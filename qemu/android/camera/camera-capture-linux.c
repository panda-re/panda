/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Contains code that is used to capture video frames from a camera device
 * on Linux. This code uses V4L2 API to work with camera devices, and requires
 * Linux kernel version at least 2.5
 */

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include "android/camera/camera-capture.h"
#include "android/camera/camera-format-converters.h"

#define  E(...)    derror(__VA_ARGS__)
#define  W(...)    dwarning(__VA_ARGS__)
#define  D(...)    VERBOSE_PRINT(camera,__VA_ARGS__)
#define  D_ACTIVE  VERBOSE_CHECK(camera)

/* the T(...) macro is used to dump traffic */
#define  T_ACTIVE   0

#if T_ACTIVE
#define  T(...)    VERBOSE_PRINT(camera,__VA_ARGS__)
#else
#define  T(...)    ((void)0)
#endif

#define CLEAR(x) memset (&(x), 0, sizeof(x))

/* Pixel format descriptor.
 * Instances of this descriptor are created during camera device enumeration, and
 * an instance of this structure describing pixel format chosen for the camera
 * emulation is saved by the camera factory service to represent an emulating
 * camera properties.
 */
typedef struct QemuPixelFormat {
    /* Pixel format in V4L2_PIX_FMT_XXX form. */
    uint32_t        format;
    /* Frame dimensions supported by this format. */
    CameraFrameDim* dims;
    /* Number of frame dimensions supported by this format. */
    int             dim_num;
} QemuPixelFormat;

/* Describes a framebuffer. */
typedef struct CameraFrameBuffer {
    /* Framebuffer data. */
    uint8_t*    data;
    /* Framebuffer data size. */
    size_t      size;
} CameraFrameBuffer;

/* Defines type of the I/O used to obtain frames from the device. */
typedef enum CameraIoType {
    /* Framebuffers are shared via memory mapping. */
    CAMERA_IO_MEMMAP,
    /* Framebuffers are available via user pointers. */
    CAMERA_IO_USERPTR,
    /* Framebuffers are to be read from the device. */
    CAMERA_IO_DIRECT
} CameraIoType;

typedef struct LinuxCameraDevice LinuxCameraDevice;
/*
 * Describes a connection to an actual camera device.
 */
struct LinuxCameraDevice {
    /* Common header. */
    CameraDevice                header;

    /* Camera device name. (default is /dev/video0) */
    char*                       device_name;
    /* Input channel. (default is 0) */
    int                         input_channel;

    /*
     * Set by the framework after initializing camera connection.
     */

    /* Handle to the opened camera device. */
    int                         handle;
    /* Device capabilities. */
    struct v4l2_capability      caps;
    /* Actual pixel format reported by the device when capturing is started. */
    struct v4l2_pix_format      actual_pixel_format;
    /* Defines type of the I/O to use to retrieve frames from the device. */
    CameraIoType                io_type;
    /* Allocated framebuffers. */
    struct CameraFrameBuffer*   framebuffers;
    /* Actual number of allocated framebuffers. */
    int                         framebuffer_num;
};

/* Preferred pixel formats arranged from the most to the least desired.
 *
 * More than anything else this array is defined by an existance of format
 * conversion between the camera supported formats, and formats that are
 * supported by camera framework in the guest system. Currently, guest supports
 * only YV12 pixel format for data, and RGB32 for preview. So, this array should
 * contain only those formats, for which converters are implemented. Generally
 * speaking, the order in which entries should be arranged in this array matters
 * only as far as conversion speed is concerned. So, formats with the fastest
 * converters should be put closer to the top of the array, while slower ones
 * should be put closer to the bottom. But as far as functionality is concerned,
 * the orser doesn't matter, and any format can be placed anywhere in this array,
 * as long as conversion for it exists.
 */
static const uint32_t _preferred_formats[] =
{
    /* Native format for the emulated camera: no conversion at all. */
    V4L2_PIX_FMT_YUV420,
    V4L2_PIX_FMT_YVU420,
    /* Continue with YCbCr: less math than with RGB */
    V4L2_PIX_FMT_NV12,
    V4L2_PIX_FMT_NV21,
    V4L2_PIX_FMT_YUYV,
    /* End with RGB. */
    V4L2_PIX_FMT_RGB32,
    V4L2_PIX_FMT_RGB24,
    V4L2_PIX_FMT_RGB565,
};
/* Number of entries in _preferred_formats array. */
static const int _preferred_format_num =
    sizeof(_preferred_formats)/sizeof(*_preferred_formats);

/*******************************************************************************
 *                     Helper routines
 ******************************************************************************/

/* IOCTL wrapper. */
static int
_xioctl(int fd, int request, void *arg) {
  int r;
  do {
      r = ioctl(fd, request, arg);
  } while (-1 == r && EINTR == errno);
  return r;
}

/* Frees resource allocated for QemuPixelFormat instance, excluding the instance
 * itself.
 */
static void _qemu_pixel_format_free(QemuPixelFormat* fmt)
{
    if (fmt != NULL) {
        if (fmt->dims != NULL)
            free(fmt->dims);
    }
}

/* Returns an index of the given pixel format in an array containing pixel
 * format descriptors.
 * This routine is used to choose a pixel format for a camera device. The idea
 * is that when the camera service enumerates all pixel formats for all cameras
 * connected to the host, we need to choose just one, which would be most
 * appropriate for camera emulation. To do that, the camera service will run
 * formats, contained in _preferred_formats array against enumerated pixel
 * formats to pick the first format that match.
 * Param:
 *  fmt - Pixel format, for which to obtain the index.
 *  formats - Array containing list of pixel formats, supported by the camera
 *      device.
 *  size - Number of elements in the 'formats' array.
 * Return:
 *  Index of the matched entry in the array, or -1 if no entry has been found.
 */
static int
_get_format_index(uint32_t fmt, QemuPixelFormat* formats, int size)
{
    int f;
    for (f = 0; f < size && formats[f].format != fmt; f++);
    return f < size ? f : -1;
}

/*******************************************************************************
 *                     CameraFrameBuffer routines
 ******************************************************************************/

/* Frees array of framebuffers, depending on the I/O method the array has been
 * initialized for.
 * Note that this routine doesn't frees the array itself.
 * Param:
 *  fb, num - Array data, and its size.
 *  io_type - Type of the I/O the array has been initialized for.
 */
static void
_free_framebuffers(CameraFrameBuffer* fb, int num, CameraIoType io_type)
{
    if (fb != NULL) {
        int n;

        switch (io_type) {
            case CAMERA_IO_MEMMAP:
                /* Unmap framebuffers. */
                for (n = 0; n < num; n++) {
                    if (fb[n].data != NULL) {
                        munmap(fb[n].data, fb[n].size);
                        fb[n].data = NULL;
                        fb[n].size = 0;
                    }
                }
                break;

            case CAMERA_IO_USERPTR:
            case CAMERA_IO_DIRECT:
                /* Free framebuffers. */
                for (n = 0; n < num; n++) {
                    if (fb[n].data != NULL) {
                        free(fb[n].data);
                        fb[n].data = NULL;
                        fb[n].size = 0;
                    }
                }
                break;

            default:
                E("%s: Invalid I/O type %d", __FUNCTION__, io_type);
                break;
        }
    }
}

/*******************************************************************************
 *                     CameraDevice routines
 ******************************************************************************/

/* Allocates an instance of LinuxCameraDevice structure.
 * Return:
 *  Allocated instance of LinuxCameraDevice structure. Note that this routine
 *  also sets 'opaque' field in the 'header' structure to point back to the
 *  containing LinuxCameraDevice instance.
 */
static LinuxCameraDevice*
_camera_device_alloc(void)
{
    LinuxCameraDevice* cd;

    ANEW0(cd);
    memset(cd, 0, sizeof(*cd));
    cd->header.opaque = cd;
    cd->handle = -1;

    return cd;
}

/* Uninitializes and frees CameraDevice structure.
 */
static void
_camera_device_free(LinuxCameraDevice* lcd)
{
    if (lcd != NULL) {
        /* Closing handle will also disconnect from the driver. */
        if (lcd->handle >= 0) {
            close(lcd->handle);
        }
        if (lcd->device_name != NULL) {
            free(lcd->device_name);
        }
        if (lcd->framebuffers != NULL) {
            _free_framebuffers(lcd->framebuffers, lcd->framebuffer_num,
                               lcd->io_type);
            free(lcd->framebuffers);
        }
        AFREE(lcd);
    } else {
        E("%s: No descriptor", __FUNCTION__);
    }
}

/* Resets camera device after capturing.
 * Since new capture request may require different frame dimensions we must
 * reset camera device by reopening its handle. Otherwise attempts to set up new
 * frame properties (different from the previous one) may fail. */
static void
_camera_device_reset(LinuxCameraDevice* cd)
{
    struct v4l2_cropcap cropcap;
    struct v4l2_crop crop;

    /* Free capturing framebuffers first. */
    if (cd->framebuffers != NULL) {
        _free_framebuffers(cd->framebuffers, cd->framebuffer_num, cd->io_type);
        free(cd->framebuffers);
        cd->framebuffers = NULL;
        cd->framebuffer_num = 0;
    }

    /* Reset device handle. */
    close(cd->handle);
    cd->handle = open(cd->device_name, O_RDWR | O_NONBLOCK, 0);

    if (cd->handle >= 0) {
        /* Select video input, video standard and tune here. */
        cropcap.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        _xioctl(cd->handle, VIDIOC_CROPCAP, &cropcap);
        crop.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        crop.c = cropcap.defrect; /* reset to default */
        _xioctl (cd->handle, VIDIOC_S_CROP, &crop);
    }
}

/* Memory maps buffers and shares mapped memory with the device.
 * Return:
 *  0 Framebuffers have been mapped.
 *  -1 A critical error has ocurred.
 *  1 Memory mapping is not available.
 */
static int
_camera_device_mmap_framebuffer(LinuxCameraDevice* cd)
{
    struct v4l2_requestbuffers req;
    CLEAR(req);
    req.count   = 4;
    req.type    = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory  = V4L2_MEMORY_MMAP;

    /* Request memory mapped buffers. Note that device can return less buffers
     * than requested. */
    if(_xioctl(cd->handle, VIDIOC_REQBUFS, &req)) {
        if (EINVAL == errno) {
            D("%s: Device '%s' does not support memory mapping",
              __FUNCTION__, cd->device_name);
            return 1;
        } else {
            E("%s: VIDIOC_REQBUFS has failed: %s",
              __FUNCTION__, strerror(errno));
            return -1;
        }
    }

    /* Allocate framebuffer array. */
    cd->framebuffers = calloc(req.count, sizeof(CameraFrameBuffer));
    if (cd->framebuffers == NULL) {
        E("%s: Not enough memory to allocate framebuffer array", __FUNCTION__);
        return -1;
    }

    /* Map every framebuffer to the shared memory, and queue it
     * with the device. */
    for(cd->framebuffer_num = 0; cd->framebuffer_num < req.count;
        cd->framebuffer_num++) {
        /* Map framebuffer. */
        struct v4l2_buffer buf;
        CLEAR(buf);
        buf.type    = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory  = V4L2_MEMORY_MMAP;
        buf.index   = cd->framebuffer_num;
        if(_xioctl(cd->handle, VIDIOC_QUERYBUF, &buf) < 0) {
            E("%s: VIDIOC_QUERYBUF has failed: %s",
              __FUNCTION__, strerror(errno));
            return -1;
        }
        cd->framebuffers[cd->framebuffer_num].size = buf.length;
        cd->framebuffers[cd->framebuffer_num].data =
            mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED,
                 cd->handle, buf.m.offset);
        if (MAP_FAILED == cd->framebuffers[cd->framebuffer_num].data) {
            E("%s: Memory mapping has failed: %s",
              __FUNCTION__, strerror(errno));
            return -1;
        }

        /* Queue the mapped buffer. */
        CLEAR(buf);
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_MMAP;
        buf.index = cd->framebuffer_num;
        if (_xioctl(cd->handle, VIDIOC_QBUF, &buf) < 0) {
            E("%s: VIDIOC_QBUF has failed: %s", __FUNCTION__, strerror(errno));
            return -1;
        }
    }

    cd->io_type = CAMERA_IO_MEMMAP;

    return 0;
}

/* Allocates frame buffers and registers them with the device.
 * Return:
 *  0 Framebuffers have been mapped.
 *  -1 A critical error has ocurred.
 *  1 Device doesn't support user pointers.
 */
static int
_camera_device_user_framebuffer(LinuxCameraDevice* cd)
{
    struct v4l2_requestbuffers req;
    CLEAR (req);
    req.count   = 4;
    req.type    = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory  = V4L2_MEMORY_USERPTR;

    /* Request user buffers. Note that device can return less buffers
     * than requested. */
    if(_xioctl(cd->handle, VIDIOC_REQBUFS, &req)) {
        if (EINVAL == errno) {
            D("%s: Device '%s' does not support user pointers",
              __FUNCTION__, cd->device_name);
            return 1;
        } else {
            E("%s: VIDIOC_REQBUFS has failed: %s",
              __FUNCTION__, strerror(errno));
            return -1;
        }
    }

    /* Allocate framebuffer array. */
    cd->framebuffers = calloc(req.count, sizeof(CameraFrameBuffer));
    if (cd->framebuffers == NULL) {
        E("%s: Not enough memory to allocate framebuffer array", __FUNCTION__);
        return -1;
    }

    /* Allocate buffers, queueing them wit the device at the same time */
    for(cd->framebuffer_num = 0; cd->framebuffer_num < req.count;
        cd->framebuffer_num++) {
        cd->framebuffers[cd->framebuffer_num].size =
            cd->actual_pixel_format.sizeimage;
        cd->framebuffers[cd->framebuffer_num].data =
            malloc(cd->framebuffers[cd->framebuffer_num].size);
        if (cd->framebuffers[cd->framebuffer_num].data == NULL) {
            E("%s: Not enough memory to allocate framebuffer", __FUNCTION__);
            return -1;
        }

        /* Queue the user buffer. */
        struct v4l2_buffer buf;
        CLEAR(buf);
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = V4L2_MEMORY_USERPTR;
        buf.m.userptr = (unsigned long)cd->framebuffers[cd->framebuffer_num].data;
        buf.length = cd->framebuffers[cd->framebuffer_num].size;
        if (_xioctl(cd->handle, VIDIOC_QBUF, &buf) < 0) {
            E("%s: VIDIOC_QBUF has failed: %s", __FUNCTION__, strerror(errno));
            return -1;
        }
    }

    cd->io_type = CAMERA_IO_USERPTR;

    return 0;
}

/* Allocate frame buffer for direct read from the device.
 * Return:
 *  0 Framebuffers have been mapped.
 *  -1 A critical error has ocurred.
 *  1 Memory mapping is not available.
 */
static int
_camera_device_direct_framebuffer(LinuxCameraDevice* cd)
{
    /* Allocate framebuffer array. */
    cd->framebuffer_num = 1;
    cd->framebuffers = malloc(sizeof(CameraFrameBuffer));
    if (cd->framebuffers == NULL) {
        E("%s: Not enough memory to allocate framebuffer array", __FUNCTION__);
        return -1;
    }

    cd->framebuffers[0].size = cd->actual_pixel_format.sizeimage;
    cd->framebuffers[0].data = malloc(cd->framebuffers[0].size);
    if (cd->framebuffers[0].data == NULL) {
        E("%s: Not enough memory to allocate framebuffer", __FUNCTION__);
        return -1;
    }

    cd->io_type = CAMERA_IO_DIRECT;

    return 0;
}

/* Opens camera device.
 * Param:
 *  cd - Camera device descriptor to open the camera for.
 * Return:
 *  0 on success, != 0 on failure.
 */
static int
_camera_device_open(LinuxCameraDevice* cd)
{
    struct stat st;

    if (stat(cd->device_name, &st)) {
        return -1;
    }

    if (!S_ISCHR(st.st_mode)) {
        E("%s: '%s' is not a device", __FUNCTION__, cd->device_name);
        return -1;
    }

    /* Open handle to the device, and query device capabilities. */
    cd->handle = open(cd->device_name, O_RDWR | O_NONBLOCK, 0);
    if (cd->handle < 0) {
        E("%s: Cannot open camera device '%s': %s",
          __FUNCTION__, cd->device_name, strerror(errno));
        return -1;
    }
    if (_xioctl(cd->handle, VIDIOC_QUERYCAP, &cd->caps) < 0) {
        if (EINVAL == errno) {
            E("%s: Camera '%s' is not a V4L2 device",
              __FUNCTION__, cd->device_name);
            close(cd->handle);
            cd->handle = -1;
            return -1;
        } else {
            E("%s: Unable to query capabilities for camera device '%s'",
              __FUNCTION__, cd->device_name);
            close(cd->handle);
            cd->handle = -1;
            return -1;
        }
    }

    /* Make sure that camera supports minimal requirements. */
    if (!(cd->caps.capabilities & V4L2_CAP_VIDEO_CAPTURE)) {
        E("%s: Camera '%s' is not a video capture device",
          __FUNCTION__, cd->device_name);
        close(cd->handle);
        cd->handle = -1;
        return -1;
    }

    return 0;
}

/* Enumerates frame sizes for the given pixel format.
 * Param:
 *  cd - Opened camera device descriptor.
 *  fmt - Pixel format to enum frame sizes for.
 *  sizes - Upon success contains an array of supported frame sizes. The size of
 *      the array is defined by the value, returned from this routine. The caller
 *      is responsible for freeing memory allocated for this array.
 * Return:
 *  On success returns number of entries in the 'sizes' array. On failure returns
 *  a negative value.
 */
static int
_camera_device_enum_format_sizes(LinuxCameraDevice* cd,
                                 uint32_t fmt,
                                 CameraFrameDim** sizes)
{
    int n;
    int sizes_num = 0;
    int out_num = 0;
    struct v4l2_frmsizeenum size_enum;
    CameraFrameDim* arr;

    /* Calculate number of supported sizes for the given format. */
    for (n = 0; ; n++) {
        size_enum.index = n;
        size_enum.pixel_format = fmt;
        if(_xioctl(cd->handle, VIDIOC_ENUM_FRAMESIZES, &size_enum)) {
            break;
        }
        if (size_enum.type == V4L2_FRMSIZE_TYPE_DISCRETE) {
            /* Size is in the simpe width, height form. */
            sizes_num++;
        } else if (size_enum.type == V4L2_FRMSIZE_TYPE_STEPWISE) {
            /* Sizes are represented as min/max width and height with a step for
             * each dimension. Since at the end we want to list each supported
             * size in the array (that's the only format supported by the guest
             * camera framework), we need to calculate how many array entries
             * this will generate. */
            const uint32_t dif_widths =
                (size_enum.stepwise.max_width - size_enum.stepwise.min_width) /
                size_enum.stepwise.step_width + 1;
            const uint32_t dif_heights =
                (size_enum.stepwise.max_height - size_enum.stepwise.min_height) /
                size_enum.stepwise.step_height + 1;
            sizes_num += dif_widths * dif_heights;
        } else if (size_enum.type == V4L2_FRMSIZE_TYPE_CONTINUOUS) {
            /* Special stepwise case, when steps are set to 1. We still need to
             * flatten this for the guest, but the array may be too big.
             * Fortunately, we don't need to be fancy, so three sizes would be
             * sufficient here: min, max, and one in the middle. */
            sizes_num += 3;
        }

    }
    if (sizes_num == 0) {
        return 0;
    }

    /* Allocate, and initialize the array of supported entries. */
    *sizes = (CameraFrameDim*)malloc(sizes_num * sizeof(CameraFrameDim));
    if (*sizes == NULL) {
        E("%s: Memory allocation failure", __FUNCTION__);
        return -1;
    }
    arr = *sizes;
    for (n = 0; out_num < sizes_num; n++) {
        size_enum.index = n;
        size_enum.pixel_format = fmt;
        if(_xioctl(cd->handle, VIDIOC_ENUM_FRAMESIZES, &size_enum)) {
            /* Errors are not welcome here anymore. */
            E("%s: Unexpected failure while getting pixel dimensions: %s",
              __FUNCTION__, strerror(errno));
            free(arr);
            return -1;
        }

        if (size_enum.type == V4L2_FRMSIZE_TYPE_DISCRETE) {
            arr[out_num].width = size_enum.discrete.width;
            arr[out_num].height = size_enum.discrete.height;
            out_num++;
        } else if (size_enum.type == V4L2_FRMSIZE_TYPE_STEPWISE) {
            uint32_t w;
            for (w = size_enum.stepwise.min_width;
                 w <= size_enum.stepwise.max_width;
                 w += size_enum.stepwise.step_width) {
                uint32_t h;
                for (h = size_enum.stepwise.min_height;
                     h <= size_enum.stepwise.max_height;
                     h += size_enum.stepwise.step_height) {
                    arr[out_num].width = w;
                    arr[out_num].height = h;
                    out_num++;
                }
            }
        } else if (size_enum.type == V4L2_FRMSIZE_TYPE_CONTINUOUS) {
            /* min */
            arr[out_num].width = size_enum.stepwise.min_width;
            arr[out_num].height = size_enum.stepwise.min_height;
            out_num++;
            /* one in the middle */
            arr[out_num].width =
                (size_enum.stepwise.min_width + size_enum.stepwise.max_width) / 2;
            arr[out_num].height =
                (size_enum.stepwise.min_height + size_enum.stepwise.max_height) / 2;
            out_num++;
            /* max */
            arr[out_num].width = size_enum.stepwise.max_width;
            arr[out_num].height = size_enum.stepwise.max_height;
            out_num++;
        }
    }

    return out_num;
}

/* Enumerates pixel formats, supported by the device.
 * Note that this routine will enumerate only raw (uncompressed) formats.
 * Param:
 *  cd - Opened camera device descriptor.
 *  fmts - Upon success contains an array of supported pixel formats. The size of
 *      the array is defined by the value, returned from this routine. The caller
 *      is responsible for freeing memory allocated for this array.
 * Return:
 *  On success returns number of entries in the 'fmts' array. On failure returns
 *  a negative value.
 */
static int
_camera_device_enum_pixel_formats(LinuxCameraDevice* cd, QemuPixelFormat** fmts)
{
    int n, max_fmt;
    int fmt_num = 0;
    int out_num = 0;
    struct v4l2_fmtdesc fmt_enum;
    QemuPixelFormat* arr;

    /* Calculate number of supported formats. */
    for (max_fmt = 0; ; max_fmt++) {
        memset(&fmt_enum, 0, sizeof(fmt_enum));
        fmt_enum.index = max_fmt;
        fmt_enum.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if(_xioctl(cd->handle, VIDIOC_ENUM_FMT, &fmt_enum)) {
            break;
        }
        /* Skip the compressed ones. */
        if ((fmt_enum.flags & V4L2_FMT_FLAG_COMPRESSED) == 0) {
            fmt_num++;
        }
    }
    if (fmt_num == 0) {
        return 0;
    }

    /* Allocate, and initialize array for enumerated formats. */
    *fmts = (QemuPixelFormat*)malloc(fmt_num * sizeof(QemuPixelFormat));
    if (*fmts == NULL) {
        E("%s: Memory allocation failure", __FUNCTION__);
        return -1;
    }
    arr = *fmts;
    memset(arr, 0, fmt_num * sizeof(QemuPixelFormat));
    for (n = 0; n < max_fmt && out_num < fmt_num; n++) {
        memset(&fmt_enum, 0, sizeof(fmt_enum));
        fmt_enum.index = n;
        fmt_enum.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if(_xioctl(cd->handle, VIDIOC_ENUM_FMT, &fmt_enum)) {
            int nn;
            /* Errors are not welcome here anymore. */
            E("%s: Unexpected failure while getting pixel format: %s",
              __FUNCTION__, strerror(errno));
            for (nn = 0; nn < out_num; nn++) {
                _qemu_pixel_format_free(arr + nn);
            }
            free(arr);
            return -1;
        }
        /* Skip the compressed ones. */
        if ((fmt_enum.flags & V4L2_FMT_FLAG_COMPRESSED) == 0) {
            arr[out_num].format = fmt_enum.pixelformat;
            /* Enumerate frame dimensions supported for this format. */
            arr[out_num].dim_num =
                _camera_device_enum_format_sizes(cd, fmt_enum.pixelformat,
                                                 &arr[out_num].dims);
            if (arr[out_num].dim_num > 0) {
                out_num++;
            } else if (arr[out_num].dim_num < 0) {
                int nn;
                E("Unable to enumerate supported dimensions for pixel format %d",
                  fmt_enum.pixelformat);
                for (nn = 0; nn < out_num; nn++) {
                    _qemu_pixel_format_free(arr + nn);
                }
                free(arr);
                return -1;
            }
        }
    }

    return out_num;
}

/* Collects information about an opened camera device.
 * The information collected in this routine contains list of pixel formats,
 * supported by the device, and list of frame dimensions supported by the camera
 * for each pixel format.
 * Param:
 *  cd - Opened camera device descriptor.
 *  cis - Upon success contains information collected from the camera device.
 * Return:
 *  0 on success, != 0 on failure.
 */
static int
_camera_device_get_info(LinuxCameraDevice* cd, CameraInfo* cis)
{
    int f;
    int chosen = -1;
    QemuPixelFormat* formats = NULL;
    int num_pix_fmts = _camera_device_enum_pixel_formats(cd, &formats);
    if (num_pix_fmts <= 0) {
        return -1;
    }

    /* Lets see if camera supports preferred formats */
    for (f = 0; f < _preferred_format_num; f++) {
        chosen = _get_format_index(_preferred_formats[f], formats, num_pix_fmts);
        if (chosen >= 0) {
            break;
        }
    }
    if (chosen < 0) {
        /* Camera doesn't support any of the chosen formats. Then it doesn't
         * matter which one we choose. Lets choose the first one. */
        chosen = 0;
    }

    cis->device_name = ASTRDUP(cd->device_name);
    cis->inp_channel = cd->input_channel;
    cis->pixel_format = formats[chosen].format;
    cis->frame_sizes_num = formats[chosen].dim_num;
    /* Swap instead of copy. */
    cis->frame_sizes = formats[chosen].dims;
    formats[chosen].dims = NULL;
    cis->in_use = 0;

    for (f = 0; f < num_pix_fmts; f++) {
        _qemu_pixel_format_free(formats + f);
    }
    free(formats);

    return 0;
}

/*******************************************************************************
 *                     CameraDevice API
 ******************************************************************************/

CameraDevice*
camera_device_open(const char* name, int inp_channel)
{
    struct v4l2_cropcap cropcap;
    struct v4l2_crop crop;
    LinuxCameraDevice* cd;

    /* Allocate and initialize the descriptor. */
    cd = _camera_device_alloc();
    cd->device_name = name != NULL ? ASTRDUP(name) : ASTRDUP("/dev/video0");
    cd->input_channel = inp_channel;

    /* Open the device. */
    if (_camera_device_open(cd)) {
        _camera_device_free(cd);
        return NULL;
    }

    /* Select video input, video standard and tune here. */
    cropcap.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    _xioctl(cd->handle, VIDIOC_CROPCAP, &cropcap);
    crop.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    crop.c = cropcap.defrect; /* reset to default */
    _xioctl (cd->handle, VIDIOC_S_CROP, &crop);

    return &cd->header;
}

int
camera_device_start_capturing(CameraDevice* ccd,
                              uint32_t pixel_format,
                              int frame_width,
                              int frame_height)
{
    struct v4l2_format fmt;
    LinuxCameraDevice* cd;
    char fmt_str[5];
    int r;

    /* Sanity checks. */
    if (ccd == NULL || ccd->opaque == NULL) {
      E("%s: Invalid camera device descriptor", __FUNCTION__);
      return -1;
    }
    cd = (LinuxCameraDevice*)ccd->opaque;
    if (cd->handle < 0) {
      E("%s: Camera device is not opened", __FUNCTION__);
      return -1;
    }

    /* Try to set pixel format with the given dimensions. */
    CLEAR(fmt);
    fmt.type                = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width       = frame_width;
    fmt.fmt.pix.height      = frame_height;
    fmt.fmt.pix.pixelformat = pixel_format;
    if (_xioctl(cd->handle, VIDIOC_S_FMT, &fmt) < 0) {
        memcpy(fmt_str, &pixel_format, 4);
        fmt_str[4] = '\0';
        E("%s: Camera '%s' does not support pixel format '%s' with dimensions %dx%d",
          __FUNCTION__, cd->device_name, fmt_str, frame_width, frame_height);
        _camera_device_reset(cd);
        return -1;
    }
    /* VIDIOC_S_FMT may has changed some properties of the structure. Make sure
     * that dimensions didn't change. */
    if (fmt.fmt.pix.width != frame_width || fmt.fmt.pix.height != frame_height) {
        memcpy(fmt_str, &pixel_format, 4);
        fmt_str[4] = '\0';
        E("%s: Dimensions %dx%d are wrong for pixel format '%s'",
          __FUNCTION__, frame_width, frame_height, fmt_str);
        _camera_device_reset(cd);
        return -1;
    }
    memcpy(&cd->actual_pixel_format, &fmt.fmt.pix, sizeof(struct v4l2_pix_format));

    /*
     * Lets initialize frame buffers, and see what kind of I/O we're going to
     * use to retrieve frames.
     */

    /* First, lets see if we can do mapped I/O (as most performant one). */
    r = _camera_device_mmap_framebuffer(cd);
    if (r < 0) {
        /* Some critical error has ocurred. Bail out. */
        _camera_device_reset(cd);
        return -1;
    } else if (r > 0) {
        /* Device doesn't support memory mapping. Retrieve to the next performant
         * one: preallocated user buffers. */
        r = _camera_device_user_framebuffer(cd);
        if (r < 0) {
            /* Some critical error has ocurred. Bail out. */
            _camera_device_reset(cd);
            return -1;
        } else if (r > 0) {
            /* The only thing left for us is direct reading from the device. */
            if (!(cd->caps.capabilities & V4L2_CAP_READWRITE)) {
                E("%s: Don't know how to access frames on device '%s'",
                  __FUNCTION__, cd->device_name);
                _camera_device_reset(cd);
                return -1;
            }
            r = _camera_device_direct_framebuffer(cd);
            if (r != 0) {
                /* Any error at this point is a critical one. */
                _camera_device_reset(cd);
                return -1;
            }
        }
    }

    /* Start capturing from the device. */
    if (cd->io_type != CAMERA_IO_DIRECT) {
        enum v4l2_buf_type type;
        type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if (_xioctl (cd->handle, VIDIOC_STREAMON, &type) < 0) {
            E("%s: VIDIOC_STREAMON on camera '%s' has failed: %s",
              __FUNCTION__, cd->device_name, strerror(errno));
            _camera_device_reset(cd);
            return -1;
        }
    }
    return 0;
}

int
camera_device_stop_capturing(CameraDevice* ccd)
{
    enum v4l2_buf_type type;
    LinuxCameraDevice* cd;

    /* Sanity checks. */
    if (ccd == NULL || ccd->opaque == NULL) {
      E("%s: Invalid camera device descriptor", __FUNCTION__);
      return -1;
    }
    cd = (LinuxCameraDevice*)ccd->opaque;
    if (cd->handle < 0) {
      E("%s: Camera device is not opened", __FUNCTION__);
      return -1;
    }

    switch (cd->io_type) {
        case CAMERA_IO_DIRECT:
            /* Nothing to do. */
            break;

        case CAMERA_IO_MEMMAP:
        case CAMERA_IO_USERPTR:
            type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
            if (_xioctl(cd->handle, VIDIOC_STREAMOFF, &type) < 0) {
	            E("%s: VIDIOC_STREAMOFF on camera '%s' has failed: %s",
                  __FUNCTION__, cd->device_name, strerror(errno));
                return -1;
            }
            break;
        default:
            E("%s: Unknown I/O method: %d", __FUNCTION__, cd->io_type);
            return -1;
    }

    /* Reopen the device to reset its internal state. It seems that if we don't
     * do that, an attempt to reinit the device with different frame dimensions
     * would fail. */
    _camera_device_reset(cd);

    return 0;
}

int
camera_device_read_frame(CameraDevice* ccd,
                         ClientFrameBuffer* framebuffers,
                         int fbs_num,
                         float r_scale,
                         float g_scale,
                         float b_scale,
                         float exp_comp)
{
    LinuxCameraDevice* cd;

    /* Sanity checks. */
    if (ccd == NULL || ccd->opaque == NULL) {
      E("%s: Invalid camera device descriptor", __FUNCTION__);
      return -1;
    }
    cd = (LinuxCameraDevice*)ccd->opaque;
    if (cd->handle < 0) {
      E("%s: Camera device is not opened", __FUNCTION__);
      return -1;
    }

    if (cd->io_type == CAMERA_IO_DIRECT) {
        /* Read directly from the device. */
        size_t total_read_bytes = 0;
        /* There is one framebuffer allocated for direct read. */
        void* buff = cd->framebuffers[0].data;
        do {
            int read_bytes =
                read(cd->handle, buff + total_read_bytes,
                     cd->actual_pixel_format.sizeimage - total_read_bytes);
            if (read_bytes < 0) {
                switch (errno) {
                    case EIO:
                    case EAGAIN:
                        continue;
                    default:
                        E("%s: Unable to read from the camera device '%s': %s",
                          __FUNCTION__, cd->device_name, strerror(errno));
                        return -1;
                }
            }
            total_read_bytes += read_bytes;
        } while (total_read_bytes < cd->actual_pixel_format.sizeimage);
        /* Convert the read frame into the caller's framebuffers. */
        return convert_frame(buff, cd->actual_pixel_format.pixelformat,
                             cd->actual_pixel_format.sizeimage,
                             cd->actual_pixel_format.width,
                             cd->actual_pixel_format.height,
                             framebuffers, fbs_num,
                             r_scale, g_scale, b_scale, exp_comp);
    } else {
        /* Dequeue next buffer from the device. */
        struct v4l2_buffer buf;
        int res;
        CLEAR(buf);
        buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        buf.memory = cd->io_type == CAMERA_IO_MEMMAP ? V4L2_MEMORY_MMAP :
                                                       V4L2_MEMORY_USERPTR;
        for (;;) {
            const int res = _xioctl(cd->handle, VIDIOC_DQBUF, &buf);
            if (res >= 0) {
                break;
            } else if (errno == EAGAIN) {
                return 1;   // Tells the caller to repeat.
            } else if (errno != EINTR && errno != EIO) {
                E("%s: VIDIOC_DQBUF on camera '%s' has failed: %s",
                  __FUNCTION__, cd->device_name, strerror(errno));
                return -1;
            }
        }

        /* Convert frame to the receiving buffers. */
        res = convert_frame(cd->framebuffers[buf.index].data,
                            cd->actual_pixel_format.pixelformat,
                            cd->actual_pixel_format.sizeimage,
                            cd->actual_pixel_format.width,
                            cd->actual_pixel_format.height,
                            framebuffers, fbs_num,
                            r_scale, g_scale, b_scale, exp_comp);

        /* Requeue the buffer back to the device. */
        if (_xioctl(cd->handle, VIDIOC_QBUF, &buf) < 0) {
            W("%s: VIDIOC_QBUF on camera '%s' has failed: %s",
              __FUNCTION__, cd->device_name, strerror(errno));
        }

        return res;
    }
}

void
camera_device_close(CameraDevice* ccd)
{
    LinuxCameraDevice* cd;

    /* Sanity checks. */
    if (ccd != NULL && ccd->opaque != NULL) {
        cd = (LinuxCameraDevice*)ccd->opaque;
        _camera_device_free(cd);
    } else {
        E("%s: Invalid camera device descriptor", __FUNCTION__);
    }
}

int
enumerate_camera_devices(CameraInfo* cis, int max)
{
    char dev_name[24];
    int found = 0;
    int n;

    for (n = 0; n < max; n++) {
        CameraDevice* cd;

        sprintf(dev_name, "/dev/video%d", n);
        cd = camera_device_open(dev_name, 0);
        if (cd != NULL) {
            LinuxCameraDevice* lcd = (LinuxCameraDevice*)cd->opaque;
            if (!_camera_device_get_info(lcd, cis + found)) {
                char user_name[24];
                sprintf(user_name, "webcam%d", found);
                cis[found].display_name = ASTRDUP(user_name);
                cis[found].in_use = 0;
                found++;
            }
            camera_device_close(cd);
        } else {
            break;
        }
    }

    return found;
}
