/* Copyright (C) 2007-2008 The Android Open Source Project
**
** This software is licensed under the terms of the GNU General Public
** License version 2, as published by the Free Software Foundation, and
** may be copied, distributed, and modified under those terms.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
*/
#include "hw.h"
#include "arm-misc.h"
#include "goldfish_device.h"
#ifdef TARGET_I386
#include "kvm.h"
#endif

#define PDEV_BUS_OP_DONE        (0x00)
#define PDEV_BUS_OP_REMOVE_DEV  (0x04)
#define PDEV_BUS_OP_ADD_DEV     (0x08)

#define PDEV_BUS_OP_INIT        (0x00)

#define PDEV_BUS_OP             (0x00)
#define PDEV_BUS_GET_NAME       (0x04)
#define PDEV_BUS_NAME_LEN       (0x08)
#define PDEV_BUS_ID             (0x0c)
#define PDEV_BUS_IO_BASE        (0x10)
#define PDEV_BUS_IO_SIZE        (0x14)
#define PDEV_BUS_IRQ            (0x18)
#define PDEV_BUS_IRQ_COUNT      (0x1c)

#include "hw/sysbus.h"
static struct BusInfo goldfish_bus_info = {
    .name       = "goldfish_bus",
    .size       = sizeof(GoldfishBus),
};

typedef struct GoldfishDeviceBusDevice {
    GoldfishDevice dev;
} GoldfishDeviceBusDevice;

static GoldfishDevice *first_device;
static GoldfishDevice *last_device;
DeviceState *goldfish_int_device;
uint32_t goldfish_free_base;
uint32_t goldfish_free_irq;

void goldfish_device_set_irq(GoldfishDevice *dev, int irq, int level)
{
    if(irq >= dev->irq_count)
        cpu_abort (cpu_single_env, "goldfish_device_set_irq: Bad irq %d >= %d\n", irq, dev->irq_count);
    else
        qemu_set_irq(qdev_get_gpio_in(goldfish_int_device, dev->irq + irq),level);
}

int goldfish_add_device_no_io(GoldfishDevice *dev)
{
    if(dev->base == 0) {
        dev->base = goldfish_free_base;
        goldfish_free_base += dev->size;
    }
    if(dev->irq == 0 && dev->irq_count > 0) {
        dev->irq = goldfish_free_irq;
        goldfish_free_irq += dev->irq_count;
    }
    printf("goldfish_add_device: %s, base %x %x, irq %d %d\n",
           dev->name, dev->base, dev->size, dev->irq, dev->irq_count);
    dev->next = NULL;
    if(last_device) {
        last_device->next = dev;
    }
    else {
        first_device = dev;
    }
    last_device = dev;
    return 0;
}

static int goldfish_device_add(GoldfishDevice *dev,
                       CPUReadMemoryFunc **mem_read,
                       CPUWriteMemoryFunc **mem_write,
                       void *opaque)
{
    int iomemtype;
    goldfish_add_device_no_io(dev);
    // TODO: make sure that is the correct endian format
    iomemtype = cpu_register_io_memory(mem_read, mem_write, opaque, DEVICE_NATIVE_ENDIAN);
    cpu_register_physical_memory(dev->base, dev->size, iomemtype);
    printf("%s: %x\t %x\n", dev->name, dev->base, iomemtype);
    return 0;
}

static uint32_t goldfish_device_bus_read(void *opaque, target_phys_addr_t offset)
{
    GoldfishBus *s = (GoldfishBus *)opaque;

    switch (offset) {
        case PDEV_BUS_OP:
            if(s->current) {
                s->current->reported_state = 1;
                s->current = s->current->next;
            }
            else {
                s->current = first_device;
            }
            while(s->current && s->current->reported_state == 1)
                s->current = s->current->next;
            if(s->current)
                return PDEV_BUS_OP_ADD_DEV;
            else {
                goldfish_device_set_irq(&s->dev, 0, 0);
                return PDEV_BUS_OP_DONE;
            }

        case PDEV_BUS_NAME_LEN:
            return s->current ? strlen(s->current->name) : 0;
        case PDEV_BUS_ID:
            return s->current ? s->current->id : 0;
        case PDEV_BUS_IO_BASE:
            return s->current ? s->current->base : 0;
        case PDEV_BUS_IO_SIZE:
            return s->current ? s->current->size : 0;
        case PDEV_BUS_IRQ:
            return s->current ? s->current->irq : 0;
        case PDEV_BUS_IRQ_COUNT:
            return s->current ? s->current->irq_count : 0;
    default:
        cpu_abort (cpu_single_env, "goldfish_bus_read: Bad offset %x\n", offset);
        return 0;
    }
}

static void goldfish_device_bus_op_init(GoldfishBus *s)
{
    GoldfishDevice *dev = first_device;
    while(dev) {
        dev->reported_state = 0;
        dev = dev->next;
    }
    s->current = NULL;
    goldfish_device_set_irq(&s->dev, 0, first_device != NULL);
}

static void goldfish_device_bus_write(void *opaque, target_phys_addr_t offset, uint32_t value)
{
    GoldfishBus *s = (GoldfishBus *)opaque;

    switch(offset) {
        case PDEV_BUS_OP:
            switch(value) {
                case PDEV_BUS_OP_INIT:
                    goldfish_device_bus_op_init(s);
                    break;
                default:
                    cpu_abort (cpu_single_env, "goldfish_bus_write: Bad PDEV_BUS_OP value %x\n", value);
            };
            break;
        case PDEV_BUS_GET_NAME:
            if(s->current) {
#ifdef TARGET_I386
                if(kvm_enabled())
                    cpu_synchronize_state(cpu_single_env);
#endif
                cpu_memory_rw(cpu_single_env, value, (void*)s->current->name, strlen(s->current->name), 1);
            }
            break;
        default:
            cpu_abort (cpu_single_env, "goldfish_bus_write: Bad offset %x\n", offset);
    }
}

static CPUReadMemoryFunc *goldfish_device_bus_readfn[] = {
    goldfish_device_bus_read,
    goldfish_device_bus_read,
    goldfish_device_bus_read
};

static CPUWriteMemoryFunc *goldfish_device_bus_writefn[] = {
    goldfish_device_bus_write,
    goldfish_device_bus_write,
    goldfish_device_bus_write
};

void goldfish_device_init(DeviceState *dev, uint32_t base, uint32_t irq)
{
    goldfish_int_device = dev;
    goldfish_free_base = base;
    goldfish_free_irq = irq;
}

static int goldfish_device_bus_init(GoldfishDevice *dev)
{
    // Return non-zero value so that this dummy device is not registerd with the kernel
    return 1;
}

static DeviceState *goldfish_device_bus_create(GoldfishBus *gbus, uint32_t base, uint32_t irq)
{
    DeviceState *dev;
    char *name = (char *)"goldfish_device_bus";

    dev = qdev_create(&gbus->bus, name);
    qdev_prop_set_string(dev, "name", name);
    qdev_prop_set_uint32(dev, "base", base);
    qdev_prop_set_uint32(dev, "irq", irq);
    qdev_init_nofail(dev);

    return dev;
}

static GoldfishDeviceInfo goldfish_device_bus_info = {
    .init = goldfish_device_bus_init,
    .readfn = goldfish_device_bus_readfn,
    .writefn = goldfish_device_bus_writefn,
    .qdev.name  = "goldfish_device_bus",
    .qdev.size  = sizeof(GoldfishDeviceBusDevice),
    .qdev.props = (Property[]) {
        DEFINE_PROP_UINT32("base", GoldfishDevice, base, 0x10001000),
        DEFINE_PROP_UINT32("id", GoldfishDevice, id, -1),
        DEFINE_PROP_UINT32("size", GoldfishDevice, size, 0x1000),
        DEFINE_PROP_UINT32("irq", GoldfishDevice, irq, 1),
        DEFINE_PROP_UINT32("irq_count", GoldfishDevice, irq_count, 1),
        DEFINE_PROP_STRING("name", GoldfishDevice, name),
        DEFINE_PROP_END_OF_LIST(),
    },
};

static void goldfish_device_bus_register(void)
{
    goldfish_bus_register_withprop(&goldfish_device_bus_info);
}
device_init(goldfish_device_bus_register);

static int goldfish_busdev_init(DeviceState *qdev, DeviceInfo *qinfo)
{
    GoldfishDeviceInfo *info = (GoldfishDeviceInfo *)qinfo;
    GoldfishDevice *dev = DO_UPCAST(GoldfishDevice, qdev, qdev);
    int ret = info->init(dev);
    if (ret == 0) {
        goldfish_device_add(dev, info->readfn, info->writefn, dev);
    }
    return ret;
}

void goldfish_bus_register_withprop(GoldfishDeviceInfo *info)
{
    info->qdev.init = goldfish_busdev_init;
    info->qdev.bus_info = &goldfish_bus_info;

    assert(info->qdev.size >= sizeof(GoldfishDevice));
    qdev_register(&info->qdev);
}

GoldfishBus *goldfish_bus_init(uint32_t base, uint32_t irq)
{
    GoldfishBus *bus;
    BusState *qbus;
    DeviceState *dev;

    dev = qdev_create(NULL, "goldfish_bridge");
    qdev_init_nofail(dev);

    qbus = qbus_create(&goldfish_bus_info, dev, "goldfish_bus");
    bus = DO_UPCAST(GoldfishBus, bus, qbus);

    dev = goldfish_device_bus_create(bus, base, irq);
    GoldfishDevice *gdev = DO_UPCAST(GoldfishDevice, qdev, dev);
    bus->dev = *gdev;

    goldfish_device_add(&bus->dev, goldfish_device_bus_readfn, goldfish_device_bus_writefn, bus);

    return bus;
}

static int goldfish_bridge_init(SysBusDevice *dev)
{
    return 0;
}

static SysBusDeviceInfo goldfish_bridge_info = {
    .init = goldfish_bridge_init,
    .qdev.name  = "goldfish_bridge",
    .qdev.size  = sizeof(SysBusDevice),
    .qdev.no_user = 1,
};

static void goldfish_register_devices(void)
{
    sysbus_register_withprop(&goldfish_bridge_info);
}

device_init(goldfish_register_devices)

#define  D(...)  ((void)0)

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include "windows.h"
#  include "shlobj.h"
#else
#  include <unistd.h>
#  include <sys/stat.h>
#endif

#if defined(USE_GOLDFISH_BUFFERS)

/** FORMATTED BUFFER PRINTING
 **
 **  bufprint() allows your to easily and safely append formatted string
 **  content to a given bounded character buffer, in a way that is easier
 **  to use than raw snprintf()
 **
 **  'buffer'  is the start position in the buffer,
 **  'buffend' is the end of the buffer, the function assumes (buffer <= buffend)
 **  'format'  is a standard printf-style format string, followed by any number
 **            of formatting arguments
 **
 **  the function returns the next position in the buffer if everything fits
 **  in it. in case of overflow or formatting error, it will always return "buffend"
 **
 **  this allows you to chain several calls to bufprint() and only check for
 **  overflow at the end, for exemple:
 **
 **     char   buffer[1024];
 **     char*  p   = buffer;
 **     char*  end = p + sizeof(buffer);
 **
 **     p = bufprint(p, end, "%s/%s", first, second);
 **     p = bufprint(p, end, "/%s", third);
 **     if (p >= end) ---> overflow
 **
 **  as a convenience, the appended string is zero-terminated if there is no overflow.
 **  (this means that even if p >= end, the content of "buffer" is zero-terminated)
 **
 **  vbufprint() is a variant that accepts a va_list argument
 **/

static char*
vbufprint( char*        buffer,
           char*        buffer_end,
           const char*  fmt,
           va_list      args )
{
    int  len = vsnprintf( buffer, buffer_end - buffer, fmt, args );
    if (len < 0 || buffer+len >= buffer_end) {
        if (buffer < buffer_end)
            buffer_end[-1] = 0;
        return buffer_end;
    }
    return buffer + len;
}

char*
bufprint(char*  buffer, char*  end, const char*  fmt, ... )
{
    va_list  args;
    char*    result;

    va_start(args, fmt);
    result = vbufprint(buffer, end, fmt, args);
    va_end(args);
    return  result;
}

/** USEFUL DIRECTORY SUPPORT
 **
 **  bufprint_add_dir() appends the application's directory to a given bounded buffer
 **
 **  bufprint_config_path() appends the applications' user-specific configuration directory
 **  to a bounded buffer. on Unix this is usually ~/.android, and something a bit more
 **  complex on Windows
 **
 **  bufprint_config_file() appends the name of a file or directory relative to the
 **  user-specific configuration directory to a bounded buffer. this really is equivalent
 **  to concat-ing the config path + path separator + 'suffix'
 **
 **  bufprint_temp_dir() appends the temporary directory's path to a given bounded buffer
 **
 **  bufprint_temp_file() appens the name of a file or directory relative to the
 **  temporary directory. equivalent to concat-ing the temp path + path separator + 'suffix'
 **/

#ifdef __linux__
/*static char*
bufprint_app_dir(char*  buff, char*  end)
{
    char   path[1024];
    int    len;
    char*  x;

    len = readlink("/proc/self/exe", path, sizeof(path));
    if (len <= 0 || len >= (int)sizeof(path)) goto Fail;
    path[len] = 0;

    x = strrchr(path, '/');
    if (x == 0) goto Fail;
    *x = 0;

    return bufprint(buff, end, "%s", path);
Fail:
    fprintf(stderr,"cannot locate application directory\n");
    exit(1);
    return end;
}*/

#elif defined(__APPLE__)
/* the following hack is needed in order to build with XCode 3.1
 * don't ask me why, but it seems that there were changes in the
 * GCC compiler that we don't have in our pre-compiled version
 */
#ifndef __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__
#define __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ MAC_OS_X_VERSION_10_4
#endif
#import <Carbon/Carbon.h>
#include <unistd.h>

static char*
bufprint_app_dir(char*  buff, char*  end)
{
    ProcessSerialNumber psn;
    CFDictionaryRef     dict;
    CFStringRef         value;
    char                s[PATH_MAX];
    char*               x;

    GetCurrentProcess(&psn);
    dict  = ProcessInformationCopyDictionary(&psn, 0xffffffff);
    value = (CFStringRef)CFDictionaryGetValue(dict,
                                             CFSTR("CFBundleExecutable"));
    CFStringGetCString(value, s, PATH_MAX - 1, kCFStringEncodingUTF8);
    x = strrchr(s, '/');
    if (x == 0) goto fail;
    *x = 0;

    return bufprint(buff, end, "%s", s);
fail:
    fprintf(stderr,"cannot locate application directory\n");
    exit(1);
    return end;
}
#elif defined _WIN32
static char*
bufprint_app_dir(char*  buff, char*  end)
{
    char   appDir[MAX_PATH];
	int    len;
	char*  sep;

    len = GetModuleFileName( 0, appDir, sizeof(appDir)-1 );
	if (len == 0) {
		fprintf(stderr, "PANIC CITY!!\n");
		exit(1);
	}
	if (len >= (int)sizeof(appDir)) {
		len = sizeof(appDir)-1;
	    appDir[len] = 0;
    }

	sep = strrchr(appDir, '\\');
	if (sep)
	  *sep = 0;

    return bufprint(buff, end, "%s", appDir);
}
#else
static char*
bufprint_app_dir(char*  buff, char*  end)
{
    return bufprint(buff, end, ".");
}
#endif

#define  _ANDROID_PATH   ".android"

/*static char*
bufprint_config_path(char*  buff, char*  end)
{
#ifdef _WIN32
    const char*  home = getenv("ANDROID_SDK_HOME");
    if (home != NULL) {
        return bufprint(buff, end, "%s\\%s", home, _ANDROID_PATH );
    } else {
        char  path[MAX_PATH];

        SHGetFolderPath( NULL, CSIDL_PROFILE,
                         NULL, 0, path);

        return bufprint(buff, end, "%s\\%s", path, _ANDROID_PATH );
    }
#else
    const char*  home = getenv("ANDROID_SDK_HOME");
    if (home == NULL)
        home = getenv("HOME");
    if (home == NULL)
        home = "/tmp";
    return bufprint(buff, end, "%s/%s", home, _ANDROID_PATH );
#endif
}*/

/*static char*
bufprint_config_file(char*  buff, char*  end, const char*  suffix)
{
    char*   p;
    p = bufprint_config_path(buff, end);
    p = bufprint(p, end, PATH_SEP "%s", suffix);
    return p;
}*/

static char*
bufprint_temp_dir(char*  buff, char*  end)
{
#ifdef _WIN32
    char   path[MAX_PATH];
    DWORD  retval;

    retval = GetTempPath( sizeof(path), path );
    if (retval > sizeof(path) || retval == 0) {
        D( "can't locate TEMP directory" );
        strncpy(path, "C:\\Temp", sizeof(path) );
    }
    strncat( path, "\\AndroidEmulator", sizeof(path)-1 );
    path_mkdir(path, 0744);

    return  bufprint(buff, end, "%s", path);
#else
    char path[MAX_PATH];
    const char*  tmppath = getenv("ANDROID_TMP");
    if (!tmppath) {
        const char* user = getenv("USER");
        if (user == NULL || user[0] == '\0')
            user = "unknown";

        snprintf(path, sizeof path, "/tmp/android-%s", user);
        tmppath = path;
    }
    mkdir(tmppath, 0744);
    return  bufprint(buff, end, "%s", tmppath );
#endif
}

static char*
bufprint_temp_file(char*  buff, char*  end, const char*  suffix)
{
    char*  p;
    p = bufprint_temp_dir(buff, end);
    p = bufprint(p, end, PATH_SEP "%s", suffix);
    return p;
}
#endif

/* Tempfile support */
struct TempFile
{
    const char*  name;
    TempFile*    next;
};

static void       tempfile_atexit(void);
static TempFile*  _all_tempfiles;

TempFile*
tempfile_create( void )
{
    TempFile*    tempfile;
    const char*  tempname = NULL;

#ifdef _WIN32
    char  temp_namebuff[MAX_PATH];
    char  temp_dir[MAX_PATH];
    char  *p = temp_dir, *end = p + sizeof(temp_dir);
    UINT  retval;

    p = bufprint_temp_dir( p, end );
    if (p >= end) {
        D( "TEMP directory path is too long" );
        return NULL;
    }

    retval = GetTempFileName(temp_dir, "TMP", 0, temp_namebuff);
    if (retval == 0) {
        D( "can't create temporary file in '%s'", temp_dir );
        return NULL;
    }

    tempname = temp_namebuff;
#else
#define  TEMPLATE  "/tmp/.android-emulator-XXXXXX"
    int   tempfd = -1;
    char  template[512];
    char  *p = template, *end = p + sizeof(template);

    p = bufprint_temp_file( p, end, "emulator-XXXXXX" );
    if (p >= end) {
        D( "Xcannot create temporary file in /tmp/android !!" );
        return NULL;
    }

    D( "template: %s", template );
    tempfd = mkstemp( template );
    if (tempfd < 0) {
        D("cannot create temporary file in /tmp/android !!");
        return NULL;
    }
    close(tempfd);
    tempname = template;
#endif
    tempfile = malloc( sizeof(*tempfile) + strlen(tempname) + 1 );
    tempfile->name = (char*)(tempfile + 1);
    strcpy( (char*)tempfile->name, tempname );

    tempfile->next = _all_tempfiles;
    _all_tempfiles = tempfile;

    if ( !tempfile->next ) {
        atexit( tempfile_atexit );
    }

    return tempfile;
}

const char*
tempfile_path(TempFile*  temp)
{
    return temp ? temp->name : NULL;
}

void
tempfile_close(TempFile*  tempfile)
{
#ifdef _WIN32
    DeleteFile(tempfile->name);
#else
    unlink(tempfile->name);
#endif
}

/** TEMP FILE CLEANUP
 **
 **/

/* we don't expect to use many temporary files */
#define MAX_ATEXIT_FDS  16

typedef struct {
    int   count;
    int   fds[ MAX_ATEXIT_FDS ];
} AtExitFds;

static void
atexit_fds_add( AtExitFds*  t, int  fd )
{
    if (t->count < MAX_ATEXIT_FDS)
        t->fds[t->count++] = fd;
    else {
        D("%s: over %d calls. Program exit may not cleanup all temporary files",
            __FUNCTION__, MAX_ATEXIT_FDS);
    }
}

static void
atexit_fds_del( AtExitFds*  t, int  fd )
{
    int  nn;
    for (nn = 0; nn < t->count; nn++)
        if (t->fds[nn] == fd) {
            /* move the last element to the current position */
            t->count  -= 1;
            t->fds[nn] = t->fds[t->count];
            break;
        }
}

static void
atexit_fds_close_all( AtExitFds*  t )
{
    int  nn;
    for (nn = 0; nn < t->count; nn++)
        close(t->fds[nn]);
}

static AtExitFds   _atexit_fds[1];

void
atexit_close_fd(int  fd)
{
    if (fd >= 0)
        atexit_fds_add(_atexit_fds, fd);
}

void
atexit_close_fd_remove(int  fd)
{
    if (fd >= 0)
        atexit_fds_del(_atexit_fds, fd);
}

static void
tempfile_atexit( void )
{
    TempFile*  tempfile;

    atexit_fds_close_all( _atexit_fds );

    for (tempfile = _all_tempfiles; tempfile; tempfile = tempfile->next)
        tempfile_close(tempfile);
}

#ifdef _WIN32
#  include <process.h>
#  include <windows.h>
#  include <tlhelp32.h>
#else
#  include <sys/types.h>
#  include <unistd.h>
#  include <signal.h>
#endif


#ifndef CHECKED
#  ifdef _WIN32
#    define   CHECKED(ret, call)    (ret) = (call)
#  else
#    define   CHECKED(ret, call)    do { (ret) = (call); } while ((ret) < 0 && errno == EINTR)
#  endif
#endif

/** FILE LOCKS SUPPORT
 **
 ** a FileLock is useful to prevent several emulator instances from using the same
 ** writable file (e.g. the userdata.img disk images).
 **
 ** create a FileLock object with filelock_create(), ithis function should return NULL
 ** only if the corresponding file path could not be locked.
 **
 ** all file locks are automatically released and destroyed when the program exits.
 ** the filelock_lock() function can also detect stale file locks that can linger
 ** when the emulator crashes unexpectedly, and will happily clean them for you
 **
 **  here's how it works, three files are used:
 **     file  - the data file accessed by the emulator
 **     lock  - a lock file  (file + '.lock')
 **     temp  - a temporary file make unique with mkstemp
 **
 **  when locking:
 **      create 'temp' and store our pid in it
 **      attemp to link 'lock' to 'temp'
 **         if the link succeeds, we obtain the lock
 **      unlink 'temp'
 **
 **  when unlocking:
 **      unlink 'lock'
 **
 **
 **  on Windows, 'lock' is a directory name. locking is equivalent to
 **  creating it...
 **
 **/

struct FileLock
{
  const char*  file;
  const char*  lock;
  char*        temp;
  int          locked;
  FileLock*    next;
};

/* used to cleanup all locks at emulator exit */
static FileLock*   _all_filelocks;


#define  LOCK_NAME   ".lock"
#define  TEMP_NAME   ".tmp-XXXXXX"

#ifdef _WIN32
#define  PIDFILE_NAME  "pid"
#endif

/* returns 0 on success, -1 on failure */
static int
filelock_lock( FileLock*  lock )
{
    int    ret;
#ifdef _WIN32
    int  pidfile_fd = -1;

    ret = _mkdir( lock->lock );
    if (ret < 0) {
        if (errno == ENOENT) {
            D( "could not access directory '%s', check path elements", lock->lock );
            return -1;
        } else if (errno != EEXIST) {
            D( "_mkdir(%s): %s", lock->lock, strerror(errno) );
            return -1;
        }

        /* if we get here, it's because the .lock directory already exists */
        /* check to see if there is a pid file in it                       */
        D("directory '%s' already exist, waiting a bit to ensure that no other emulator instance is starting", lock->lock );
        {
            int  _sleep = 200;
            int  tries;

            for ( tries = 4; tries > 0; tries-- )
            {
                pidfile_fd = open( lock->temp, O_RDONLY );

                if (pidfile_fd >= 0)
                    break;

                Sleep( _sleep );
                _sleep *= 2;
            }
        }

        if (pidfile_fd < 0) {
            D( "no pid file in '%s', assuming stale directory", lock->lock );
        }
        else
        {
            /* read the pidfile, and check wether the corresponding process is still running */
            char            buf[16];
            int             len, lockpid;
            HANDLE          processSnapshot;
            PROCESSENTRY32  pe32;
            int             is_locked = 0;

            len = read( pidfile_fd, buf, sizeof(buf)-1 );
            if (len < 0) {
                D( "could not read pid file '%s'", lock->temp );
                close( pidfile_fd );
                return -1;
            }
            buf[len] = 0;
            lockpid  = atoi(buf);

            /* PID 0 is the IDLE process, and 0 is returned in case of invalid input */
            if (lockpid == 0)
                lockpid = -1;

            close( pidfile_fd );

            pe32.dwSize     = sizeof( PROCESSENTRY32 );
            processSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

            if ( processSnapshot == INVALID_HANDLE_VALUE ) {
                D( "could not retrieve the list of currently active processes\n" );
                is_locked = 1;
            }
            else if ( !Process32First( processSnapshot, &pe32 ) )
            {
                D( "could not retrieve first process id\n" );
                CloseHandle( processSnapshot );
                is_locked = 1;
            }
            else
            {
                do {
                    if (pe32.th32ProcessID == lockpid) {
                        is_locked = 1;
                        break;
                    }
                } while (Process32Next( processSnapshot, &pe32 ) );

                CloseHandle( processSnapshot );
            }

            if (is_locked) {
                D( "the file '%s' is locked by process ID %d\n", lock->file, lockpid );
                return -1;
            }
        }
    }

    /* write our PID into the pid file */
    pidfile_fd = open( lock->temp, O_WRONLY | O_CREAT | O_TRUNC );
    if (pidfile_fd < 0) {
        if (errno == EACCES) {
            if ( path_delete_file( lock->temp ) < 0 ) {
                D( "could not remove '%s': %s\n", lock->temp, strerror(errno) );
                return -1;
            }
            pidfile_fd = open( lock->temp, O_WRONLY | O_CREAT | O_TRUNC );
        }
        if (pidfile_fd < 0) {
            D( "could not create '%s': %s\n", lock->temp, strerror(errno) );
            return -1;
        }
    }

    {
        char  buf[16];
        sprintf( buf, "%ld", GetCurrentProcessId() );
        ret = write( pidfile_fd, buf, strlen(buf) );
        close(pidfile_fd);
        if (ret < 0) {
            D( "could not write PID to '%s'\n", lock->temp );
            return -1;
        }
    }

    lock->locked = 1;
    return 0;
#else
    int    temp_fd = -1;
    int    lock_fd = -1;
    int    rc, tries, _sleep;
    FILE*  f = NULL;
    char   pid[8];
    struct stat  st_temp;

    strcpy( lock->temp, lock->file );
    strcat( lock->temp, TEMP_NAME );
    temp_fd = mkstemp( lock->temp );

    if (temp_fd < 0) {
        D("cannot create locking temp file '%s'", lock->temp );
        goto Fail;
    }

    sprintf( pid, "%d", getpid() );
    ret = write( temp_fd, pid, strlen(pid)+1 );
    if (ret < 0) {
        D( "cannot write to locking temp file '%s'", lock->temp);
        goto Fail;
    }
    close( temp_fd );
    temp_fd = -1;

    CHECKED(rc, lstat( lock->temp, &st_temp ));
    if (rc < 0) {
        D( "can't properly stat our locking temp file '%s'", lock->temp );
        goto Fail;
    }

    /* now attempt to link the temp file to the lock file */
    _sleep = 0;
    for ( tries = 4; tries > 0; tries-- )
    {
        struct stat  st_lock;
        int          rc;

        if (_sleep > 0) {
            if (_sleep > 2000000) {
                D( "cannot acquire lock file '%s'", lock->lock );
                goto Fail;
            }
            usleep( _sleep );
        }
        _sleep += 200000;

        /* the return value of link() is buggy on NFS */
        CHECKED(rc, link( lock->temp, lock->lock ));

        CHECKED(rc, lstat( lock->lock, &st_lock ));
        if (rc == 0 &&
            st_temp.st_rdev == st_lock.st_rdev &&
            st_temp.st_ino  == st_lock.st_ino  )
        {
            /* SUCCESS */
            lock->locked = 1;
            CHECKED(rc, unlink( lock->temp ));
            return 0;
        }

        /* if we get there, it means that the link() call failed */
        /* check the lockfile to see if it is stale              */
        if (rc == 0) {
            char    buf[16];
            time_t  now;
            int     lockpid = 0;
            int     lockfd;
            int     stale = 2;  /* means don't know */
            struct stat  st;

            CHECKED(rc, time( &now));
            st.st_mtime = now - 120;

            CHECKED(lockfd, open( lock->lock,O_RDONLY ));
            if ( lockfd >= 0 ) {
                int  len;

                CHECKED(len, read( lockfd, buf, sizeof(buf)-1 ));
                buf[len] = 0;
                lockpid = atoi(buf);

                CHECKED(rc, fstat( lockfd, &st ));
                if (rc == 0)
                  now = st.st_atime;

                CHECKED(rc, close(lockfd));
            }
            /* if there is a PID, check that it is still alive */
            if (lockpid > 0) {
                CHECKED(rc, kill( lockpid, 0 ));
                if (rc == 0 || errno == EPERM) {
                    stale = 0;
                } else if (rc < 0 && errno == ESRCH) {
                    stale = 1;
                }
            }
            if (stale == 2) {
                /* no pid, stale if the file is older than 1 minute */
                stale = (now >= st.st_mtime + 60);
            }

            if (stale) {
                D( "removing stale lockfile '%s'", lock->lock );
                CHECKED(rc, unlink( lock->lock ));
                _sleep = 0;
                tries++;
            }
        }
    }
    D("file '%s' is already in use by another process", lock->file );

Fail:
    if (f)
        fclose(f);

    if (temp_fd >= 0) {
        close(temp_fd);
    }

    if (lock_fd >= 0) {
        close(lock_fd);
    }

    unlink( lock->lock );
    unlink( lock->temp );
    return -1;
#endif
}

void
filelock_release( FileLock*  lock )
{
    if (lock->locked) {
#ifdef _WIN32
        path_delete_file( (char*)lock->temp );
        rmdir( (char*)lock->lock );
#else
        unlink( (char*)lock->lock );
#endif
        lock->locked = 0;
    }
}

static void
filelock_atexit( void )
{
  FileLock*  lock;

  for (lock = _all_filelocks; lock != NULL; lock = lock->next)
     filelock_release( lock );
}

/* create a file lock */
FileLock*
filelock_create( const char*  file )
{
    int    file_len = strlen(file);
    int    lock_len = file_len + sizeof(LOCK_NAME);
#ifdef _WIN32
    int    temp_len = lock_len + 1 + sizeof(PIDFILE_NAME);
#else
    int    temp_len = file_len + sizeof(TEMP_NAME);
#endif
    int    total_len = sizeof(FileLock) + file_len + lock_len + temp_len + 3;

    FileLock*  lock = malloc(total_len);

    lock->file = (const char*)(lock + 1);
    memcpy( (char*)lock->file, file, file_len+1 );

    lock->lock = lock->file + file_len + 1;
    memcpy( (char*)lock->lock, file, file_len+1 );
    strcat( (char*)lock->lock, LOCK_NAME );

    lock->temp    = (char*)lock->lock + lock_len + 1;
#ifdef _WIN32
    snprintf( (char*)lock->temp, temp_len, "%s\\" PIDFILE_NAME, lock->lock );
#else
    lock->temp[0] = 0;
#endif
    lock->locked = 0;

    if (filelock_lock(lock) < 0) {
        free(lock);
        return NULL;
    }

    lock->next     = _all_filelocks;
    _all_filelocks = lock;

    if (lock->next == NULL)
        atexit( filelock_atexit );

    return lock;
}

/** PATH HANDLING ROUTINES
 **
 **  path_parent() can be used to return the n-level parent of a given directory
 **  this understands . and .. when encountered in the input path
 **/

static __inline__ int
ispathsep(int  c)
{
#ifdef _WIN32
    return (c == '/' || c == '\\');
#else
    return (c == '/');
#endif
}

char*
path_parent( const char*  path, int  levels )
{
    const char*  end = path + strlen(path);
    char*        result;

    while (levels > 0) {
        const char*  base;

        /* trim any trailing path separator */
        while (end > path && ispathsep(end[-1]))
            end--;

        base = end;
        while (base > path && !ispathsep(base[-1]))
            base--;

        if (base <= path) /* we can't go that far */
            return NULL;

        if (end == base+1 && base[0] == '.')
            goto Next;

        if (end == base+2 && base[0] == '.' && base[1] == '.') {
            levels += 1;
            goto Next;
        }

        levels -= 1;

    Next:
        end = base - 1;
    }
    result = malloc( end-path+1 );
    if (result != NULL) {
        memcpy( result, path, end-path );
        result[end-path] = 0;
    }
    return result;
}

static char*
substring_dup( const char*  start, const char*  end )
{
    int    len    = end - start;
    char*  result = g_malloc(len+1);
    memcpy(result, start, len);
    result[len] = 0;
    return result;
}

int
path_split( const char*  path, char* *pdirname, char* *pbasename )
{
    const char*  end = path + strlen(path);
    const char*  last;
    char*        basename;

    /* prepare for errors */
    if (pdirname)
        *pdirname = NULL;
    if (pbasename)
        *pbasename = NULL;

    /* handle empty path case */
    if (end == path) {
        return -1;
    }

    /* strip trailing path separators */
    while (end > path && ispathsep(end[-1]))
        end -= 1;

    /* handle "/" and degenerate cases like "////" */
    if (end == path) {
        return -1;
    }

    /* find last separator */
    last = end;
    while (last > path && !ispathsep(last[-1]))
        last -= 1;

    /* handle cases where there is no path separator */
    if (last == path) {
        if (pdirname)
            *pdirname  = g_strdup(".");
        if (pbasename)
            *pbasename = substring_dup(path,end);
        return 0;
    }

    /* handle "/foo" */
    if (last == path+1) {
        if (pdirname)
            *pdirname  = g_strdup("/");
        if (pbasename)
            *pbasename = substring_dup(path+1,end);
        return 0;
    }

    /* compute basename */
    basename = substring_dup(last,end);
    if (strcmp(basename, ".") == 0 || strcmp(basename, "..") == 0) {
        g_free(basename);
        return -1;
    }

    if (pbasename)
        *pbasename = basename;
    else {
        g_free(basename);
    }

    /* compute dirname */
    if (pdirname != NULL)
        *pdirname = substring_dup(path,last-1);

    return 0;
}

char*
path_basename( const char*  path )
{
    char*  basename;

    if (path_split(path, NULL, &basename) < 0)
        return NULL;

    return basename;
}

char*
path_dirname( const char*  path )
{
    char*  dirname;

    if (path_split(path, &dirname, NULL) < 0)
        return NULL;

    return dirname;
}





/** MISC FILE AND DIRECTORY HANDLING
 **/

ABool
path_exists( const char*  path )
{
    int  ret;
    CHECKED(ret, access(path, F_OK));
    return (ret == 0) || (errno != ENOENT);
}

/* checks that a path points to a regular file */
ABool
path_is_regular( const char*  path )
{
    int          ret;
    struct stat  st;

    CHECKED(ret, stat(path, &st));
    if (ret < 0)
        return 0;

    return S_ISREG(st.st_mode);
}


/* checks that a path points to a directory */
ABool
path_is_dir( const char*  path )
{
    int          ret;
    struct stat  st;

    CHECKED(ret, stat(path, &st));
    if (ret < 0)
        return 0;

    return S_ISDIR(st.st_mode);
}

/* checks that one can read/write a given (regular) file */
ABool
path_can_read( const char*  path )
{
    int  ret;
    CHECKED(ret, access(path, R_OK));
    return (ret == 0);
}

ABool
path_can_write( const char*  path )
{
    int  ret;
    CHECKED(ret, access(path, R_OK));
    return (ret == 0);
}

ABool
path_can_exec( const char* path )
{
    int  ret;
    CHECKED(ret, access(path, X_OK));
    return (ret == 0);
}

/* try to make a directory. returns 0 on success, -1 on failure
 * (error code in errno) */
APosixStatus
path_mkdir( const char*  path, int  mode )
{
#ifdef _WIN32
    (void)mode;
    return _mkdir(path);
#else
    int  ret;
    CHECKED(ret, mkdir(path, mode));
    return ret;
#endif
}

static APosixStatus
path_mkdir_recursive( char*  path, unsigned  len, int  mode )
{
    char      old_c;
    int       ret;
    unsigned  len2;

    /* get rid of trailing separators */
    while (len > 0 && ispathsep(path[len-1]))
        len -= 1;

    if (len == 0) {
        errno = ENOENT;
        return -1;
    }

    /* check that the parent exists, 'len2' is the length of
     * the parent part of the path */
    len2 = len-1;
    while (len2 > 0 && !ispathsep(path[len2-1]))
        len2 -= 1;

    if (len2 > 0) {
        old_c      = path[len2];
        path[len2] = 0;
        ret        = 0;
        if ( !path_exists(path) ) {
            /* the parent doesn't exist, so try to create it */
            ret = path_mkdir_recursive( path, len2, mode );
        }
        path[len2] = old_c;

        if (ret < 0)
            return ret;
    }

    /* at this point, we now the parent exists */
    old_c     = path[len];
    path[len] = 0;
    ret       = path_mkdir( path, mode );
    path[len] = old_c;

    return ret;
}

/* ensure that a given directory exists, create it if not,
   0 on success, -1 on failure (error code in errno) */
APosixStatus
path_mkdir_if_needed( const char*  path, int  mode )
{
    int  ret = 0;

    if (!path_exists(path)) {
        ret = path_mkdir(path, mode);

        if (ret < 0 && errno == ENOENT) {
            char      temp[MAX_PATH];
            unsigned  len = (unsigned)strlen(path);

            if (len > sizeof(temp)-1) {
                errno = EINVAL;
                return -1;
            }
            memcpy( temp, path, len );
            temp[len] = 0;

            return path_mkdir_recursive(temp, len, mode);
        }
    }
    return ret;
}

/* return the size of a given file in '*psize'. returns 0 on
 * success, -1 on failure (error code in errno) */
APosixStatus
path_get_size( const char*  path, uint64_t  *psize )
{
#ifdef _WIN32
    /* avoid _stat64 which is only defined in MSVCRT.DLL, not CRTDLL.DLL */
    /* do not use OpenFile() because it has strange search behaviour that could */
    /* result in getting the size of a different file */
    LARGE_INTEGER  size;
    HANDLE  file = CreateFile( /* lpFilename */        path,
                               /* dwDesiredAccess */   GENERIC_READ,
                               /* dwSharedMode */     FILE_SHARE_READ|FILE_SHARE_WRITE,
                               /* lpSecurityAttributes */  NULL,
                               /* dwCreationDisposition */ OPEN_EXISTING,
                               /* dwFlagsAndAttributes */  0,
                               /* hTemplateFile */      NULL );
    if (file == INVALID_HANDLE_VALUE) {
        /* ok, just to play fair */
        errno = ENOENT;
        return -1;
    }
    if (!GetFileSizeEx(file, &size)) {
        /* maybe we tried to get the size of a pipe or something like that ? */
        *psize = 0;
    }
    else {
        *psize = (uint64_t) size.QuadPart;
    }
    CloseHandle(file);
    return 0;
#else
    int    ret;
    struct stat  st;

    CHECKED(ret, stat(path, &st));
    if (ret == 0) {
        *psize = (uint64_t) st.st_size;
    }
    return ret;
#endif
}

/*
static ABool
path_is_absolute( const char*  path )
{
#ifdef _WIN32
    if (path == NULL)
        return 0;

    if (path[0] == '/' || path[0] == '\\')
        return 1;

*/    /* 'C:' is always considered to be absolute
     * even if used with a relative path like C:foo which
     * is different from C:\foo
     */
/*    if (path[0] != 0 && path[1] == ':')
        return 1;

    return 0;
#else
    return (path != NULL && path[0] == '/');
#endif
}
*/

/** OTHER FILE UTILITIES
 **
 **  path_empty_file() creates an empty file at a given path location.
 **  if the file already exists, it is truncated without warning
 **
 **  path_copy_file() copies one file into another.
 **
 **  both functions return 0 on success, and -1 on error
 **/

APosixStatus
path_empty_file( const char*  path )
{
#ifdef _WIN32
    int  fd = _creat( path, S_IWRITE );
#else
    /* on Unix, only allow the owner to read/write, since the file *
     * may contain some personal data we don't want to see exposed */
    int  fd = creat(path, S_IRUSR | S_IWUSR);
#endif
    if (fd >= 0) {
        close(fd);
        return 0;
    }
    return -1;
}

APosixStatus
path_copy_file( const char*  dest, const char*  source )
{
    int  fd, fs, result = -1;

    /* if the destination doesn't exist, create it */
    if ( access(source, F_OK)  < 0 ||
         path_empty_file(dest) < 0) {
        return -1;
    }

    if ( access(source, R_OK) < 0 ) {
        //D("%s: source file is un-readable: %s\n",
        //  __FUNCTION__, source);
        return -1;
    }

#ifdef _WIN32
    fd = _open(dest, _O_RDWR | _O_BINARY);
    fs = _open(source, _O_RDONLY |  _O_BINARY);
#else
    fd = creat(dest, S_IRUSR | S_IWUSR);
    fs = open(source, S_IREAD);
#endif
    if (fs >= 0 && fd >= 0) {
        char buf[4096];
        ssize_t total = 0;
        ssize_t n;
        result = 0; /* success */
        while ((n = read(fs, buf, 4096)) > 0) {
            if (write(fd, buf, n) != n) {
                /* write failed. Make it return -1 so that an
                 * empty file be created. */
                //D("Failed to copy '%s' to '%s': %s (%d)",
                //       source, dest, strerror(errno), errno);
                result = -1;
                break;
            }
            total += n;
        }
    }

    if (fs >= 0) {
        close(fs);
    }
    if (fd >= 0) {
        close(fd);
    }
    return result;
}


APosixStatus
path_delete_file( const char*  path )
{
#ifdef _WIN32
    int  ret = _unlink( path );
    if (ret == -1 && errno == EACCES) {
        /* a first call to _unlink will fail if the file is set read-only */
        /* we can however try to change its mode first and call unlink    */
        /* again...                                                       */
        ret = _chmod( path, _S_IREAD | _S_IWRITE );
        if (ret == 0)
            ret = _unlink( path );
    }
    return ret;
#else
    return  unlink(path);
#endif
}


void*
path_load_file(const char *fn, size_t  *pSize)
{
    char*  data;
    int    sz;
    int    fd;

    if (pSize)
        *pSize = 0;

    data   = NULL;

    fd = open(fn, O_BINARY | O_RDONLY);
    if(fd < 0) return NULL;

    do {
        sz = lseek(fd, 0, SEEK_END);
        if(sz < 0) break;

        if (pSize)
            *pSize = (size_t) sz;

        if (lseek(fd, 0, SEEK_SET) != 0)
            break;

        data = (char*) malloc(sz + 1);
        if(data == NULL) break;

        if (read(fd, data, sz) != sz)
            break;

        close(fd);
        data[sz] = 0;

        return data;
    } while (0);

    close(fd);

    if(data != NULL)
        free(data);

    return NULL;
}

#ifdef _WIN32
#  define DIR_SEP  ';'
#else
#  define DIR_SEP  ':'
#endif

char*
path_search_exec( const char* filename )
{
    const char* sysPath = getenv("PATH");
    char        temp[PATH_MAX];
    const char* p;

    /* If the file contains a directory separator, don't search */
#ifdef _WIN32
    if (strchr(filename, '/') != NULL || strchr(filename, '\\') != NULL) {
#else
    if (strchr(filename, '/') != NULL) {
#endif
        if (path_exists(filename)) {
            return strdup(filename);
        } else {
            return NULL;
        }
    }

    /* If system path is empty, don't search */
    if (sysPath == NULL || sysPath[0] == '\0') {
        return NULL;
    }

    /* Count the number of non-empty items in the system path
     * Items are separated by DIR_SEP, and two successive separators
     * correspond to an empty item that will be ignored.
     * Also compute the required string storage length. */
    p       = sysPath;

    while (*p) {
        char* p2 = strchr(p, DIR_SEP);
        int   len;
        if (p2 == NULL) {
            len = strlen(p);
        } else {
            len = p2 - p;
        }

        do {
            if (len <= 0)
                break;

            snprintf(temp, sizeof(temp), "%.*s/%s", len, p, filename);

            if (path_exists(temp) && path_can_exec(temp)) {
                return strdup(temp);
            }

        } while (0);

        p += len;
        if (*p == DIR_SEP)
            p++;
    }

    /* Nothing, really */
    return NULL;
}
