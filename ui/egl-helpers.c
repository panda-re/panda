/*
 * Copyright (C) 2015-2016 Gerd Hoffmann <kraxel@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include <glob.h>
#include <dirent.h>

#include "qemu/error-report.h"
#include "ui/egl-helpers.h"

EGLDisplay *qemu_egl_display;
EGLConfig qemu_egl_config;

/* ---------------------------------------------------------------------- */

static bool egl_gles;
static int egl_debug;

#define egl_dbg(_x ...)                          \
    do {                                         \
        if (egl_debug) {                         \
            fprintf(stderr, "egl: " _x);         \
        }                                        \
    } while (0);

/* ---------------------------------------------------------------------- */

#ifdef CONFIG_OPENGL_DMABUF

int qemu_egl_rn_fd;
struct gbm_device *qemu_egl_rn_gbm_dev;
EGLContext qemu_egl_rn_ctx;

static int qemu_egl_rendernode_open(const char *rendernode)
{
    DIR *dir;
    struct dirent *e;
    int r, fd;
    char *p;

    if (rendernode) {
        return open(rendernode, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
    }

    dir = opendir("/dev/dri");
    if (!dir) {
        return -1;
    }

    fd = -1;
    while ((e = readdir(dir))) {
        if (e->d_type != DT_CHR) {
            continue;
        }

        if (strncmp(e->d_name, "renderD", 7)) {
            continue;
        }

        p = g_strdup_printf("/dev/dri/%s", e->d_name);

        r = open(p, O_RDWR | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
        if (r < 0) {
            g_free(p);
            continue;
        }
        fd = r;
        g_free(p);
        break;
    }

    closedir(dir);
    if (fd < 0) {
        return -1;
    }
    return fd;
}

int egl_rendernode_init(const char *rendernode)
{
    qemu_egl_rn_fd = -1;

    qemu_egl_rn_fd = qemu_egl_rendernode_open(rendernode);
    if (qemu_egl_rn_fd == -1) {
        error_report("egl: no drm render node available");
        goto err;
    }

    qemu_egl_rn_gbm_dev = gbm_create_device(qemu_egl_rn_fd);
    if (!qemu_egl_rn_gbm_dev) {
        error_report("egl: gbm_create_device failed");
        goto err;
    }

    qemu_egl_init_dpy((EGLNativeDisplayType)qemu_egl_rn_gbm_dev, false, false);

    if (!epoxy_has_egl_extension(qemu_egl_display,
                                 "EGL_KHR_surfaceless_context")) {
        error_report("egl: EGL_KHR_surfaceless_context not supported");
        goto err;
    }
    if (!epoxy_has_egl_extension(qemu_egl_display,
                                 "EGL_MESA_image_dma_buf_export")) {
        error_report("egl: EGL_MESA_image_dma_buf_export not supported");
        goto err;
    }

    qemu_egl_rn_ctx = qemu_egl_init_ctx();
    if (!qemu_egl_rn_ctx) {
        error_report("egl: egl_init_ctx failed");
        goto err;
    }

    return 0;

err:
    if (qemu_egl_rn_gbm_dev) {
        gbm_device_destroy(qemu_egl_rn_gbm_dev);
    }
    if (qemu_egl_rn_fd != -1) {
        close(qemu_egl_rn_fd);
    }

    return -1;
}

int egl_get_fd_for_texture(uint32_t tex_id, EGLint *stride, EGLint *fourcc)
{
    EGLImageKHR image;
    EGLint num_planes, fd;

    image = eglCreateImageKHR(qemu_egl_display, eglGetCurrentContext(),
                              EGL_GL_TEXTURE_2D_KHR,
                              (EGLClientBuffer)(unsigned long)tex_id,
                              NULL);
    if (!image) {
        return -1;
    }

    eglExportDMABUFImageQueryMESA(qemu_egl_display, image, fourcc,
                                  &num_planes, NULL);
    if (num_planes != 1) {
        eglDestroyImageKHR(qemu_egl_display, image);
        return -1;
    }
    eglExportDMABUFImageMESA(qemu_egl_display, image, &fd, stride, NULL);
    eglDestroyImageKHR(qemu_egl_display, image);

    return fd;
}

#endif /* CONFIG_OPENGL_DMABUF */

/* ---------------------------------------------------------------------- */

EGLSurface qemu_egl_init_surface_x11(EGLContext ectx, Window win)
{
    EGLSurface esurface;
    EGLBoolean b;

    egl_dbg("eglCreateWindowSurface (x11 win id 0x%lx) ...\n",
            (unsigned long) win);
    esurface = eglCreateWindowSurface(qemu_egl_display,
                                      qemu_egl_config,
                                      (EGLNativeWindowType)win, NULL);
    if (esurface == EGL_NO_SURFACE) {
        error_report("egl: eglCreateWindowSurface failed");
        return NULL;
    }

    b = eglMakeCurrent(qemu_egl_display, esurface, esurface, ectx);
    if (b == EGL_FALSE) {
        error_report("egl: eglMakeCurrent failed");
        return NULL;
    }

    return esurface;
}

/* ---------------------------------------------------------------------- */

/*
 * Taken from glamor_egl.h from the Xorg xserver, which is MIT licensed
 *
 * Create an EGLDisplay from a native display type. This is a little quirky
 * for a few reasons.
 *
 * 1: GetPlatformDisplayEXT and GetPlatformDisplay are the API you want to
 * use, but have different function signatures in the third argument; this
 * happens not to matter for us, at the moment, but it means epoxy won't alias
 * them together.
 *
 * 2: epoxy 1.3 and earlier don't understand EGL client extensions, which
 * means you can't call "eglGetPlatformDisplayEXT" directly, as the resolver
 * will crash.
 *
 * 3: You can't tell whether you have EGL 1.5 at this point, because
 * eglQueryString(EGL_VERSION) is a property of the display, which we don't
 * have yet. So you have to query for extensions no matter what. Fortunately
 * epoxy_has_egl_extension _does_ let you query for client extensions, so
 * we don't have to write our own extension string parsing.
 *
 * 4. There is no EGL_KHR_platform_base to complement the EXT one, thus one
 * needs to know EGL 1.5 is supported in order to use the eglGetPlatformDisplay
 * function pointer.
 * We can workaround this (circular dependency) by probing for the EGL 1.5
 * platform extensions (EGL_KHR_platform_gbm and friends) yet it doesn't seem
 * like mesa will be able to advertise these (even though it can do EGL 1.5).
 */
static EGLDisplay qemu_egl_get_display(void *native)
{
    EGLDisplay dpy = EGL_NO_DISPLAY;

#ifdef EGL_MESA_platform_gbm
    /* In practise any EGL 1.5 implementation would support the EXT extension */
    if (epoxy_has_egl_extension(NULL, "EGL_EXT_platform_base")) {
        PFNEGLGETPLATFORMDISPLAYEXTPROC getPlatformDisplayEXT =
            (void *) eglGetProcAddress("eglGetPlatformDisplayEXT");
        if (getPlatformDisplayEXT) {
            dpy = getPlatformDisplayEXT(EGL_PLATFORM_GBM_MESA, native, NULL);
        }
    }
#endif

    if (dpy == EGL_NO_DISPLAY) {
        /* fallback */
        dpy = eglGetDisplay(native);
    }
    return dpy;
}

int qemu_egl_init_dpy(EGLNativeDisplayType dpy, bool gles, bool debug)
{
    static const EGLint conf_att_gl[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
        EGL_RED_SIZE,   5,
        EGL_GREEN_SIZE, 5,
        EGL_BLUE_SIZE,  5,
        EGL_ALPHA_SIZE, 0,
        EGL_NONE,
    };
    static const EGLint conf_att_gles[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
        EGL_RED_SIZE,   5,
        EGL_GREEN_SIZE, 5,
        EGL_BLUE_SIZE,  5,
        EGL_ALPHA_SIZE, 0,
        EGL_NONE,
    };
    EGLint major, minor;
    EGLBoolean b;
    EGLint n;

    if (debug) {
        egl_debug = 1;
        setenv("EGL_LOG_LEVEL", "debug", true);
        setenv("LIBGL_DEBUG", "verbose", true);
    }

    egl_dbg("qemu_egl_get_display (dpy %p) ...\n", dpy);
    qemu_egl_display = qemu_egl_get_display(dpy);
    if (qemu_egl_display == EGL_NO_DISPLAY) {
        error_report("egl: eglGetDisplay failed");
        return -1;
    }

    egl_dbg("eglInitialize ...\n");
    b = eglInitialize(qemu_egl_display, &major, &minor);
    if (b == EGL_FALSE) {
        error_report("egl: eglInitialize failed");
        return -1;
    }

    egl_dbg("eglBindAPI ...\n");
    b = eglBindAPI(gles ? EGL_OPENGL_ES_API : EGL_OPENGL_API);
    if (b == EGL_FALSE) {
        error_report("egl: eglBindAPI failed");
        return -1;
    }

    egl_dbg("eglChooseConfig ...\n");
    b = eglChooseConfig(qemu_egl_display,
                        gles ? conf_att_gles : conf_att_gl,
                        &qemu_egl_config, 1, &n);
    if (b == EGL_FALSE || n != 1) {
        error_report("egl: eglChooseConfig failed");
        return -1;
    }

    egl_gles = gles;
    return 0;
}

EGLContext qemu_egl_init_ctx(void)
{
    static const EGLint ctx_att_gl[] = {
        EGL_NONE
    };
    static const EGLint ctx_att_gles[] = {
        EGL_CONTEXT_CLIENT_VERSION, 2,
        EGL_NONE
    };

    EGLContext ectx;
    EGLBoolean b;

    egl_dbg("eglCreateContext ...\n");
    ectx = eglCreateContext(qemu_egl_display, qemu_egl_config, EGL_NO_CONTEXT,
                            egl_gles ? ctx_att_gles : ctx_att_gl);
    if (ectx == EGL_NO_CONTEXT) {
        error_report("egl: eglCreateContext failed");
        return NULL;
    }

    b = eglMakeCurrent(qemu_egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE, ectx);
    if (b == EGL_FALSE) {
        error_report("egl: eglMakeCurrent failed");
        return NULL;
    }

    return ectx;
}
