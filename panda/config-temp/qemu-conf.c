#include <epoxy/egl.h>
#ifndef EGL_MESA_image_dma_buf_export
# error mesa/epoxy lacks support for dmabufs (mesa 10.6+)
#endif
int main(void) { return 0; }
