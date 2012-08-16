#ifndef BMP_H
#define BMP_H
#include "types.h"

struct bmp_decdata {
    struct tagRGBQUAD *quadp;
    unsigned char *datap;
    int width;
    int height;
    int bpp;
};

/* allocate decdata struct */
struct bmp_decdata *bmp_alloc(void);

/* extract information from bmp file data */
int bmp_decode(struct bmp_decdata *bmp, unsigned char *data, int data_size);

/* get bmp properties */
void bmp_get_size(struct bmp_decdata *bmp, int *width, int *height);

/* flush flat picture data to *pc */
int bmp_show(struct bmp_decdata *bmp, unsigned char *pic, int width
             , int height, int depth, int bytes_per_line_dest);
#endif
