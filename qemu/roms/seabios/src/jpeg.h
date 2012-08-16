#ifndef __JPEG_H
#define __JPEG_H

struct jpeg_decdata;
struct jpeg_decdata *jpeg_alloc(void);
int jpeg_decode(struct jpeg_decdata *jpeg, unsigned char *buf);
void jpeg_get_size(struct jpeg_decdata *jpeg, int *width, int *height);
int jpeg_show(struct jpeg_decdata *jpeg, unsigned char *pic, int width
              , int height, int depth, int bytes_per_line_dest);

#endif
