#ifndef VIDEO_SUBR_H
#define VIDEO_SUBR_H

/* packages/video.c */
int video_get_res(int *w, int *h);
void draw_pixel(int x, int y, int colind);
void set_color(int ind, unsigned long color);
void video_scroll(int height);
void init_video(unsigned long fb, int width, int height, int depth, int rb);

#endif /* VIDEO_SUBR_H */
