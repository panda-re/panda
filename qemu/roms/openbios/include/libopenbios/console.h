#ifndef VIDEO_CONSOLE_H
#define VIDEO_CONSOLE_H

/* libopenbios/console_common.c */
int console_draw_fstr(const char *str, int len);
int console_init(void);
void console_close(void);

#endif /* VIDEO_CONSOLE_H */
