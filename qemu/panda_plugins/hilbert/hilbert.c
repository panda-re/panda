/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
#include "config.h"
#include "qemu-common.h"
#include "monitor.h"
#include "cpu.h"
#include "cpu-common.h"

// Basically the whole file is commented out if we are in user mode
#ifndef CONFIG_USER_ONLY

extern ram_addr_t ram_size;
void qemu_system_shutdown_request(void);

#include "panda_plugin.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <stdbool.h>

#include <pthread.h>

#ifdef CONFIG_SDL
#include <SDL.h>
#else
#error Hilbert visualization requires SDL
#endif

// Hilbert-order traversal of the color cube
uint8_t colortable[256][3] = {
    { 0x00, 0x00, 0x00 },
    { 0x00, 0x20, 0x20 },
    { 0x20, 0x20, 0x00 },
    { 0x20, 0x00, 0x20 },
    { 0x40, 0x00, 0x00 },
    { 0x60, 0x20, 0x00 },
    { 0x60, 0x00, 0x20 },
    { 0x40, 0x20, 0x20 },
    { 0x40, 0x00, 0x40 },
    { 0x60, 0x20, 0x40 },
    { 0x60, 0x00, 0x60 },
    { 0x40, 0x20, 0x60 },
    { 0x20, 0x00, 0x60 },
    { 0x00, 0x00, 0x40 },
    { 0x20, 0x20, 0x40 },
    { 0x00, 0x20, 0x60 },
    { 0x20, 0x40, 0x60 },
    { 0x00, 0x40, 0x40 },
    { 0x20, 0x60, 0x40 },
    { 0x00, 0x60, 0x60 },
    { 0x40, 0x60, 0x60 },
    { 0x60, 0x40, 0x60 },
    { 0x60, 0x60, 0x40 },
    { 0x40, 0x40, 0x40 },
    { 0x40, 0x60, 0x20 },
    { 0x60, 0x40, 0x20 },
    { 0x60, 0x60, 0x00 },
    { 0x40, 0x40, 0x00 },
    { 0x20, 0x60, 0x00 },
    { 0x20, 0x40, 0x20 },
    { 0x00, 0x40, 0x00 },
    { 0x00, 0x60, 0x20 },
    { 0x00, 0x80, 0x00 },
    { 0x20, 0xa0, 0x00 },
    { 0x20, 0x80, 0x20 },
    { 0x00, 0xa0, 0x20 },
    { 0x00, 0x80, 0x40 },
    { 0x20, 0x80, 0x60 },
    { 0x00, 0xa0, 0x60 },
    { 0x20, 0xa0, 0x40 },
    { 0x00, 0xc0, 0x40 },
    { 0x20, 0xc0, 0x60 },
    { 0x00, 0xe0, 0x60 },
    { 0x20, 0xe0, 0x40 },
    { 0x00, 0xe0, 0x20 },
    { 0x00, 0xc0, 0x00 },
    { 0x20, 0xc0, 0x20 },
    { 0x20, 0xe0, 0x00 },
    { 0x40, 0xe0, 0x20 },
    { 0x40, 0xc0, 0x00 },
    { 0x60, 0xc0, 0x20 },
    { 0x60, 0xe0, 0x00 },
    { 0x60, 0xe0, 0x40 },
    { 0x40, 0xe0, 0x60 },
    { 0x60, 0xc0, 0x60 },
    { 0x40, 0xc0, 0x40 },
    { 0x60, 0xa0, 0x40 },
    { 0x40, 0xa0, 0x60 },
    { 0x60, 0x80, 0x60 },
    { 0x40, 0x80, 0x40 },
    { 0x60, 0x80, 0x20 },
    { 0x40, 0xa0, 0x20 },
    { 0x40, 0x80, 0x00 },
    { 0x60, 0xa0, 0x00 },
    { 0x80, 0x80, 0x00 },
    { 0xa0, 0xa0, 0x00 },
    { 0xa0, 0x80, 0x20 },
    { 0x80, 0xa0, 0x20 },
    { 0x80, 0x80, 0x40 },
    { 0xa0, 0x80, 0x60 },
    { 0x80, 0xa0, 0x60 },
    { 0xa0, 0xa0, 0x40 },
    { 0x80, 0xc0, 0x40 },
    { 0xa0, 0xc0, 0x60 },
    { 0x80, 0xe0, 0x60 },
    { 0xa0, 0xe0, 0x40 },
    { 0x80, 0xe0, 0x20 },
    { 0x80, 0xc0, 0x00 },
    { 0xa0, 0xc0, 0x20 },
    { 0xa0, 0xe0, 0x00 },
    { 0xc0, 0xe0, 0x20 },
    { 0xc0, 0xc0, 0x00 },
    { 0xe0, 0xc0, 0x20 },
    { 0xe0, 0xe0, 0x00 },
    { 0xe0, 0xe0, 0x40 },
    { 0xc0, 0xe0, 0x60 },
    { 0xe0, 0xc0, 0x60 },
    { 0xc0, 0xc0, 0x40 },
    { 0xe0, 0xa0, 0x40 },
    { 0xc0, 0xa0, 0x60 },
    { 0xe0, 0x80, 0x60 },
    { 0xc0, 0x80, 0x40 },
    { 0xe0, 0x80, 0x20 },
    { 0xc0, 0xa0, 0x20 },
    { 0xc0, 0x80, 0x00 },
    { 0xe0, 0xa0, 0x00 },
    { 0xe0, 0x60, 0x00 },
    { 0xc0, 0x60, 0x20 },
    { 0xe0, 0x40, 0x20 },
    { 0xc0, 0x40, 0x00 },
    { 0xe0, 0x20, 0x00 },
    { 0xe0, 0x00, 0x20 },
    { 0xc0, 0x00, 0x00 },
    { 0xc0, 0x20, 0x20 },
    { 0xa0, 0x20, 0x00 },
    { 0xa0, 0x00, 0x20 },
    { 0x80, 0x00, 0x00 },
    { 0x80, 0x20, 0x20 },
    { 0x80, 0x40, 0x00 },
    { 0xa0, 0x60, 0x00 },
    { 0xa0, 0x40, 0x20 },
    { 0x80, 0x60, 0x20 },
    { 0x80, 0x40, 0x40 },
    { 0xa0, 0x60, 0x40 },
    { 0xa0, 0x40, 0x60 },
    { 0x80, 0x60, 0x60 },
    { 0x80, 0x20, 0x60 },
    { 0x80, 0x00, 0x40 },
    { 0xa0, 0x00, 0x60 },
    { 0xa0, 0x20, 0x40 },
    { 0xc0, 0x20, 0x60 },
    { 0xc0, 0x00, 0x40 },
    { 0xe0, 0x00, 0x60 },
    { 0xe0, 0x20, 0x40 },
    { 0xe0, 0x40, 0x60 },
    { 0xc0, 0x40, 0x40 },
    { 0xe0, 0x60, 0x40 },
    { 0xc0, 0x60, 0x60 },
    { 0xe0, 0x60, 0x80 },
    { 0xc0, 0x60, 0xa0 },
    { 0xe0, 0x40, 0xa0 },
    { 0xc0, 0x40, 0x80 },
    { 0xe0, 0x20, 0x80 },
    { 0xe0, 0x00, 0xa0 },
    { 0xc0, 0x00, 0x80 },
    { 0xc0, 0x20, 0xa0 },
    { 0xa0, 0x20, 0x80 },
    { 0xa0, 0x00, 0xa0 },
    { 0x80, 0x00, 0x80 },
    { 0x80, 0x20, 0xa0 },
    { 0x80, 0x40, 0x80 },
    { 0xa0, 0x60, 0x80 },
    { 0xa0, 0x40, 0xa0 },
    { 0x80, 0x60, 0xa0 },
    { 0x80, 0x40, 0xc0 },
    { 0xa0, 0x60, 0xc0 },
    { 0xa0, 0x40, 0xe0 },
    { 0x80, 0x60, 0xe0 },
    { 0x80, 0x20, 0xe0 },
    { 0x80, 0x00, 0xc0 },
    { 0xa0, 0x00, 0xe0 },
    { 0xa0, 0x20, 0xc0 },
    { 0xc0, 0x20, 0xe0 },
    { 0xc0, 0x00, 0xc0 },
    { 0xe0, 0x00, 0xe0 },
    { 0xe0, 0x20, 0xc0 },
    { 0xe0, 0x40, 0xe0 },
    { 0xc0, 0x40, 0xc0 },
    { 0xe0, 0x60, 0xc0 },
    { 0xc0, 0x60, 0xe0 },
    { 0xe0, 0x80, 0xe0 },
    { 0xc0, 0xa0, 0xe0 },
    { 0xc0, 0x80, 0xc0 },
    { 0xe0, 0xa0, 0xc0 },
    { 0xe0, 0x80, 0xa0 },
    { 0xc0, 0x80, 0x80 },
    { 0xe0, 0xa0, 0x80 },
    { 0xc0, 0xa0, 0xa0 },
    { 0xe0, 0xc0, 0xa0 },
    { 0xc0, 0xc0, 0x80 },
    { 0xe0, 0xe0, 0x80 },
    { 0xc0, 0xe0, 0xa0 },
    { 0xe0, 0xe0, 0xc0 },
    { 0xe0, 0xc0, 0xe0 },
    { 0xc0, 0xc0, 0xc0 },
    { 0xc0, 0xe0, 0xe0 },
    { 0xa0, 0xe0, 0xc0 },
    { 0xa0, 0xc0, 0xe0 },
    { 0x80, 0xc0, 0xc0 },
    { 0x80, 0xe0, 0xe0 },
    { 0x80, 0xe0, 0xa0 },
    { 0xa0, 0xe0, 0x80 },
    { 0x80, 0xc0, 0x80 },
    { 0xa0, 0xc0, 0xa0 },
    { 0x80, 0xa0, 0xa0 },
    { 0xa0, 0xa0, 0x80 },
    { 0x80, 0x80, 0x80 },
    { 0xa0, 0x80, 0xa0 },
    { 0x80, 0x80, 0xc0 },
    { 0xa0, 0xa0, 0xc0 },
    { 0xa0, 0x80, 0xe0 },
    { 0x80, 0xa0, 0xe0 },
    { 0x60, 0x80, 0xe0 },
    { 0x40, 0xa0, 0xe0 },
    { 0x40, 0x80, 0xc0 },
    { 0x60, 0xa0, 0xc0 },
    { 0x60, 0x80, 0xa0 },
    { 0x40, 0x80, 0x80 },
    { 0x60, 0xa0, 0x80 },
    { 0x40, 0xa0, 0xa0 },
    { 0x60, 0xc0, 0xa0 },
    { 0x40, 0xc0, 0x80 },
    { 0x60, 0xe0, 0x80 },
    { 0x40, 0xe0, 0xa0 },
    { 0x60, 0xe0, 0xc0 },
    { 0x60, 0xc0, 0xe0 },
    { 0x40, 0xc0, 0xc0 },
    { 0x40, 0xe0, 0xe0 },
    { 0x20, 0xe0, 0xc0 },
    { 0x20, 0xc0, 0xe0 },
    { 0x00, 0xc0, 0xc0 },
    { 0x00, 0xe0, 0xe0 },
    { 0x00, 0xe0, 0xa0 },
    { 0x20, 0xe0, 0x80 },
    { 0x00, 0xc0, 0x80 },
    { 0x20, 0xc0, 0xa0 },
    { 0x00, 0xa0, 0xa0 },
    { 0x20, 0xa0, 0x80 },
    { 0x00, 0x80, 0x80 },
    { 0x20, 0x80, 0xa0 },
    { 0x00, 0x80, 0xc0 },
    { 0x20, 0xa0, 0xc0 },
    { 0x20, 0x80, 0xe0 },
    { 0x00, 0xa0, 0xe0 },
    { 0x00, 0x60, 0xe0 },
    { 0x00, 0x40, 0xc0 },
    { 0x20, 0x40, 0xe0 },
    { 0x20, 0x60, 0xc0 },
    { 0x40, 0x60, 0xe0 },
    { 0x60, 0x40, 0xe0 },
    { 0x60, 0x60, 0xc0 },
    { 0x40, 0x40, 0xc0 },
    { 0x40, 0x60, 0xa0 },
    { 0x60, 0x40, 0xa0 },
    { 0x60, 0x60, 0x80 },
    { 0x40, 0x40, 0x80 },
    { 0x20, 0x60, 0x80 },
    { 0x00, 0x60, 0xa0 },
    { 0x20, 0x40, 0xa0 },
    { 0x00, 0x40, 0x80 },
    { 0x20, 0x20, 0x80 },
    { 0x00, 0x20, 0xa0 },
    { 0x20, 0x00, 0xa0 },
    { 0x00, 0x00, 0x80 },
    { 0x40, 0x00, 0x80 },
    { 0x60, 0x20, 0x80 },
    { 0x60, 0x00, 0xa0 },
    { 0x40, 0x20, 0xa0 },
    { 0x40, 0x00, 0xc0 },
    { 0x60, 0x20, 0xc0 },
    { 0x60, 0x00, 0xe0 },
    { 0x40, 0x20, 0xe0 },
    { 0x20, 0x00, 0xe0 },
    { 0x20, 0x20, 0xc0 },
    { 0x00, 0x20, 0xe0 },
    { 0x00, 0x00, 0xc0 }
};

void hexDump (const char *desc, void *addr, int len, int offset);
void rot(int n, int *x, int *y, int rx, int ry);
void d2xy(int n, int d, int *x, int *y);
int xy2d (int n, int x, int y);
void render_full(SDL_Surface *dest, SDL_Rect *view, int hilbert_size);
int phys_mem_write(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf);
int phys_mem_write_graphics(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf);
bool init_sdl(void);
bool init_plugin(void *self);
void uninit_plugin(void *self);
void * display_loop(void *);

#define SIZE 256

void hexDump (const char *desc, void *addr, int len, int offset) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("%08x:", i+offset);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

//rotate/flip a quadrant appropriately
void rot(int n, int *x, int *y, int rx, int ry) {
    assert(__builtin_popcount(n) == 1);
    if (ry == 0) {
        if (rx == 1) {
            *x = n-1 - *x;
            *y = n-1 - *y;
        }
 
        //Swap x and y
        int t  = *x;
        *x = *y;
        *y = t;
    }
}

//convert (x,y) to d
int xy2d (int n, int x, int y) {
    assert(__builtin_popcount(n) == 1);
    int rx, ry, s, d=0;
    for (s=n/2; s>0; s/=2) {
        rx = (x & s) > 0;
        ry = (y & s) > 0;
        d += s * s * ((3 * rx) ^ ry);
        rot(s, &x, &y, rx, ry);
    }
    return d;
}
 
//convert d to (x,y)
void d2xy(int n, int d, int *x, int *y) {
    assert(__builtin_popcount(n) == 1);
    int rx, ry, s, t=d;
    *x = *y = 0;
    for (s=1; s<n; s*=2) {
        rx = 1 & (t/2);
        ry = 1 & (t ^ rx);
        rot(s, x, y, rx, ry);
        *x += s * rx;
        *y += s * ry;
        t /= 4;
    }
}
 
void render_full(SDL_Surface *dest, SDL_Rect *view, int hilbert_size) {
    uint8_t byte = 0;
    // Clear screen
    SDL_FillRect(dest, NULL, 0x000000);
    // Fill the pixel buffer
    //printf("View: %d,%d %dx%d\n", view->x, view->y, view->w, view->h);
    for(int x = view->x; x < view->x+view->w; x++) {
        for (int y = view->y; y < view->y+view->h; y++) {
            int d = xy2d(hilbert_size, x, y);
            
            // Skip parts of the curve outside of RAM
            if (d > ram_size) continue;
            
            // Map it back into the window
            int adj_x, adj_y;
            adj_x = x - view->x;
            adj_y = y - view->y;
            if (-1 == panda_physical_memory_rw(d, &byte, 1, false)) {
                byte = 0;
            }
            uint8_t *color = colortable[byte];
            memcpy(dest->pixels + (adj_y * dest->pitch) + (adj_x * sizeof(Uint8) * 3), color, 3);
        }
    }
}

#define VIEW_LAG_THRESH 1000
// Initialize so that we shift the view once to start with
int view_lag = VIEW_LAG_THRESH+1;
bool init_done = false;
int hilbert_size = 1;
// view controls which portion of the whole curve we can currently see
SDL_Rect view = {0,0,SIZE,SIZE};
SDL_Surface *win;

typedef struct point {
    int x;
    int y;
} point;

#define FF_INTERVAL 500000
int fast_forward_counter;
bool fast_forwarding = false;

int phys_mem_write(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf) {
    if (!fast_forwarding) {
        return phys_mem_write_graphics(env, pc, addr, size, buf);
    }
    else {
        fast_forward_counter--;
        if (fast_forward_counter == 0) {
            fast_forwarding = false;
        }
    }
    return 0;
}

int phys_mem_write_graphics(CPUState *env, target_ulong pc, target_ulong addr,
        target_ulong size, void *buf) {
    point points[16];

    bool should_recenter = false;
    bool would_recenter = false;
    for (int i = 0; i < size; i++) {
        d2xy(hilbert_size, addr+i, &points[i].x, &points[i].y);
        //printf("Write to " TARGET_FMT_lx " pos (%d,%d) val %02x\n", addr+i, points[i].x, points[i].y, ((uint8_t *)buf)[i]);
        // Do we need to change the view?
        if (points[i].x < view.x || points[i].x >= view.x + view.w ||
            points[i].y < view.y || points[i].y >= view.y + view.h) {
            would_recenter = true;
            if (view_lag > VIEW_LAG_THRESH) {
                should_recenter = true;
                view_lag = 0;
            }
            else {
                view_lag++;
            }
        }
        else {
            view_lag = 0;
        }
    }

    // Write is to an area we don't care about (until we get enough writes)
    if (would_recenter && !should_recenter) return 0;

    if (should_recenter) {
        view.x = points[0].x > view.w / 2 ? points[0].x - (view.w / 2) : 0;
        view.y = points[0].y > view.h / 2 ? points[0].y - (view.h / 2) : 0;
    }

    // We check if SDL is already set up here so that our initial view
    // is centered on the first memory write.
    if (!init_done) {
        init_sdl();
        init_done = true;
    }
    else {
        // If we've already initialized, then we need to do a full
        // repaint if the viewpoint has moved
        if (should_recenter) render_full(win, &view, hilbert_size);
    }

    // Do the incremental update
    Uint8 *pixels = (Uint8 *)win->pixels;
    for (int i = 0; i < size; i++) {
        int adj_x, adj_y;
        adj_x = points[i].x - view.x; // map the points into
        adj_y = points[i].y - view.y; // our view
        //printf("Adjusted point: (%d,%d)\n", adj_x, adj_y);
        
        uint8_t byte = *((Uint8 *)(buf + i));
        uint8_t *color = colortable[byte];
        memcpy(pixels + (adj_y * win->pitch) + (adj_x * sizeof(Uint8) * 3), color, 3);
    }

    SDL_Flip(win);

    // Check for mouse click and dump memory
    SDL_Event event;
    if (SDL_PollEvent(&event)) {
        switch(event.type) {
            case SDL_MOUSEBUTTONUP:
                {
                uint32_t addr;
                uint8_t data[0x50];
                addr = xy2d(hilbert_size, event.button.x+view.x, event.button.y+view.y);
                uint32_t start = addr >= 0x20 ? addr - 0x20 : 0;
                panda_physical_memory_rw(addr, data, 0x50, false);
                hexDump("Memory", data, 0x50, start);
                }
                break;
            case SDL_KEYUP:
                if (event.key.keysym.sym == SDLK_f) {
                    view_lag = VIEW_LAG_THRESH;
                    fast_forward_counter = FF_INTERVAL;
                    fast_forwarding = true;
                }
                else if (event.key.keysym.sym == SDLK_g) {
                    view_lag = VIEW_LAG_THRESH;
                    fast_forward_counter = FF_INTERVAL*10;
                    fast_forwarding = true;
                }
                else if (event.key.keysym.sym == SDLK_q) {
                    qemu_system_shutdown_request();
                }
                break;
            case SDL_QUIT:
                qemu_system_shutdown_request();
                break;
        }
    }

    return 0;
}

bool init_plugin(void *self) {
    panda_cb pcb;

    panda_enable_memcb();

    pcb.phys_mem_write = phys_mem_write;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_WRITE, pcb);

    return true;
}

void * display_loop(void *unused) {
    while (true) {
        SDL_Flip(win);
        SDL_Delay(10);
    }
    return NULL;
}

bool init_sdl(void) {
    // Figure out how big the whole hilbert curve needs to be
    hilbert_size = 1;
    while ((hilbert_size*hilbert_size) < ram_size) {
        hilbert_size <<= 1;
    }
    fprintf(stderr, "NOTE: Creating a %d x %d canvas.\n", hilbert_size, hilbert_size);

    // Init SDL
    if (SDL_Init(SDL_INIT_EVERYTHING) != 0) {
        fprintf(stderr, "SDL_Init Error: %s\n", SDL_GetError());
        return false;
    }
    win = SDL_SetVideoMode(SIZE, SIZE, 24, SDL_HWSURFACE | SDL_DOUBLEBUF);
    if (win == NULL) {
        fprintf(stderr, "SDL_SetVideoMode failed: %s\n", SDL_GetError());
        return false;
    }
    SDL_WM_SetCaption("Hilbert", "Hilbert");

    // Do the initial rendering
    render_full(win, &view, hilbert_size);
    SDL_Flip(win);

    //pthread_t t;
    //pthread_create(&t, NULL, display_loop, NULL);

    return true;
}

void uninit_plugin(void *self) {
    SDL_Quit();
}

#endif /* CONFIG_USER_ONLY */
