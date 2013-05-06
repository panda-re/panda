/**
 * Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of 
 * the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public 
 * License along with this program; if not, write to the Free 
 * Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, 
 * MA 02111-1307 USA
**/

#ifndef _DECAF_VM_COMPRESS_H_
#define _DECAF_VM_COMPRESS_H_
#include <zlib.h>
#define IOBUF_SIZE 4096

#include "hw/hw.h" // AWH

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

//typedef unsigned char uint8_t;

typedef struct{
    z_stream zstream;
    void *f;
    uint8_t buf[IOBUF_SIZE];
} DECAF_CompressState_t;

extern int DECAF_compress_open(DECAF_CompressState_t *s, void *f);
extern int DECAF_compress_buf(DECAF_CompressState_t *s, const uint8_t *buf, int len);
extern void DECAF_compress_close(DECAF_CompressState_t *s);
extern int DECAF_decompress_open(DECAF_CompressState_t *s, void *f);
extern int DECAF_decompress_buf(DECAF_CompressState_t *s, uint8_t *buf, int len);
extern void DECAF_decompress_close(DECAF_CompressState_t *s);
extern void DECAF_vm_compress_init(void); //dummy init

#ifdef __cplusplus
}
#endif // __cplusplus

#endif //_TEMU_VM_COMPRESS_H_
