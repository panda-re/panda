/******************************************************************************
 * Copyright (c) 2004, 2008 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/


#ifndef OF_H
#define OF_H
#define p32 int
#define p32cast (int) (unsigned long) (void*)

#define phandle_t p32
#define ihandle_t p32

typedef struct 
{
    unsigned int serv;
    int nargs;
    int nrets;
    unsigned int args[16];
} of_arg_t;


phandle_t of_finddevice (const char *);
phandle_t of_peer (phandle_t);
phandle_t of_child (phandle_t);
phandle_t of_parent (phandle_t);
int of_getprop (phandle_t, const char *, void *, int);
void * of_call_method_3 (const char *, ihandle_t, int);


ihandle_t of_open (const char *);
void of_close(ihandle_t);
int of_read (ihandle_t , void*, int);
int of_write (ihandle_t, void*, int);
int of_seek (ihandle_t, int, int);

void * of_claim(void *, unsigned int , unsigned int );
void of_release(void *, unsigned int );

int of_yield(void);
void * of_set_callback(void *);

unsigned int romfs_lookup(const char *, void **);
int vpd_read(unsigned int , unsigned int , char *);
int vpd_write(unsigned int , unsigned int , char *);
int write_mm_log(char *, unsigned int , unsigned short );

#endif
