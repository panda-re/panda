#ifndef __PANDA_MARK_H__
#define __PANDA_MARK_H__

#if !defined(TARGET_I386) && !defined(TARGET_ARM)
#error "Define your architecture (TARGET_I386 or TARGET_ARM) with -D"
#endif

const int LABEL_BUFFER = 7;
const int LABEL_BUFFER_POS = 8;
const int QUERY_BUFFER = 9;
const int ENABLE_TAINT = 10;
const int DISABLE_TAINT = 11;

#define debug 0

void hypercall(unsigned long buf, unsigned long len, unsigned long arg, int action);


#ifdef TARGET_I386
inline
void hypercall(unsigned long buf, unsigned long len, unsigned long arg, int action) {
  unsigned long eax = action;
  unsigned long ebx = buf;
  unsigned long ecx = len;
  unsigned long edx = arg; // label.  or query number.  or whatever

  asm __volatile__
      ("push %%eax \t\n\
        push %%ebx \t\n\
        push %%ecx \t\n\
        push %%edx \t\n\
        mov  %0, %%eax \t\n\
        mov  %1, %%ebx \t\n\
        mov  %2, %%ecx \t\n\
        mov  %3, %%edx \t\n\
        cpuid \t\n\
        pop  %%edx \t\n\
        pop  %%ecx \t\n\
        pop  %%ebx \t\n\
        pop  %%eax \t\n\
       "
      : /* no output registers */
      : "g" (eax), "g" (ebx), "g" (ecx), "g" (edx) /* input operands */
      : "eax", "ebx", "ecx", "edx" /* clobbered registers */
      );
  return;
}



#endif // TARGET_I386

#ifdef TARGET_ARM
inline
void hypercall(unsigned long buf, unsigned long len, unsigned long arg, int action) {
    unsigned long r0 = action;
    unsigned long r1 = buf;
    unsigned long r2 = len;
    unsigned long r3 = arg;

    asm __volatile__
      ("push {%%r0-%%r3} \t\n\
        mov %%r0, %0 \t\n\
        mov %%r1, %1 \t\n\
        mov %%r2, %2 \t\n\
        mov %%r3, %3 \t\n\
        mcr p7, 0, r0, c0, c0, 0 \t\n\
        pop {%%r0-%%r3} \t\n"
      
      : /* no output registers */
      : "r" (r0), "r" (r1), "r" (r2), "r" (r3) /* input operands */
      : "r0", "r1", "r2", "r3" /* clobbered registers */
      );
    return;
}
#endif // TARGET_ARM

inline
void enable_taint(void) {
    hypercall(0,0,0,ENABLE_TAINT);
}

inline
void disable_taint(void) {
    hypercall(0,0,0,DISABLE_TAINT);
}

/* buf is the address of the buffer to be labeled
 * len is the length of the buffer to be labeled */
inline
void label_buffer(unsigned long buf, unsigned long len, unsigned long label, int  pos) {
    if (debug) {
        printf("Address to be labeled: 0x%lx\n", buf);
        printf("Size in bytes: %lu\n", len);
    }
    if (pos) {
        if (debug) printf ("Positional labels starting at %lu \n", label);
        hypercall(buf, len, label, LABEL_BUFFER_POS);
    }
    else {
        if (debug) printf ("Non-positional label %lu\n", label);
        hypercall(buf, len, label, LABEL_BUFFER);
    }
    return;
}

/* buf is the address of the buffer to be queried
 * len is the length of the buffer to be queried */
inline
void query_buffer(unsigned long buf, unsigned long len, unsigned long query_number) {
    if (debug) {
        printf("Address to be queried: 0x%lx\n", buf);
        printf("Size in bytes: %lu\n", len);
    }
    hypercall(buf, len, query_number, QUERY_BUFFER);
    return;
}

void enable_taint(void);
void disable_taint(void);
void label_buffer(unsigned long buf, unsigned long len, unsigned long label, int pos);
void query_buffer(unsigned long buf, unsigned long len, unsigned long query_number);


#endif
