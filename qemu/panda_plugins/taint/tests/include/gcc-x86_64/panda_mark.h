#ifndef __PANDA_MARK_H__
#define __PANDA_MARK_H__

const int LABEL_BUFFER = 7;
const int LABEL_BUFFER_POS = 8;
const int QUERY_BUFFER = 9;

inline
void cpu_id(unsigned long buf, unsigned long len, unsigned long off, int action) {
  unsigned long rax = action;
  unsigned long rbx = buf;
  unsigned long rcx = len;
  unsigned long rdx = off;

  asm __volatile__
      ("push %%rax \t\n\
        push %%rbx \t\n\
        push %%rcx \t\n\
        push %%rdx \t\n\
        mov  %0, %%rax \t\n\
        mov  %1, %%rbx \t\n\
        mov  %2, %%rcx \t\n\
        mov  %3, %%rdx \t\n\
        cpuid \t\n\
        pop  %%rdx \t\n\
        pop  %%rcx \t\n\
        pop  %%rbx \t\n\
        pop  %%rax \t\n\
       "
      : /* no output registers */
      : "r" (rax), "r" (rbx), "r" (rcx), "r" (rdx) /* input operands */
      : "rax", "rbx", "rcx", "rdx" /* clobbered registers */
      );
  return;
}

/* buf is the address of the buffer to be labeled
 * len is the length of the buffer to be labeled */
inline
void label_buffer(unsigned long buf, unsigned long len) {
  printf("Address to be labeled: 0x%lx\n", buf);
  printf("Size in bytes: %lu\n", len);
  //Ignore offset for now
  cpu_id(buf, len, 0, LABEL_BUFFER);
  return;
}

/* buf is the address of the buffer to be queried
 * len is the length of the buffer to be queried */
inline
void query_buffer(unsigned long buf, unsigned long len) {
  printf("Address to be queried: 0x%lx\n", buf);
  printf("Size in bytes: %lu\n", len);
  //Ignore offset for now
  cpu_id(buf, len, 0, QUERY_BUFFER);
  return;
}

#endif
