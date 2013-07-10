#ifndef __PANDA_MARK_H__
#define __PANDA_MARK_H__

const int LABEL_BUFFER = 0;
const int QUERY_BUFFER = 1;

inline
void cpu_id(unsigned long buf, unsigned long len, int action) {
  unsigned long rax = 0xDEADBEEF;
  unsigned long rbx = action;
  unsigned long rcx = buf;
  unsigned long rdx = len;

  asm ("push %%rax \t\n\
        push %%rbx \t\n\
        push %%rcx \t\n\
        push %%rdx \t\n\
        mov  %0, %%rax \t\n\
        mov  %1, %%rbx \t\n\
        mov  %2, %%rcx \t\n\
        mov  %3, %%rdx \t\n\
        cpuid \t\n\
        pop  %%rax \t\n\
        pop  %%rbx \t\n\
        pop  %%rcx \t\n\
        pop  %%rdx \t\n\
      "
      : /* no output registers */
      : "r" (rax), "r" (rbx), "r" (rcx), "r" (rdx)
      : /* no clobbered registers */
      );
  return;
}

/* buf is the address of the buffer to be labeled
 * len is the length of the buffer to be labeled */
inline
void label_buffer(unsigned long buf, unsigned long len) {
  printf("Address to be labeled: 0x%lx\n", buf);
  printf("Size in bytes: %lu\n", len);
  cpu_id(buf, len, LABEL_BUFFER);
  return;
}

/* buf is the address of the buffer to be queried
 * len is the length of the buffer to be queried */
inline
void query_buffer(unsigned long buf, unsigned long len) {
  printf("Address to be queried: 0x%lx\n", buf);
  printf("Size in bytes: %lu\n", len);
  cpu_id(buf, len, QUERY_BUFFER);
  return;
}

#endif
