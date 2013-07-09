//Panda Label and Query Test
//Sam Coe

#include <stdio.h>
#include <string.h>
#include <cpuid.h>

void label_buffer(unsigned long, unsigned long);
void query_buffer(unsigned long, unsigned long);

int main(int argc, char* argv[]) {
  unsigned long buffer = 1;

  label_buffer(buffer, sizeof(buffer));
  query_buffer(buffer, sizeof(buffer));

  printf("Completed successfully\n");

  return 0;
}

void label_buffer(unsigned long buf, unsigned long len) {
  unsigned long rax = 0xDEADBEEF;
  unsigned long rbx = 0;
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
      : "r" (rax), "r" (rbx), "r" (&rcx), "r" (rdx)
      : /* no clobbered registers */
      );
  printf("Address to be labeled: %p\n", &rcx);
  printf("Size in bytes: %lu\n", rdx);
  return;
}

//TODO: Refactor so there is only one assembly
void query_buffer(unsigned long buf, unsigned long len) {
  unsigned long rax = 0xDEADBEEF;
  unsigned long rbx = 1;
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
      : "r" (rax), "r" (rbx), "r" (&rcx), "r" (rdx)
      : /* no clobbered registers */
      );

  printf("Address to be queried: %p\n", &rcx);
  printf("Size in bytes: %lu\n", rdx);
  return;
}
