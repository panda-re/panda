//Panda Label and Query Test
//Sam Coe

#include <stdio.h>
#include <string.h>
#include <cpuid.h>

void label_buffer(unsigned, unsigned);
void query_buffer(unsigned, unsigned, unsigned);

int main(int argc, char* argv[]) {
  unsigned buffer = 1;

  label_buffer(buffer, sizeof(buffer));
  //query_buffer(&buffer, sizeof(buffer), 0);
  //vm_guest_util_done();

  printf("Completed successfully\n");

  return 0;
}

void label_buffer(unsigned buf, unsigned buf_len) {
  unsigned level = 0;
  unsigned eax = 0;
  unsigned ebx;
  unsigned ecx;
  unsigned edx;
  //unsigned ebx = buf;
  //unsigned ecx = buf_len;
  //unsigned edx = 0;

  __get_cpuid(level, &eax, &ebx, &ecx, &edx);
  printf("Max instruction ID: %i\n", eax);
  return;
}

void query_buffer(unsigned buf, unsigned len, unsigned offset) {
  return;
}
