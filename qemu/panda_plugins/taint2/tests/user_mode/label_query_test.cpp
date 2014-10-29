//Panda Label and Query Test
//Sam Coe

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "panda_mark.h"

void label_buffer(unsigned long, unsigned long);
void query_buffer(unsigned long, unsigned long);

int main(int argc, char* argv[]) {
  unsigned long buffer = 1;

  label_buffer((uint64_t)&buffer, sizeof(unsigned long));
  query_buffer((uint64_t)&buffer, sizeof(unsigned long));

  printf("Completed successfully\n");

  return 0;
}


