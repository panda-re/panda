#ifndef __PANDA_MARK_H__
#define __PANDA_MARK_H__

const int LABEL_BUFFER = 0;
const int QUERY_BUFFER = 1;

inline
void cpu_id(unsigned buf, unsigned len, int action) {
  unsigned eax_var = 0xDEADBEEF;
  unsigned ebx_var = action;
  unsigned ecx_var = buf;
  unsigned edx_var = len;

  __asm {
        push eax
        push ebx
        push ecx
        push edx
		mov eax, eax_var
		mov ebx, ebx_var
		mov ecx, ecx_var
		mov edx, edx_var
        cpuid
        pop edx
        pop ecx
        pop ebx
        pop eax
  };
  return;
}

/* buf is the address of the buffer to be labeled
 * len is the length of the buffer to be labeled */
inline
void label_buffer(unsigned buf, unsigned len) {
  printf("Address to be labeled: 0x%lx\n", buf);
  printf("Size in bytes: %lu\n", len);
  cpu_id(buf, len, LABEL_BUFFER);
  return;
}

/* buf is the address of the buffer to be queried
 * len is the length of the buffer to be queried */
inline
void query_buffer(unsigned buf, unsigned len) {
  printf("Address to be queried: 0x%lx\n", buf);
  printf("Size in bytes: %lu\n", len);
  cpu_id(buf, len, QUERY_BUFFER);
  return;
}

#endif
