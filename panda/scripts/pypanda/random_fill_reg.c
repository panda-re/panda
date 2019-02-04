#include <stdio.h>
#include <stdio.h> 
#include <stdlib.h> 
#include <time.h>

int main() {
    srand(time(0));

    fill_regs(9, 8, 7);

	int a,b,c;
    asm("\t movl %%eax,%0" : "=r"(a));
    asm("\t movl %%ebx,%0" : "=r"(b));
    asm("\t movl %%ecx,%0" : "=r"(c));

	printf("a = %d, b = %d, c = %d \n\r", a,b,c);
	return 0;
}

void fill_regs(int c, int b, int a){
    register int p1 asm("eax") = a;
    register int p2 asm("ebx") = b;
    register int p3 asm("ecx") = c;
}

void printRandoms(int lower, int upper, int count) 
{ 
    int i; 
    for (i = 0; i < count; i++) { 
        int num = (rand() % 
           (upper - lower + 1)) + lower; 
        printf("%d ", num); 
    } 
} 