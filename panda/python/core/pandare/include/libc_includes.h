// Sometimes it is convenient to call C functions. They go here.
// from the C <stdio.h>
FILE *fdopen(int, const char *);   
FILE *fopen(const char *, const char*);   
int fileno(FILE *);
int fclose(FILE *);
extern FILE *stderr;
extern FILE *stdout;