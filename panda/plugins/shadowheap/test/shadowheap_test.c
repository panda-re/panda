#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define NUM_TO_MALLOC 10
#define READ_OOB_INDEX 5
#define WRITE_OOB_INDEX 6
#define REALLOC_INDEX 2
#define MALLOC_SIZE 128
#define PADDING 64

static char *vec[NUM_TO_MALLOC];

int
main(int argc, char *argv[])
{
    char *data;
    char value;

    /* I'm writing to /dev/null to ensure the compiler doesn't
       remove read accesses. */
    FILE *null_fp = fopen("/dev/null", "w");

    (void)argc;
    (void)argv;

    printf("Malloc %d items\n", NUM_TO_MALLOC);
    for (int i = 0; i < NUM_TO_MALLOC; i++) {
        data = (char *)malloc(MALLOC_SIZE);
        vec[i] = data;
        printf("%d: %p\n", i, data);
    }

    for (int i = 0; i < NUM_TO_MALLOC; i++) {
        data = vec[i];
        memset(data, 0, MALLOC_SIZE);
    }

    printf("Reading OOB Test\n");
    data = vec[READ_OOB_INDEX];
    printf("OOB read should be detected from %p-%p\n",
           &data[MALLOC_SIZE],
           &data[MALLOC_SIZE+PADDING-1]);
    for (int i = MALLOC_SIZE; i < MALLOC_SIZE+PADDING; i++) {
        value = data[i];
        fprintf(null_fp, "value=%d\n", (int)value);
    }

    printf("Writing OOB Test\n");
    data = vec[WRITE_OOB_INDEX] - 60;
    printf("OOB write should be detected at %p\n", data);
    data[0] = value;
    data[60] = value;

    printf("Valid realloc test OOB Test\n");
    data = vec[REALLOC_INDEX];
    data = (char *)realloc(data, MALLOC_SIZE * 2);
    memset(data, 0, MALLOC_SIZE * 2);
    data = (char *)realloc(data, 10);
    memset(data, 0, 10);
    data = (char *)realloc(data, MALLOC_SIZE * 4);
    memset(data, 0, MALLOC_SIZE * 4);

    printf("OOB write should be detected at %p\n",
           &data[MALLOC_SIZE * 4 + 1]);
    data[MALLOC_SIZE * 4 + 1] = 1;

    printf("OOB write should be detected at %p\n",
           data-1);
    data[-1] = 0;

    printf("OOB read should be detected at %p\n",
           &data[MALLOC_SIZE * 4 + 1]);
    value = data[MALLOC_SIZE * 4 + 1];
    fprintf(null_fp, "%d", (int)value);

    printf("OOB read should be detected at %p\n",
           data-1);
    value = data[-1];
    fprintf(null_fp, "%d", (int)value);

    printf("Double free should be detected at %p\n", vec[READ_OOB_INDEX]);
    free(vec[READ_OOB_INDEX]);
    free(vec[READ_OOB_INDEX]);

    return 0;
}
