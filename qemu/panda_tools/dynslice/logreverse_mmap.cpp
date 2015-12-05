#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <string>

// Reverse an (uncompressed) tubtf log, in-place.
// This reverses the basic blocks, not the instructions.

typedef enum {
  TUBTFE_USE =          0,
  TUBTFE_DEF =          1,
  TUBTFE_TJMP =         2,   // tainted jmp target
  TUBTFE_TTEST =        3,   // tainted test arg
  TUBTFE_TCMP =         4,   // tainted cmp arg
  TUBTFE_TLDA =         5,   // tainted ld addr
  TUBTFE_TLDV =         6,   // tainted ld val
  TUBTFE_TSTA =         7,   // tainted st addr
  TUBTFE_TSTV =         8,   // tainted st val
  TUBTFE_TFNA_VAL =     9,   // tainted fn arg value
  TUBTFE_TFNA_PTR =     10,  // tainted data pointed to by fn arg
  TUBTFE_TFNA_STR =     11,  // tainted data string pointed to by fn arg
  TUBTFE_TFNA_ECX =     12,  // tainted fastcall fn arg value ecx
  TUBTFE_TFNA_EDX =     13,  // tainted fastcall fn arg value edx
  TUBTFE_TVE_JMP =      14,  // tainted value expr (tve) jmp target
  TUBTFE_TVE_TEST_T0 =  15,  // tve test arg
  TUBTFE_TVE_TEST_T1 =  16,  // tve test arg
  TUBTFE_TVE_CMP_T0 =   17,  // tve cmp arg
  TUBTFE_TVE_CMP_T1 =   18,  // tve cmp arg
  TUBTFE_TVE_LDA =      19,  // tve ld addr
  TUBTFE_TVE_LDV =      20,  // tve ld val
  TUBTFE_TVE_STA =      21,  // tve st addr
  TUBTFE_TVE_STV =      22,  // tve st arg

  // LLVM trace stuff
  TUBTFE_LLVM_FN =         30,  // entering LLVM function
  TUBTFE_LLVM_DV_LOAD =    31,  // dyn load
  TUBTFE_LLVM_DV_STORE =   32,  // dyn store
  TUBTFE_LLVM_DV_BRANCH =  33,  // dyn branch
  TUBTFE_LLVM_DV_SELECT =  34,  // dyn select
  TUBTFE_LLVM_DV_SWITCH =  35,  // dyn switch
  TUBTFE_LLVM_EXCEPTION =  36,   // some kind of fail?

  TUBTFE_LAST = 37
} TubtfEIType;

std::string TubtfEITypeStr[TUBTFE_LAST] = {
    "TUBTFE_USE",
    "TUBTFE_DEF",
    "TUBTFE_TJMP",
    "TUBTFE_TTEST",
    "TUBTFE_TCMP",
    "TUBTFE_TLDA",
    "TUBTFE_TLDV",
    "TUBTFE_TSTA",
    "TUBTFE_TSTV",
    "TUBTFE_TFNA_VAL",
    "TUBTFE_TFNA_PTR",
    "TUBTFE_TFNA_STR",
    "TUBTFE_TFNA_ECX",
    "TUBTFE_TFNA_EDX",
    "TUBTFE_TVE_JMP",
    "TUBTFE_TVE_TEST_T0",
    "TUBTFE_TVE_TEST_T1",
    "TUBTFE_TVE_CMP_T0",
    "TUBTFE_TVE_CMP_T1",
    "TUBTFE_TVE_LDA",
    "TUBTFE_TVE_LDV",
    "TUBTFE_TVE_STA",
    "TUBTFE_TVE_STV",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "TUBTFE_LLVM_FN",
    "TUBTFE_LLVM_DV_LOAD",
    "TUBTFE_LLVM_DV_STORE",
    "TUBTFE_LLVM_DV_BRANCH",
    "TUBTFE_LLVM_DV_SELECT",
    "TUBTFE_LLVM_DV_SWITCH",
    "TUBTFE_LLVM_EXCEPTION",
};

struct tubtf_row_64 {
    uint64_t asid;
    uint64_t pc;
    uint64_t type;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
};

static inline void update_progress(uint64_t cur, uint64_t total) {
    double pct = cur / (double)total;
    const int columns = 80;
    printf("[");
    int pos = columns*pct;
    for (int i = 0; i < columns; i++) {
        if (i < pos) printf("=");
        else if (i == pos) printf(">");
        else printf(" ");
    }
    printf("] %02d%%\r", (int)(pct*100));
    fflush(stdout);
}

// Swap the ith and jth records
// Assumes file has been opened in r+ mode
static inline void swaprecs(tubtf_row_64 *rows, uint64_t i, uint64_t j) {
    tubtf_row_64 row = {};
    // Read i
    row = rows[i];
    rows[i] = rows[j];
    rows[j] = row;
}

// Reverse a section of the file in-place
static inline void reverse(tubtf_row_64 *rows, uint64_t start, uint64_t end, bool progress) {
    uint64_t i = start, j = end;
    uint64_t mid = (end - start + 1) / 2;
    uint64_t interval = mid / 100;
    while (i < j) {
        if (progress && (i % interval) == 0) update_progress(i, mid);
        swaprecs(rows, i, j); 
        i++; j--;
    }
    if (progress) update_progress(mid, mid);
}

int main(int argc, char **argv) {
    struct stat st;
    if(argc < 2) {
        fprintf(stderr, "usage: %s <tubtf.log>\n", argv[0]);
        return 1;
    }
    if (stat(argv[1], &st) != 0) {
        perror("stat");
        return 1;
    }
    int fd = open(argv[1], O_RDWR|O_LARGEFILE);
    uint8_t *mapped = (uint8_t *)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    // Skip header
    tubtf_row_64 *rows = (tubtf_row_64 *)(mapped + 20);

    uint64_t num_records = (st.st_size - 20) / sizeof(tubtf_row_64);
    printf("Reversing %d records in place... \n", num_records);
    reverse(rows, 0, num_records - 1, true);
    printf("\n");

    printf("Reversing each group.... \n");
    uint64_t i = 0, j = 0;
    uint64_t interval = num_records / 100;
    tubtf_row_64 row = {};
    do {
        if ((j % interval) == 0) update_progress(j, num_records);

        if (rows[j].type == TUBTFE_LLVM_FN) {
            reverse(rows, i, j, false);
            i = j+1;
        }
        j++;
    } while (j < num_records);
    update_progress(num_records, num_records);

    munmap(rows, st.st_size);
    close(fd);

    return 0;
}
