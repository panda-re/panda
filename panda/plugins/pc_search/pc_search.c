/* PANDABEGINCOMMENT
 * 
 * Authors: FlyingRagnar (Jim Knapp)
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#include "panda/plugin.h"

int insn_exec_callback(CPUState *env, target_ulong pc);
bool translate_callback(CPUState* env, target_ulong pc);
bool init_plugin(void *);
void uninit_plugin(void *);
int num_of_input_pcs = 0;
uint64_t* input_pcs = NULL;
bool range_passed = false;
uint64_t input_pc_range[2];
uint64_t* first_instr;
uint64_t* last_instr;
static bool first_last_only = false;
FILE *counterslog = NULL;

int insn_exec_callback(CPUState *env, target_ulong pc) {
    assert(rr_in_replay());
    
    uint64_t curinstr = rr_get_guest_instr_count();

    if (first_last_only) {
        for (int i=0; i < num_of_input_pcs; i++) {
            if (pc == input_pcs[i]) {
                if ( first_instr[i] == 0 ) {
                    // this is first occurrence of this pc
                    first_instr[i] = curinstr;
                    last_instr[i] = curinstr;
                } else {
                    // store guest instruction as the current last one for this pc
                    last_instr[i] = curinstr;
                }
            }   
        }
        
        if (range_passed) {
            if (first_instr[0] == 0) {
                first_instr[0] = curinstr;
                last_instr[0] = curinstr;
            } else {
                last_instr[0] = curinstr;
            }
        }
    } else {
        fprintf(counterslog, "PC:0x%" PRIx64 " Guest Instr:%" PRIu64 "\n", (uint64_t)pc, curinstr);
    }     
    return 0;
}

bool translate_callback(CPUState* env, target_ulong pc) {
    for (int i=0; i < num_of_input_pcs; i++) {
        if (pc == input_pcs[i]) {
            return true;
        }
    }
    
    if (range_passed) {
        if (pc >= input_pc_range[0] && pc <= input_pc_range[1])
            return true;
    }
    return false; 
}

bool init_plugin(void *self) {
    panda_arg_list *args = panda_get_args("pc_search");
    if (args != NULL) {
        uint64_t pc = panda_parse_uint64_opt(args, "pc", 0, 
                "program counter to search for");
        first_last_only = panda_parse_bool_opt(args, "first_last_only",
                "output only first and last occurrence of each pc");
        const char* pc_filename = panda_parse_string_opt(args, "pc_file", "",
                "filename of the text file containing pc values");
        const char* out_filename = panda_parse_string_opt(args, "out_file", "pc_matches.txt",
                "filename of the output text file");
        const char* pc_range = panda_parse_string_opt(args, "pc_range", "",
                "range of pc values to search for");
                
        
        int in_count = 0;
        if (strlen(pc_filename) != 0)
          in_count += 1;
        if (pc != 0)
          in_count += 1;
        if (strlen(pc_range) != 0)
          in_count += 1;
        if (in_count == 0) {
          fprintf(stderr, "error: must specify one input parameter (pc, pc_file, or pc_range)\n");
          return false;
        } else if (in_count > 1) {
          fprintf(stderr, "error: only one input (pc, pc_file, or pc_range) can be specified\n");
          return false;
        }
        
        // if file passed, read contents into an array
        if (strlen(pc_filename) != 0) {
            FILE *pc_input_file = fopen(pc_filename, "r");
            
            if (pc_input_file == NULL) {
              fprintf(stderr, "error: could not open file %s\n", pc_filename);
              return false;
            }

            char str[24];  // largest unsigned 64 bit integer is 20 decimal digits, plus potentially 4 characters for line endings
            // get count for number of valid input pcs
            while(fgets(str,24,pc_input_file)) {
                str[strcspn(str,"\r\n")] = 0;
                if (strlen(str) == 0) {
                    continue;
                }
                num_of_input_pcs++;
            }
            rewind(pc_input_file);
        
            input_pcs = (uint64_t*)malloc(num_of_input_pcs * sizeof(uint64_t));
            int j = 0;  
            while(fgets(str,24,pc_input_file)) {
                str[strcspn(str,"\r\n")] = 0;
                if (strlen(str) == 0) {
                    continue;
                }

                input_pcs[j] = (uint64_t) strtoul(str,NULL,0);                             
                j++;
            }
            fclose(pc_input_file);  
        } else if (strlen(pc_range) != 0) {
            
            // verify input contains a hyphen and no spaces
            char* check = strstr(pc_range,"-");
            if (!check) {
                fprintf(stderr, "error: pc_range must contain a hyphen between two pc values\n");
                return false;
            }
            check = strstr(pc_range," ");
            if (check) {
                fprintf(stderr, "error: pc_range should contain two pc values separated by a hyphen with no spaces\n");
                return false;
            }
        
            range_passed = true;
            char* range_cpy = strdup(pc_range);
            char* token = strtok(range_cpy,"-");
            input_pc_range[0] = (uint64_t) strtoul(token,NULL,0);
            token = strtok(NULL,"-");
            input_pc_range[1] = (uint64_t) strtoul(token,NULL,0);
            
            if (input_pc_range[0] >= input_pc_range[1]) {
                fprintf(stderr, "error: pc_range not a valid range, left value must be less than right value\n");
                return false;
            }
            
        } else {
            // use single pc value passed, which defaults to 0
            num_of_input_pcs = 1;
            input_pcs = (uint64_t*)malloc(num_of_input_pcs * sizeof(uint64_t));
            input_pcs[0] = pc;
        }
        
        // if first last only, create arrays to store/track instructions
        if (first_last_only) {
            if (num_of_input_pcs > 0) {
                first_instr = (uint64_t*)calloc(num_of_input_pcs, sizeof(uint64_t));
                last_instr = (uint64_t*)calloc(num_of_input_pcs, sizeof(uint64_t));
            } else if (range_passed) {
                first_instr = (uint64_t*)calloc(1, sizeof(uint64_t));
                last_instr = (uint64_t*)calloc(1, sizeof(uint64_t));
            }
        }
        
        // open file for output
        counterslog = fopen(out_filename, "w");
        
        // print out input parameters to console
        fprintf(stderr, "%sfirst last instructions only %s\n", PANDA_MSG, PANDA_FLAG_STATUS(first_last_only));
        for (int l=0; l < num_of_input_pcs; l++) {
            fprintf(stderr, "%sinput pc %i = 0x%" PRIx64 "\n", PANDA_MSG, l, input_pcs[l]);
        }
        
        if (range_passed) {
            fprintf(stderr, "%spc start range 0x%" PRIx64 " pc end range 0x%" PRIx64 "\n", PANDA_MSG, input_pc_range[0], input_pc_range[1]);
        }
    }

    panda_cb pcb;
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_exec = insn_exec_callback;
    panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {

    // if first last only, print out instructions
    if (first_last_only) {
        for (int i=0; i < num_of_input_pcs; i++) {
            fprintf(counterslog, "PC:0x%" PRIx64 " First Guest Instr:%" PRIu64 " Last Guest Instr:%" PRIu64 "\n", input_pcs[i], first_instr[i], last_instr[i]);
        }
        
        if (range_passed) {
            fprintf(counterslog, "PC Range:0x%" PRIx64 "-0x%" PRIx64 " First Guest Instr:%" PRIu64 " Last Guest Instr:%" PRIu64 "\n", input_pc_range[0], input_pc_range[1], first_instr[0], last_instr[0]);
        }
        free(first_instr);
        free(last_instr);
    }
    
    if (num_of_input_pcs > 0)
        free(input_pcs);
    
    if (counterslog != NULL) {
        fclose(counterslog);
        counterslog = NULL;
    }
}


