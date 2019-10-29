/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#include <math.h>

#include "panda/plugin.h"
#include "qmp-commands.h"

const double MIN_FRACTION = 0.0;
const double MAX_FRACTION = 1.0;

void before_block_callback(CPUState *env, TranslationBlock *tb);

bool init_plugin(void *);
void uninit_plugin(void *);

int num = 0;
uint64_t total_insns = 0;
bool save_instr_count = false;
float xfraction = 1.0;
float yfraction = 1.0;
FILE *counterslog = NULL;

void before_block_callback(CPUState *env, TranslationBlock *tb) {
    assert(rr_in_replay());
    char fname[256] = {0};
    if (total_insns == 0) {
    	total_insns = replay_get_total_num_instructions();
    	if (save_instr_count) {
    	    uint16_t needed_digits = (uint16_t)(floor(log10(total_insns) + 1));
    	    counterslog = fopen("replay_movie_counters.txt", "w");
    	    fprintf(counterslog, "%d\n", needed_digits);
    	}
    }
    if (rr_get_percentage() >= num) {
        Error *errp;
        snprintf(fname, 255, "replay_movie_%03d.ppm", (int)num);
        qmp_screendump(fname, &errp);

        if (save_instr_count) {
            // have to save some general information the first time around
            if (0 == num) {
                // there isn't any way to get the width and height w/out adding
                // API to the console file, other than reading an output file
                // yes, we are assuming every screen shot has same size
				FILE *f000 = fopen("replay_movie_000.ppm", "r");
				if (f000 != NULL) {
					// skip past the P6\n at front of file, and then read the
					// width
					int curdim;
					int itemsfilled = fscanf(f000, "%*2c%d", &curdim);
					if (1 == itemsfilled) {
					    fprintf(counterslog, "%d\n", curdim);
					    fprintf(counterslog, "%f\n", xfraction);
					} else {
						LOG_ERROR("Could not read width from image 0");
					}

					// now the height
					itemsfilled = fscanf(f000, "%d", &curdim);
					if (1 == itemsfilled) {
					    fprintf(counterslog, "%d\n", curdim);
					    fprintf(counterslog, "%f\n", yfraction);
					} else {
						LOG_ERROR("Could not read height from image 0");
					}
				} else {
					LOG_ERROR("Could not open image 0 to fetch dimensions");
				}
				fclose(f000);
            }

            // save current instruction count
            uint64_t curinstr = rr_get_guest_instr_count();
            fprintf(counterslog, "%" PRId64 "\n", curinstr);
        }
        num += 1;
    }
    return;
}

bool init_plugin(void *self) {
	panda_arg_list *args = panda_get_args("replaymovie");
	if (args != NULL) {
		save_instr_count = panda_parse_bool_opt(args, "save_instruction_count",
				"save instruction counter for each image");
		if (save_instr_count) {
			double fraction_loc = panda_parse_double_opt(args, "xfraction",
					MAX_FRACTION,
					"fraction along the x axis at which to place the counter [0.0, 1.0]");
			if (fraction_loc < MIN_FRACTION) {
				xfraction = MIN_FRACTION;
				LOG_WARNING("xfraction out of range, reset to minimum");
			} else if (fraction_loc > MAX_FRACTION) {
				xfraction = MAX_FRACTION;
				LOG_WARNING("xfraction out of range, reset to maximum");
			}
			else {
				xfraction = (float)fraction_loc;
			}

			fraction_loc = panda_parse_double_opt(args, "yfraction",
					MAX_FRACTION,
					"fraction along the y axis at which to place the counter [0.0, 1.0]");
			if (fraction_loc < MIN_FRACTION) {
				yfraction = MIN_FRACTION;
				LOG_WARNING("yfraction out of range, reset to minimum");
			} else if (fraction_loc > MAX_FRACTION) {
				yfraction = MAX_FRACTION;
				LOG_WARNING("yfraction out of range, reset to maximum");
			}
			else {
				yfraction = (float)fraction_loc;
			}
		}
		// LOG_INFO is off by default, but I always want to output this info
		fprintf(stderr, "%ssave instruction counter %s\n", PANDA_MSG,
				PANDA_FLAG_STATUS(save_instr_count));
		if (save_instr_count) {
			fprintf(stderr, "%sxfraction = %f\n", PANDA_MSG, xfraction);
			fprintf(stderr, "%syfraction = %f\n", PANDA_MSG, yfraction);
		}
	}

    panda_cb pcb;

    // In general you should always register your callbacks last, because
    // if you return false your plugin will be unloaded and there may be stale
    // pointers hanging around.
    pcb.before_block_exec = before_block_callback;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

void uninit_plugin(void *self) {
    // Save the last frame
    Error *errp;
    char fname[256] = {0};
    snprintf(fname, 255, "replay_movie_%03d.ppm", num);
    qmp_screendump(fname, &errp);
    if (save_instr_count) {
        fprintf(counterslog, "%" PRId64 "\n", total_insns);
        fclose(counterslog);
    }
    printf("Unloading replaymovie plugin.\n");
}
