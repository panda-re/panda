#include "panda/plugin.h"
// OSI
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

FILE * outputFile = 0;							// pointer to output file...


int before_block_exec(CPUState *cpuState, TranslationBlock *translationBlock) 
{	// this function gets called right before every basic block is executed
	if (panda_in_kernel(first_cpu) == 0)				// I'm not interested in kernel modules
		{
		OsiProc * process = get_current_process(cpuState);		// get a reference to the process this TranslationBlock belongs to
	        if (process) 
			{
			fprintf(outputFile,"\n%s@%#018"PRIx64"", process->name, (translationBlock->pc)- (long unsigned int)0x00000);//m->base);
			free_osiproc(process);					// always free unused resources
			}
		} 
	return 0;
};

bool init_plugin(void *self) 
{
	panda_require("osi");						// ensure that OSI is loaded
	assert(init_osi_api());						// ensure that OSI is loaded
	outputFile = fopen("lighthouse.out", "w");			// open output file
	panda_cb pcb = { .before_block_exec = before_block_exec };
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);	// register the callback function above
	return true;
};

void uninit_plugin(void *self) 
{ 
	fclose(outputFile);						// close output file
};
