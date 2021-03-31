#include "panda/plugin.h"
// OSI
#include "osi/osi_types.h"
#include "osi/osi_ext.h"

// you can restrict the output of this plugin to a particular process by specifying the process parameter, e.g.
// -panda lighthouse_coverage:process=lsass.exe
// you can restrict the output of this plugin to a particular dll by specifying both process and dll parameters, e.g.
// -panda lighthouse_coverage:process=lsass.exe,dll=ntdll.dll


// function prototypes
void after_block_exec(CPUState *cpuState, TranslationBlock *translationBlock, uint8_t exitCode) ;
void uninit_plugin(void *self) ;
bool init_plugin(void *self) ;

FILE       * outputFile = 0;							// pointer to output file...
const char * processName = 0;							// pointer to process name to restrict output to
const char * dllName = 0;							// pointer to dll name to restrict output to

void after_block_exec(CPUState *cpuState, TranslationBlock *translationBlock, uint8_t exitCode) 
{	// this function gets called right after every basic block is executed
	if (exitCode > TB_EXIT_IDX1)						// If exitCode > TB_EXIT_IDX1, then the block exited early.
		return;
	if (panda_in_kernel(first_cpu) == 0)				// I'm not interested in kernel modules
		{
		OsiProc * process = get_current_process(cpuState);		// get a reference to the process this TranslationBlock belongs to
	        if (process) 										// Make sure 'process' is a thing
			{
			GArray * mappings = get_mappings(cpuState, process);			// we need this for getting the base address of the process or DLL
			if (mappings != NULL)										// make sure 'mappings' is a thing
				{
				OsiModule * module = NULL;
				// now we have 3 cases. All processes; only a particular process; or a particular DLL for a particular process
				if (0 == strcmp("",processName))							// This means all processes; but we ignore the DLLs
					{
					// find base address
					module = &g_array_index(mappings, OsiModule, 0);											// the first module mapped is the main executable itself
					if ((translationBlock->pc >= module->base) && (translationBlock->pc <= (module->base + module->size)))			// make sure we are in the address space for the module
						{
						fprintf(outputFile,"\n%s+%#018"PRIx64"", module->name, (long unsigned int)((translationBlock->pc)-(module->base)));		// print out info
						}
					}
				else if(0 == strcmp("",dllName))							// Only a particular process; but not a DLL
					{
					module = &g_array_index(mappings, OsiModule, 0);
					if (0 == strcasecmp(module->name,processName))				// first check that the first module name matches the desired process name
						{
						if ((translationBlock->pc >= module->base) && (translationBlock->pc <= (module->base + module->size)))			// make sure we are in the address space for the module
							{
							fprintf(outputFile,"\n%s+%#018"PRIx64"", module->name, (long unsigned int)((translationBlock->pc)-(module->base)));		// print out info
							}
						}
					}
				else													// Only a particular DLL for a particular process
					{
					module = &g_array_index(mappings, OsiModule, 0);
					if (0 == strcasecmp(module->name,processName))					// check for the particular process
						{
						for (int i = 1; i < mappings->len; i++)							// we have to iterate though the list of loaded modules to find the desired DLL
							{
							module = &g_array_index(mappings, OsiModule, i);
							if (0 == strcasecmp(module->name,dllName))					// found the module with the right name
								{
								if ((translationBlock->pc >= module->base) && (translationBlock->pc <= (module->base + module->size)))			// make sure we are in the dll
									{
									fprintf(outputFile,"\n%s+%#018"PRIx64"", module->name, (long unsigned int)((translationBlock->pc)-(module->base)));		// print out info
									}
								break; // done iterating through for loop
								}
							}
						}
					}
				g_array_free(mappings, true);							// always free unused resources					
				}
			else
				{
				printf("Whoa! g_array_index went wrong\n");
				}
			}
		else
			{
			printf("Whoa! get_current_process went wrong\n");
			}
		free_osiproc(process);							// always free unused resources
		} 
	return;
};

bool init_plugin(void *self) 
{
	panda_require("osi");										// ensure that OSI is loaded
	assert(init_osi_api());										// ensure that OSI is loaded
	outputFile = fopen("lighthouse.out", "w");						// open output file
	panda_cb pcb = { .after_block_exec = after_block_exec };
	panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);		// register the callback function above
	panda_arg_list *args = panda_get_args("lighthouse_coverage");		// Get Plugin Arguments
	processName = panda_parse_string(args, "process", "");				// get process name to restrict to, or default to ""
	dllName = panda_parse_string(args, "dll", "");					// get dll name to restrict to, or default to ""
	return true;
};

void uninit_plugin(void *self) 
{ 
	fclose(outputFile);						// close output file
};
