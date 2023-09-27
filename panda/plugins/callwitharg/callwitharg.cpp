#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <unordered_set>
#include <string>
#include <memory>

#include "callwitharg.h"
#include "callstack_instr/callstack_instr.h"

extern "C" {
#include "callwitharg_int_fns.h"
	bool init_plugin(void *);
	void uninit_plugin(void *);
  PPP_PROT_REG_CB(on_call_match_str);
  PPP_PROT_REG_CB(on_call_match_num);
}

PPP_CB_BOILERPLATE(on_call_match_str);
PPP_CB_BOILERPLATE(on_call_match_num);

uint N;
bool verbose;
void on_call_with_args(CPUState *cpu, target_ulong func_pc);

// Sets of the targets we're looking for
std::unordered_set<std::string> string_targets;
std::unordered_set<target_ulong> int_targets;
void add_target_string(char* target) {
  if (verbose) {
    printf("Adding string target %s\n", target);
  }
  std::string target_s = std::string(target);
  string_targets.insert(target_s);
}

bool remove_target_string(char* target) {
  if (verbose) {
    printf("Removing string target %s\n", target);
  }
  std::string target_s = std::string(target);
  return string_targets.erase(target_s) > 0;
}

void add_target_num(target_ulong target) {
  if (verbose) {
    printf("Adding number target " TARGET_FMT_lx "\n", target);
  }
  int_targets.insert(target);
}

bool remove_target_num(target_ulong target) {
  if (verbose) {
    printf("Removing number target " TARGET_FMT_lx "\n", target);
  }
  return int_targets.erase(target) > 0;
}

bool init_plugin(void *self) {
  std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(
    panda_get_args("callwitharg"), panda_free_args);

  const char * target_str_const = panda_parse_string_opt(args.get(), "targets", "", "Hex values and strings to search for in arguments. Seperated by _s");

  if (strlen(target_str_const) > 0) {
    char *target_str = strdup(target_str_const); // Make a mutable copy

    // First split string on _'s, then iterate over each target and
    // add to the appropriate set
    char* target = strtok(target_str, "_");
    while (target != NULL) {
      // If target is a hex value, add it to the int_targets set
      if (target[0] == '0' && target[1] == 'x') {
        target_ulong target_num = strtoul(target, NULL, 16);
        add_target_num(target_num);
      } else {
        // Otherwise, add it to the string_targets set
        add_target_string(target);
      }
      target = strtok(NULL, "_");
    }
  }

  verbose = panda_parse_bool_opt(args.get(), "verbose", "enable verbose output");
  N = (uint)panda_parse_uint32_opt(args.get(), "N", 2, "Maximum number of arguments to examine on each call");

#if defined(TARGET_ARM) || defined(TARGET_MIPS) || defined(TARGET_X86_64)
	PPP_REG_CB("callstack_instr", on_call, on_call_with_args);
	return true;
#else
  printf("ERROR: Unsupported architecture for targetcmp\n");
  return false;
#endif
}

typedef struct {
  target_ulong *args;
  size_t count;
} Arguments;

bool _get_args_for_arch(CPUArchState *env, Arguments *args, int N) {
#ifdef TARGET_ARM
  for (int i = 0; i < N; ++i) {
    args->args[i] = env->regs[i];
  }
#elif defined(TARGET_MIPS)
  for (int i = 0; i < N; ++i) {
    args->args[i] = env->active_tc.gpr[4 + i];
  }
#elif defined(TARGET_X86_64)
  // Handle SysV ABI here, or make it a parameter to the function
  const int regs[] = {7, 6};  // RDI, RSI
  for (int i = 0; i < N; ++i) {
    args->args[i] = env->regs[regs[i]];
  }
#else
  return false; // Error
#endif

  return true; // All good
}

bool get_n_args(CPUState *cpu, Arguments *args, uint n) {
  CPUArchState *UNUSED(env) = (CPUArchState *)cpu->env_ptr;
  args->args = (target_ulong*)malloc(n * sizeof(target_ulong));
  args->count = N;
  return _get_args_for_arch(env, args, N);
}


// Called on every guest function call
void on_call_with_args(CPUState *cpu, target_ulong func_pc) {

  // What kind of target do we have?
  bool have_strings = string_targets.size() > 0;
  bool have_nums = int_targets.size() > 0;

  size_t max_len = 0;

  if (!have_strings && !have_nums) return;

  if (have_strings) {
    for (auto it = string_targets.begin(); it != string_targets.end(); ++it) {
      if (it->length() > max_len) {
        max_len = it->length();
      }
    }
  }

  Arguments args;
  if (!get_n_args(cpu, &args, N)) {
    // Error!
    printf("Failed to get %d args\n", N);
    return;
  }

  // Check the up to N arguments for matches
  for (uint i=0; i < N; i++) {
    // Is argument a string or a number?
    if (have_nums) {
      if (int_targets.find(args.args[i]) != int_targets.end()) {
        if (verbose) {
          printf("Found target " TARGET_FMT_lx " in call at " TARGET_FMT_lx ". In argument %d\n", args.args[i], func_pc, i);
        }
        PPP_RUN_CB(on_call_match_num, cpu, func_pc, args.args, i, N);
      }
    }

    if (have_strings) {
      // Read string from guest memory
      char str[max_len+1];
      if (panda_virtual_memory_read(cpu, args.args[i], (uint8_t*)str, max_len) != 0) {
        // Read failed
        continue;
      }
      str[max_len] = '\0';

      // Check if string is in set of targets
      std::string str_s = std::string(str);
      if (string_targets.find(str_s) != string_targets.end()) {
        if (verbose) {
          printf("Found string target %s in call at " TARGET_FMT_lx ". In argument %d\n", str, func_pc, i);
        }
        PPP_RUN_CB(on_call_match_str, cpu, func_pc, args.args, str, i, N);
      }
    }
  }
  free(args.args);
}

void uninit_plugin(void *self) {
}
