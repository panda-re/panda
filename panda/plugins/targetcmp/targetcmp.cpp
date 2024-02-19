#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
#include <filesystem>
#include <sys/types.h>
#include <set>

#include "callstack_instr/callstack_instr.h"
#include "callwitharg/callwitharg.h" // Unnecessary?

extern "C" {

#include "targetcmp_ppp.h"
#include "callwitharg/callwitharg_ext.h"

  bool add_target(const char* target);
  bool remove_target(const char* target);
  void reset_targets(void);

	bool init_plugin(void *);
	void uninit_plugin(void *);
  PPP_PROT_REG_CB(on_tcm);
}

PPP_CB_BOILERPLATE(on_tcm)


std::ofstream outfile;
bool verbose = false;
//size_t target_str_len;

// To support multiple concurrent targets, we need to track the strings we're tracking
std::vector<std::string> targets;

// We track the last QUEUE_SIZE addresses we've checked to avoid rereading guest pointers
//#define QUEUE_SIZE 100
// We need a queue for each entry in targets
//std::vector<std::atomic<size_t>> queue_idx;
//std::vector<std::atomic<target_ulong*>> queue;

bool add_target(const char* target) {
  // Check if we already have this target
  for (size_t i = 0; i < targets.size(); i++) {
    if (targets[i] == target) {
      return false;
    }
  }
  // If not, add it to our list
  targets.push_back(target);
  // And create a queue for it
  //queue_idx.push_back(0);
  //queue.push_back(new std::atomic<target_ulong>[QUEUE_SIZE]);

  // And request that callwitharg track it
  add_target_string((char*)target);

  return true;
}

bool remove_target(const char* target) {
  // Check if we have this target
  for (size_t i = 0; i < targets.size(); i++) {
    if (targets[i] == target) {
      // If so, remove it
      targets.erase(targets.begin() + i);

      // And delete its queue
      //delete[] queue[i];
      //queue.erase(queue.begin() + i);
      //queue_idx.erase(queue_idx.begin() + i);

      return true;
    }
  }

  return false;
}

void reset_targets(void) {
  targets.clear();
}

// C++ set for storing unique string matche that we've logged as key=value
std::set<std::string> matches;

void record_match(CPUState* cpu, char *known_value, char *str) {
  if (strlen(str) == 0) return;

  for (int i = 0; i < strlen(str); i++) {
    if (!isprint(str[i])) {
      return;
    }
  }

  // If it's a self-comparison, ignore
  if (strcmp(known_value, str) == 0 && strlen(known_value) == strlen(str)) {
    return;
  }

  // We want to create a key=value string to log
  std::string s(known_value);
  s.append("=");
  s.append(str);

  if (matches.find(s) == matches.end()) {
    // New match - we want to report this!

    // Verbose: log to stdout
    if (verbose) {
      printf("[TargetCMP of %s] %s\n", known_value, str);
    }

    // Log file: write down
    if (outfile.is_open()) {
      outfile << s << std::endl;
    }

    // PPP output:
    PPP_RUN_CB(on_tcm, cpu, known_value, str);


    // Update matches
    matches.insert(s);

  }
}

void on_match(CPUState* cpu, target_ulong func_addr, target_ulong *args, char* value, uint matching_idx, uint args_read) {
  // We expect 2 args, if matching_idx is 0, arg1 is our target pointer, otherwise arg0
  assert(args_read >= 2);
  target_ulong target_ptr = args[matching_idx == 0 ? 1 : 0]; // If we matched arg0, we want arg1 and vice versa

  size_t short_len = strlen(value);
  size_t full_len = 4*short_len;
  char* other_arg = (char*)malloc(full_len + 1);

  // Try to read the target string from memory
  if (panda_virtual_memory_read(cpu, target_ptr, (uint8_t*)other_arg, full_len) == 0) {
    other_arg[full_len] = '\0'; // Ensure null termination
  } else if (panda_virtual_memory_read(cpu, target_ptr, (uint8_t*)other_arg, short_len) == 0) {
    // Recovered short string - move null terminator early
    other_arg[short_len] = '\0'; // Ensure null termination
  } else {
    // Failed to read even the short string - bail
    free(other_arg);
    return;
  }

  record_match(cpu, value, other_arg);
  free(other_arg);
}

// logfile default is cwd/targetcmp.txt
std::filesystem::path logfile = std::filesystem::current_path() / "targetcmp.txt";

bool init_plugin(void *self) {
#if !defined(TARGET_ARM) && !defined(TARGET_MIPS) && !defined(TARGET_X86_64)
  printf("ERROR: Unsupported architecture for targetcmp\n");
  return false;
#endif

  if (!init_callwitharg_api()) {
    printf("[targetcmp] Fatal error: unable to initialize callwitharg - is it loaded?\n");
    return false;
  }

  std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(
    panda_get_args("targetcmp"), panda_free_args);

  // Optional arguments: target_strings, output_file, verbose
  char *target_str = strdup(panda_parse_string_opt(args.get(), "target_strings",
      "String(s) to match. Colon seperated", ""));


  const char* logfile_arg = panda_parse_string_opt(args.get(), "output_file",
      NULL, "Output file to record compared values into");
  if (logfile_arg) {
    // Open file for writing, delete anything there.
    outfile.open(logfile.string(), std::ios_base::out | std::ios_base::trunc);
  }

  verbose = panda_parse_bool_opt(args.get(), "verbose", "enable verbose output on every match");

  // If we have a target_str, split it on commas and add each target
  if (strlen(target_str) > 0) {
    char* target = strtok(target_str, ":");
    while (target != NULL) {
      add_target(target);
      target = strtok(NULL, ":");
    }
  }

  // Register on_call_match with callwitharg's on_call_match_str PPP callback
  PPP_REG_CB("callwitharg", on_call_match_str, on_match);

  free(target_str);

	return true;

}

void uninit_plugin(void *self) {
  if (outfile.is_open()) {
    outfile.close();
  }
}