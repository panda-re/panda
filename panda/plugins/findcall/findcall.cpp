#include "panda/plugin.h"
#include "panda/plugin_plugin.h"
#include <fstream>
#include <thread>
#include <atomic>
#include <iostream>
#include <filesystem>
#include <sys/types.h>
#include <set>
#include <map>

#include "callstack_instr/callstack_instr.h"
#include "callwitharg/callwitharg.h"
#include "osi/osi_types.h"

extern "C" {
//#include "callwitharg/callwitharg_int_fns.h"
#include "callwitharg/callwitharg_ext.h"
#include "osi/osi_ext.h"
	bool init_plugin(void *);
	void uninit_plugin(void *);
}

//size_t target_str_len;
//char *target_str;
std::ofstream outfile;

// We want to store a mapping from unique strigs -> set of (module+offset (as a tuple))
std::map<std::string, std::set<std::tuple<std::string, target_ulong>>> matches;

// Also we store unique strings -> absolute addresses
std::map<std::string, std::set<target_ulong>> matches_abs;

void on_match(CPUState* cpu, target_ulong func_addr, target_ulong *args, char* value, uint matching_idx, uint args_read) {
  assert(args_read >= 1);

  // A match happend! Use OSI to get our current module+offst
  OsiProc *current = get_current_process(cpu);

  OsiModule *m = get_mapping_by_addr(cpu, current, func_addr);
  if (m) {
      // If matches doesn't have a key for this string, add it
      if (matches.find(value) == matches.end()) {
        matches[value] = std::set<std::tuple<std::string, target_ulong>>();
      }

      if (matches_abs.find(value) == matches_abs.end()) {
        matches_abs[value] = std::set<target_ulong>();
      }

      // Now check the matches[value] set for this module+offset tuple - if it's not there, add it
      std::tuple<std::string, target_ulong> t(m->name, func_addr - m->base);
      if (matches[value].find(t) == matches[value].end()) {
        matches[value].insert(t);
        printf("Match of %s at func_addr " TARGET_FMT_lx " which is in module %s + " TARGET_FMT_lx "\n", value, func_addr, m->name, func_addr - m->base);
      }

      if (matches_abs[value].find(func_addr) == matches_abs[value].end()) {
        matches_abs[value].insert(func_addr);
        printf("Match of %s at func_addr " TARGET_FMT_lx "\n", value, func_addr);
      }

      // cleanup
      free_osimodule(m);
  }else {
    printf("Match of %s at unknown\n", value);
  }
}

// logfile default is cwd/findcall.txt
std::filesystem::path logfile = std::filesystem::current_path() / "findcall.txt";

bool init_plugin(void *self) {
  init_callwitharg_api();
  init_osi_api();

  std::unique_ptr<panda_arg_list, void(*)(panda_arg_list*)> args(
    panda_get_args("findcall"), panda_free_args);

  const char* logfile_arg = panda_parse_string_opt(args.get(), "output_file",
      NULL, "Output file to record compared values into");
  if (logfile_arg) logfile = std::string(logfile_arg);

  /*
  target_str = strdup(panda_parse_string_req(args.get(), "target_str", "String to match"));
  target_str_len = strlen(target_str);

  if (target_str_len <= 0) {
    printf("targetcmp error: invalid target_str argument\n");
    return false;
  }
  */

#if defined(TARGET_ARM) || defined(TARGET_MIPS) || defined(TARGET_X86_64)
  outfile.open(logfile.string(), std::ios_base::out | std::ios_base::trunc); // Empty file to start

  // Tell callwitharg to call on_match when it finds a match of our string
  //add_target_string(target_str);

  // Register on_call_match with callwitharg's on_call_match_str PPP callback
  PPP_REG_CB("callwitharg", on_call_match_str, on_match);
	return true;
#endif
  printf("ERROR: Unsupported architecture for targetcmp\n");
  return false;
}

void uninit_plugin(void *self) {
  // Find all unique module+offset values in matches, then check if all keys ever have each value - if so print
  std::map<std::tuple<std::string, target_ulong>, std::set<std::string>> modoff_to_keys;
  for (auto const& [key, val] : matches) {
    for (auto const& [mod, off] : val) {
      modoff_to_keys[std::make_tuple(mod, off)].insert(key);
    }
  }
  // Now we have a map from module+offset to set of keys that have that module+offset - print all that have all keys
  for (auto const& [modoff, keys] : modoff_to_keys) {
    if (keys.size() == matches.size()) {

      // Write module, offset to outfile
      outfile << std::get<0>(modoff) << "," << std::get<1>(modoff) << std::endl;

      // Print the common module+offset then the two keys
      printf("%s + " TARGET_FMT_lx "\n", std::get<0>(modoff).c_str(), std::get<1>(modoff));
      for (auto const& key : keys) {
        printf("  %s\n", key.c_str());
      }
    }
  }

  // Now write down all absolute addresses that are in every key
  std::map<target_ulong, std::set<std::string>> abs_to_keys;
  for (auto const& [key, val] : matches_abs) {
    for (auto const& abs : val) {
      abs_to_keys[abs].insert(key);
    }
  }
  // Now we have a map from absolute address to set of keys that have that absolute address - print all that have all keys
  for (auto const& [abs, keys] : abs_to_keys) {
    if (keys.size() == matches_abs.size()) {

      // Write absolute address to outfile: just raw address
      outfile << abs << std::endl;

      // Print the common absolute address then the two keys
      printf(TARGET_FMT_lx "\n", abs);
      for (auto const& key : keys) {
        printf("  %s\n", key.c_str());
      }
    }
  }

  if (outfile.is_open()) {
    outfile.close();
  }

}
