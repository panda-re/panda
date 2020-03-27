#ifndef __IOCTL_OPT_JSON_H__
#define __IOCTL_OPT_JSON_H__

#include <iostream>
#include <iomanip>
#include <fstream>

#include "ioctl.h"

// Write single ioctl entry to JSON
void log_line_json(
    const char* json_fn,
    std::ofstream &out_log_file,
    ioctl_t* ioctl,
    target_pid_t pid,
    std::string name,
    bool is_request
) {

    // TODO: Requires osi_linux
    out_log_file
        << std::hex << std::setfill('0') << "{ "
        << "\"proc_pid\": \"" << pid << "\", "
        << "\"proc_name\": \"" << name << "\", "
        << "\"file_name\": \"" << ioctl->file_name << "\", ";

    // Write log line, hacky JSON
    if (is_request) {
        out_log_file
            << "\"data_flow\": \"req\", ";
    } else {
        out_log_file
            << "\"data_flow\": \"res\", ";
    }

    out_log_file
        << "\"raw_cmd\": \"0x" << std::setw(hex_width) << encode_ioctl_cmd(ioctl->cmd) << "\", "
        << "\"direction\": \""  << ioctl_direction_to_str(ioctl->cmd->direction) << "\", "
        << "\"cmd_num\": \"0x" << std::setw(hex_width) << ioctl->cmd->cmd_num << "\", "
        << "\"type_num\": \"0x" << std::setw(hex_width) << ioctl->cmd->type_num << "\" ";

    if (ioctl->cmd->arg_size) {
        out_log_file
            << ", "
            << "\"guest_arg_ptr\": \"0x" << std::setw(hex_width) << ioctl->guest_arg_ptr << "\", "
            << "\"guest_arg_size\": \"0x" << std::setw(hex_width) << ioctl->cmd->arg_size << "\" ";

        for (int i = 0; i < ioctl->cmd->arg_size; ++i) {
            out_log_file
                << "0x" << std::hex << std::setfill('0') << std::setw(2)
                << ioctl->guest_arg_buf[i] << " ";
        }

        out_log_file
            << "}";

    } else {
        out_log_file
            << "}";
    }

    // Validate write
    if (!out_log_file.good()) {
        std::cerr << "Error writing to " << json_fn << std::endl;
        return;
    }
}

// Write JSON log
void flush_json(
    const char* json_fn,
    const AllIoctlsByPid& pid_to_all_ioctls,
    const NameByPid& pid_to_name
) {

    if (!json_fn) { return; }    // Pre-condition

    std::ofstream out_log_file(json_fn);
    auto delim = ",\n";

    out_log_file << "[" << std::endl;

    printf("ioctl: dumping log for %lu processes to %s\n", pid_to_all_ioctls.size(), json_fn);
    for (auto const& pid_to_ioctls : pid_to_all_ioctls) {
    //for (auto it = pid_to_all_ioctls.begin(); it != pid_to_all_ioctls.end(); ++it) {

        auto pid = pid_to_ioctls.first;
        auto ioctl_pair_list = pid_to_ioctls.second;
        assert(pid_to_name.find(pid) != pid_to_name.end());
        auto name = pid_to_name.find(pid)->second;

        for (auto const& ioctl_pair : ioctl_pair_list) {

            log_line_json(json_fn, out_log_file, ioctl_pair.first, pid, name, true);
            out_log_file << delim;

            log_line_json(json_fn, out_log_file, ioctl_pair.second, pid, name, false);

            // TODO: fix so last does not have trailing
            //if ((&ioctl_pair != &ioctl_pair_list.back()) and
            //    (it.next() != pid_to_all_ioctls.end()) {
                //out_log_file << delim;
            //}

            out_log_file << delim;
        }
    }

    out_log_file << std::endl << "]" << std::endl;
    out_log_file.close();
}

#endif // __IOCTL_OPT_JSON_H__