#!/bin/bash

# Define the list of test scripts to run
declare -a tests=("dyn_hooks" "copy_test" "file_fake" "file_hook" "generic_tests" "monitor_cmds" "multi_proc_cbs" "sleep_in_cb" "syscalls" "record_no_snap" "sig_suppress")

# Base directory for test scripts
TEST_DIR="/panda/panda/python/tests"

# Iterate over the test scripts array
for test_script in "${tests[@]}"; do
    # Construct the full path to the script
    full_script_path="$TEST_DIR/${test_script}.py"

    echo "Running $full_script_path..."
    python3 "$full_script_path"
    
    # Check the exit status of the script
    if [ $? -ne 0 ]; then
        echo "Test $full_script_path failed"
        exit 1
    fi
done
