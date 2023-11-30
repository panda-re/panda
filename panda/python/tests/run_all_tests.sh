#!/bin/bash
# Iterate over all Python test scripts and execute them
for test_script in /panda/panda/python/tests/*.py; do
    echo "Running $test_script..."
    python3 "$test_script"
    if [ $? -ne 0 ]; then
        echo "Test $test_script failed"
        exit 1
    fi
done
