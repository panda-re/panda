#!/usr/bin/env python3
# Test that OSI works for each generic qcow - Note we use subprocesses to call
# ourself to hack around the bug where that we can't support multiple panda
# objects in one script :(

import os
import subprocess
from sys import argv
from pandare.qcows import SUPPORTED_IMAGES, VM_DIR, Qcows
reverted = False

# If called as ./generic_tests.py, run each supported architecture
# if called as ./generic_tests.py [arch] test that arch

def driver(): # Drive all tests
    results = {}
    seen_urls = set() # use URLs to deduplicate items
    for gen_name, data in SUPPORTED_IMAGES.items():
        print(f"Testing generic={gen_name}...")
        if data.url in seen_urls: # duplicate
            print("[skipping duplicate]")
            continue
        seen_urls.add(data.url)
        assert(data.snapshot == 'root'), "Non-standard snapshot name"

        with open(f"/tmp/{gen_name}.stdout", "w") as out:
            with open(f"/tmp/{gen_name}.stderr", "w") as oute:
                try:
                    subprocess.run(["python", "./generic_tests.py", gen_name], stderr=oute, stdout=out)
                except subprocess.CalledProcessError:
                    print(f"\tFAILURE - check /tmp/{gen_name}.std{{out,err}} for details")

        # Read stdout file for our CLI: PASS / Python: PASS message
        # if both aren't there, print what we have and FAILURE
        with open(f"/tmp/{gen_name}.stdout", "r") as out:
            lines = out.readlines()
            c_pass = [x for x in lines if 'CLI: PASS' in x]
            p_pass = [x for x in lines if 'Python: PASS' in x]
            if len(c_pass) == 1 and len(p_pass) == 1:
                print("PASS")
                results[gen_name] = True
            else:
                with open(f"/tmp/{gen_name}.stderr", "r") as err:
                    print("failure:", lines, err.read())
                results[gen_name] = False

    for gen_name, success in results.items():
        print(gen_name, "Pass" if success else "FAIL")

def runner(generic_name):
    '''
    Try to run a single generic image
    First run via CLI - load root snapshot, run a command and quit - check command output
    Then test via python to see if OSI works
    '''
    from pandare import Panda, blocking
    data = SUPPORTED_IMAGES[generic_name]
    qcow_path = Qcows.get_qcow(generic_name)

    # Check 1 - can we load with CLI
    assert(os.path.isfile(qcow_path)), f"Can't find qcow for {generic_name}"
    # Start panda with a 10s timeout and background it
    # then sleep 1s, connect to the serial port via telnet, run a command and capture output
    # then shutdown panda via monitor and check if output matches expected value
    cmd = f"timeout 10s    panda-system-{data.arch} -loadvm {data.snapshot} -m {data.default_mem}  {qcow_path} \
            {data.extra_args} -serial telnet:localhost:4321,server,nowait \
            -monitor unix:/tmp/panda.monitor,server,nowait & \
            sleep 2; RES=$(echo 'whoami' | nc localhost 4321) && (echo 'q' | nc -q1 -U /tmp/panda.monitor  || true) && echo \"RESULT: $RES\" | grep -q 'root'"
    print(cmd)
    p = subprocess.run(cmd, shell=True)
    if p.returncode != 0:
        raise RuntimeError("Failed to run CLI panda")
    print("\tCLI: PASS")

    # Check 2 - load with python and test OSI profile if arch in osi_supported
    panda = Panda(generic=generic_name)
    assert(os.path.isdir(panda.build_dir)), f"Missing build dir {panda.build_dir}"
    osi_supported = ['i386', 'x86_64', 'arm']

    if panda.arch in osi_supported:
        print(f"{panda.arch} supports OSI - loading")
        panda.load_plugin("osi")
        panda.load_plugin("osi_linux")

    seen = set()
    @panda.cb_asid_changed # Grab proc names at each asid change - AFTER we're at root (can't do OSI during boot, but asid will chage)
    def new_asid(cpu, oldasid, newasid):
        global reverted
        print("ASID", reverted, panda.arch)
        if reverted and panda.arch in osi_supported: # If osi unsupported, bail
            proc = panda.plugins['osi'].get_current_process(cpu) 
            name = panda.ffi.string(proc.name)
            if name not in seen:
                seen.add(name)
        return 0

    @blocking
    def start():
        panda.revert_sync("root")
        global reverted
        reverted = True

        r = panda.run_serial_cmd("grep --color=no root /etc/passwd")
        assert("root:x" in r), "Failed to run grep command"
        panda.end_analysis()

    panda.queue_async(start)
    panda.run()

    if panda.arch in osi_supported:
        assert(len(seen)), "Didn't observe any processes"
        assert(b'grep' in seen), "Didn't see grep process run"

    print("\tPython: PASS" + (" (no OSI)" if panda.arch not in osi_supported else ""))


if __name__ == '__main__':
    if len(argv) == 1:
        driver()
    else:
        runner(argv[1])
