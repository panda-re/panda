import wget
import shutil
from pathlib import Path

from pandare import blocking, Panda

BIN_NAME = "sig_logger"
SIG_LOG = "/tmp/sig_log.txt"
PROG_DIR = "sig"
HOST_PROG_DIR = Path(__file__).parent.absolute().joinpath(PROG_DIR)
HOST_PROG_PATH = HOST_PROG_DIR.joinpath(BIN_NAME)

@blocking
def prepare_plugins():

    # Apply signal supression by process, for the 3 signals we're about to send
    bin_name_str = f"{BIN_NAME}".encode('ascii')
    panda.plugins['signal'].block_sig_by_proc(2, bin_name_str)
    panda.plugins['signal'].block_sig_by_proc(11, bin_name_str)
    panda.plugins['signal'].block_sig_by_proc(6, bin_name_str)

@blocking
def run_in_guest():

    # Setup write capture, mirrors files create to hyper visor
    panda.revert_sync("root")
    panda.copy_to_guest(str(HOST_PROG_DIR))

    run_cmds = [

        # Start the test program, give it a sec to register handlers
        f"cd ./{PROG_DIR}",
        f"./{BIN_NAME} &",
        f"sleep 1",

        # SIGINT
        f"kill -s 2 $(ps aux | grep \'[{str(BIN_NAME)[0]}]{str(BIN_NAME)[1:]}\' | awk \'{{print $2}}\')",

        # SIGSEGV
        f"kill -s 11 $(ps aux | grep \'[{str(BIN_NAME)[0]}]{str(BIN_NAME)[1:]}\' | awk \'{{print $2}}\')",

        # SIGABRT
        f"kill -s 6 $(ps aux | grep \'[{str(BIN_NAME)[0]}]{str(BIN_NAME)[1:]}\' | awk \'{{print $2}}\')",
    ]

    for cmd in run_cmds:
        print(panda.run_serial_cmd(cmd, no_timeout=True))

    log = panda.run_serial_cmd(f"cat {SIG_LOG}", no_timeout=True)

    # Signals successfully supressed (via swap to SIGWINCH)
    lines = log.splitlines()
    for l in lines:
        print(f"LOG Line: \'{l}\'")

        # Negative test
        assert("SIGABRT" not in l)
        assert("SIGSEGV" not in l)
        assert("SIGINT" not in l)

        # Postive test
        assert("SIGWINCH" in l)

    print("\nTEST OK! Signals successfully suppressed\n")
    panda.end_analysis()

if __name__ == "__main__":

    #host_build_test_progs()
    assert(HOST_PROG_PATH.is_file())

    panda = Panda(
        generic = "x86_64_ubuntu_1804",
        extra_args = "-nographic -pandalog test_sig_suppress.plog",
        expect_prompt = rb"root@ubuntu:.*",
        mem = "1G"
    )

    panda.queue_async(prepare_plugins)
    panda.queue_async(run_in_guest)
    panda.run()
