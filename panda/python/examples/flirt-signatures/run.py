import capstone

import flirt

from pathlib import Path

from pandare import Panda, PyPlugin

ARCH = "x86_64"


class SearchFlirtPlugin(PyPlugin):
    """
    PyPanda Plugin to search for F.L.I.R.T. signatures in process memory.

    This plugin creates an on_call callback (from the `callstack_instr` plugin)
    to check the bytes at each callee against signatures.
    """

    NO_INSTRUCTIONS_TO_PRINT = 5

    # Source: https://en.wikipedia.org/wiki/Instruction_set_architecture
    MAX_INSTRUCTION_SIZE = 15

    # This is an arbitrary value that seems large enough to always cover the 32 + n F.L.I.R.T. CRC16 bytes.
    MATCH_BYTES_TO_READ = 0x100

    def __init__(self, panda):
        super().__init__(panda)

        self._panda = panda

        self._process_name = self.get_arg("process_name")
        self._show_function_instructions = self.get_arg_bool("show_function_instructions")

        self._matcher = self.load_flirt_signatures(self.get_arg("signatures_path"))
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

        self._seen_function_addresses = set()

        # Create `on_call` callback.
        ppp_decorator = panda.ppp("callstack_instr", "on_call")
        ppp_decorator(self.on_call_search_flirt)

    def on_call_search_flirt(self, env, addr_func: int) -> None:
        """
        Checks every call inside a given process against F.L.I.R.T. signatures.

        Based on the PANDA callstack_instr plugin.

        When the callstack_instr detects a call, we read 0x100 bytes of the callee.
        We then match these bytes against the loaded signatures.

        When a match is found it is printend and if show_function_instructions is set,
        the first five instructions of the callee are also printed.

        :param env: The current state during the execution.
        :param addr_func: The address of the callee.
        """

        if addr_func in self._seen_function_addresses or self._panda.get_process_name(env) != self._process_name:
            return

        self._seen_function_addresses.add(addr_func)

        try:
            buffer = self._panda.virtual_memory_read(env, addr_func, self.MATCH_BYTES_TO_READ)
        except ValueError:
            print(f"@{hex(addr_func)}: Failed to read.")
            return

        for match in self._matcher.match(buffer):
            for function_name, _, offset in match.names:
                addr_matched_function = addr_func + offset
                print(f"@{hex(addr_matched_function)}: '{function_name}'")

                if self._show_function_instructions:
                    try:
                        buffer = self._panda.virtual_memory_read(
                            env,
                            addr_matched_function,
                            self.MAX_INSTRUCTION_SIZE * self.NO_INSTRUCTIONS_TO_PRINT,
                        )
                    except ValueError as e:
                        print(f"\tFailed to read.")
                        continue

                    instructions = list(self._md.disasm(buffer, addr_matched_function, self.NO_INSTRUCTIONS_TO_PRINT))
                    for instruction in instructions:
                        print(f"\t{hex(instruction.address)}" f"\t{instruction.mnemonic}" f"\t{instruction.op_str}")
                    print()

    @staticmethod
    def load_flirt_signatures(signatures_path: Path) -> flirt.FlirtMatcher:
        """Loads .sig F.L.I.R.T. signature files from signatures_path."""
        signatures = []
        for file_signature in signatures_path.glob("*.sig"):
            with file_signature.open("rb") as h_signature:
                data_sig = h_signature.read()
            signatures += flirt.parse_sig(data_sig)
        return flirt.compile(signatures)


def take_recording(
    panda: Panda,
    path_recording: Path,
    path_binary: Path,
) -> None:
    """
    Recording a binary.

    :param panda: An instance of a panda, giving access to the vm.
    :param path_recording: The path where the recording should be saved.
    :param path_binary: The path of the binary to run.
    """

    panda.revert_sync("root")
    panda.copy_to_guest(str(path_binary.parent), absolute_paths=True)

    command = str(path_binary)

    print(f"Testing command: '{command}'")
    command_output = panda.run_serial_cmd(command)
    print(f"Output: '{command_output}'")

    panda.record_cmd(command, recording_name=str(path_recording), snap_name=None)

    panda.end_analysis()


if __name__ == "__main__":
    # Directories inside Docker
    directory_binaries = Path("/data/binaries/")
    directory_recordings = Path("/data/recordings/")
    directory_signatures = Path("/data/signatures/")

    binary = "hello-stripped"
    path_binary = directory_binaries.joinpath(binary)
    path_recording = directory_recordings.joinpath(f"{binary}_{ARCH}")

    panda = Panda(generic=ARCH)

    if panda.recording_exists(str(path_recording)):
        print("Running the plugin")

        # Copied from https://github.com/panda-re/panda/blob/dev/panda/python/examples/experimental/callstack_isntr.py
        panda.disable_tb_chaining()
        panda.load_plugin("callstack_instr")

        panda.pyplugins.load(
            SearchFlirtPlugin,
            {
                "process_name": binary,
                "signatures_path": directory_signatures,
                "show_function_instructions": True,
            },
        )

        panda.run_replay(str(path_recording))

    else:
        print("Taking recording")
        panda.queue_blocking(lambda: take_recording(panda, path_recording, path_binary))
        panda.run()
