from datetime import datetime

import yara

from pathlib import Path

from pandare import Panda, PyPlugin

ARCH = "x86_64"


class YaraPlugin(PyPlugin):
    def __init__(self, panda):
        super().__init__(panda)

        self._panda = panda

        self._process_name: str = self.get_arg("process_name")
        self._matcher = self.load_rules(self.get_arg("rules_path"))
        self._output_path: Path = self.get_arg("output_path")

        self._addr_current_buffer = None
        self._current_buffer_size = 0
        panda.cb_virt_mem_after_write(self.check_memory)

    def check_memory(self, env, pc, addr_buffer, size_buffer, buffer) -> None:
        """
        Match buffers written to memory against YARA rules.

        :param env: The current state during the execution.
        :param pc: The current program counter.
        :param addr_buffer: The address where data was written to.
        :param size_buffer: The size of the written data.
        :param buffer: The written data.

        We first check that we are looking at the relevant process.

        Buffers are often written to in chunks (e.g. an 80 byte buffer might be written in 10 8 byte writes).
        To make sure we are checking the full buffer, and not only a single write,
        we keep track of the start address and size of each buffer.
        Only when data is written to an address that does not match
        the current buffer address + the size (i.e. the end of the current buffer),
        do we check the current buffer against a YARA rule.

        As buffer is checked when a next buffer is written, this approach will miss the last buffer.

        When a buffer matches a YARA rule, we write it to a file for later analysis.
        """
        if self._panda.get_process_name(env) != self._process_name:
            return

        if self._addr_current_buffer is None:
            self._addr_current_buffer = addr_buffer

        elif self._addr_current_buffer + self._current_buffer_size != addr_buffer and self._current_buffer_size > 0:
            buffer = panda.virtual_memory_read(
                env,
                self._addr_current_buffer,
                self._current_buffer_size,
            )

            matches = self._matcher.match(data=buffer)
            for match in matches:
                print(f"0x{self._addr_current_buffer:x}: {match.rule} ({self._current_buffer_size})")
                date_string = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
                match_file_name = (
                    f"{date_string}"
                    f"-{match.rule}"
                    f"-0x{pc}"
                    f"-0x{self._addr_current_buffer}"
                    f"-{self._process_name}.dat"
                )
                output_path = self._output_path.joinpath(match_file_name)
                with output_path.open("wb") as h_output:
                    h_output.write(buffer)

            self._addr_current_buffer = addr_buffer
            self._current_buffer_size = 0

        self._current_buffer_size += size_buffer

    @staticmethod
    def load_rules(rules_path: Path) -> yara.Rules:
        """Read and compile YARA rules from a given directory."""
        return yara.compile(
            filepaths={rule_file.name: rule_file.as_posix() for rule_file in rules_path.rglob("*.yara")}
        )


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
    directory_rules = Path("/data/rules/")
    directory_output = Path("/data/matches/")

    binary = "decrypt"
    path_binary = directory_binaries.joinpath(binary)
    path_recording = directory_recordings.joinpath(f"{binary}_{ARCH}")

    panda = Panda(generic=ARCH)

    if panda.recording_exists(str(path_recording)):
        print("Running the plugin")

        panda.pyplugins.load(
            YaraPlugin,
            {
                "process_name": binary,
                "rules_path": directory_rules,
                "output_path": directory_output,
            },
        )

        panda.enable_memcb()
        panda.run_replay(str(path_recording))

    else:
        print("Taking recording")
        panda.queue_blocking(lambda: take_recording(panda, path_recording, path_binary))
        panda.run()
