# XXX: Do not call any of the following from the main thread- they depend on the CPU loop running
from .decorators import blocking
from .utils import progress, make_iso, debug
from shlex import quote as shlex_quote
from os import path

class blocking_mixins():
    @blocking
    def stop_run(self):
        '''
        From a blocking thread, request vl.c loop to break. Returns control flow in main thread.
        In other words, once this is called, panda.run() will finish and your main thread will continue.
        If you also want to unload plugins, use end_analysis instead

        XXX: This doesn't work in replay mode
        '''
        self.libpanda.panda_break_vl_loop_req = True

    @blocking
    def run_serial_cmd(self, cmd, no_timeout=False):
        self.running.wait() # Can only run serial when guest is running
        self.serial_console.sendline(cmd.encode("utf8"))
        if no_timeout:
            result = self.serial_console.expect(timeout=9999)
        else:
            result = self.serial_console.expect()
        return result

    @blocking
    def type_serial_cmd(self, cmd):
        #Can send message into socket without guest running (no self.running.wait())
        self.serial_console.send(cmd.encode("utf8")) # send, not sendline

    def finish_serial_cmd(self):
        result = self.serial_console.send_eol()
        result = self.serial_console.expect()
        return result

    @blocking
    def run_monitor_cmd(self, cmd):
        self.monitor_console.sendline(cmd.encode("utf8"))
        result = self.monitor_console.expect()
        return result

    @blocking
    def revert_sync(self, snapshot_name):
        self.run_monitor_cmd("loadvm {}".format(snapshot_name))

    @blocking
    def delvm_sync(self, snapshot_name):
        self.run_monitor_cmd("delvm {}".format(snapshot_name))

    @blocking
    def copy_to_guest(self, copy_directory, iso_name=None):
        if not iso_name: iso_name = copy_directory + '.iso'
        progress("Creating ISO {}...".format(iso_name))

        make_iso(copy_directory, iso_name)

        copy_directory = path.split(copy_directory)[-1] # Get dirname

        # 1) we insert the CD drive
        self.run_monitor_cmd("change ide1-cd0 \"{}\"".format(iso_name))

        # 2) run setup script
        # setup_sh: 
        #   Make sure cdrom didn't automount
        #   Make sure guest path mirrors host path
        #   if there is a setup.sh script in the directory,
        #   then run that setup.sh script first (good for scripts that need to
        #   prep guest environment before script runs)
        setup_sh = "mkdir -p {mount_dir}; while ! mount /dev/cdrom {mount_dir}; do sleep 0.3; " \
               " umount /dev/cdrom; done; {mount_dir}/setup.sh &> /dev/null || true " \
               .format(mount_dir = (shlex_quote(copy_directory)))
        progress("setup_sh = [%s] " % setup_sh)
        progress(self.run_serial_cmd(setup_sh))

    @blocking
    def record_cmd(self, guest_command, copy_directory=None, iso_name=None, recording_name="recording", ignore_errors=False):
        self.revert_sync("root") # Can't use self.revert because that would would run async and we'd keep going before the revert happens

        if copy_directory: # If there's a directory, build an ISO and put it in the cddrive
            # Make iso
            self.copy_to_guest(copy_directory, iso_name)

        # 3) type commmand (note we type command, start recording, finish command)
        self.type_serial_cmd(guest_command)

        # 3) start recording
        self.run_monitor_cmd("begin_record {}".format(recording_name))

        # 4) finish command
        result = self.finish_serial_cmd()

        if debug:
            progress("Result of `{}`:".format(guest_command))
            print("\t"+"\n\t".join(result.split("\n"))+"\n")

        if "No such file or directory" in result and not ignore_errors:
            print("Bad output running command: {}".format(result))
            raise RuntimeError("Command not found while taking recording")

        if "cannot execute binary file" in result and not ignore_errors:
            print("Bad output running command: {}".format(result))
            raise RuntimeError("Could not execute binary while taking recording")

        # 5) End recording
        self.run_monitor_cmd("end_record")

        print("Finished recording")

    @blocking
    def check_crashed(self):
        '''
        After end_analysis, check if an exn was caught in a callback.
        If so, print traceback and kill this python instance
        TODO: currently prints 2 stack frames too low (shows pypanda internals), should hide those
        '''
        if self.exception is not None:
            import traceback, os
            try:
                raise self.exception
            except:
                traceback.print_exc()
            os._exit(1) # Force process to exit now
