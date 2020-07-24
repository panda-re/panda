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
        result = self.run_monitor_cmd("loadvm {}".format(snapshot_name))
        if result.startswith("Length mismatch"):
            raise RuntimeError("QEMU machine's RAM size doesn't match snapshot RAM size!")
        return result

    @blocking
    def delvm_sync(self, snapshot_name):
        self.run_monitor_cmd("delvm {}".format(snapshot_name))

    @blocking
    def copy_to_guest(self, copy_directory, iso_name=None):
        if not iso_name: iso_name = copy_directory + '.iso'
        progress("Creating ISO {}...".format(iso_name))

        make_iso(copy_directory, iso_name)

        copy_directory = path.split(copy_directory)[-1] # Get dirname

        # 1) we insert the CD drive TODO: the cd-drive name should be a config option, see the values in qcow.py
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
    def record_cmd(self, guest_command, copy_directory=None, iso_name=None, setup_command=None, recording_name="recording", snap_name="root", ignore_errors=False):
        '''
        Take a recording as follows:
            0) Revert to the specified snapshot name if one is set. By default 'root'. Set to `None` if you have already set up the guest and are ready to record with no revert
            1) Create an ISO of files that need to be copied into the guest if copy_directory is specified. Copy them in
            2) Run the setup_command in the guest, if provided
            3) Type the command you wish to record but do not press enter to begin execution. This avoids the recording capturing the command being typed
            4) Begin the recording (name controlled by recording_name)
            5) Press enter in the guest to begin the command. Wait until it finishes.
            6) End the recording
        '''
        # 0) Revert to the specified snapshot
        if snap_name is not None:
            self.revert_sync(snap_name) # Can't use self.revert because that would would run async and we'd keep going before the revert happens

	# 1) Make copy_directory into an iso and copy it into the guest - It will end up at the exact same path
        if copy_directory: # If there's a directory, build an ISO and put it in the cddrive
            # Make iso
            self.copy_to_guest(copy_directory, iso_name)

	# 2) Run setup_command, if provided before we start the recording (good place to CD or install, etc)
        if setup_command:
            print(f"Running setup command {setup_command}")
            r = self.run_serial_cmd(setup_command)
            print(f"Setup command results: {r}")

        # 3) type commmand (note we type command, start recording, finish command)
        self.type_serial_cmd(guest_command)

        # 4) start recording
        self.run_monitor_cmd("begin_record {}".format(recording_name))

        # 5) finish command
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

        # 6) End recording
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

    @blocking
    def interact(self, confirm_quit=True):
        '''
        Expose console interactively until user types pandaquit
        Must be run in blocking thread.

        TODO: This should probably repace self.serial_console with something
        that directly renders output to the user. Then we don't have to handle
        buffering and other problems. But we will need to re-enable the serial_console
        interface after this returns
        '''
        print("PANDA: entering interactive mode. Type pandaquit to exit")
        prompt = self.expect_prompt.decode("utf8") if self.expect_prompt  else "$ "
        if not prompt.endswith(" "): prompt += " "
        while True:
            cmd = input(prompt) # TODO: Strip all control characters - Ctrl-L breaks things
            if cmd.strip() == 'pandaquit':
                if confirm_quit:
                    q = input("PANDA: Quitting interactive mode. Are you sure? (y/n) ")
                    if len(q) and q.lower()[0] == 'y':
                        break
                    else:
                        continue
                else: # No confirm - just break
                    break
            r = self.run_serial_cmd(cmd) # XXX: may timeout
            print(r)

    @blocking
    def do_panda_finish(self):
        '''
        Call panda_finish. Note this isn't really blocking - the
        guest should have exited by now, but queue this after
        (blocking) shutdown commands in our internal async queue
        so it must also be labeled as blocking.
        '''
#        assert (not self.running.is_set()), "Can't finish while still running"
        self.panda_finish()
