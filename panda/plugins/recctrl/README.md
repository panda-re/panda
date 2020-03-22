Plugin: recctrl
========================

Summary
------------------------
`recctrl` plugin adds support for a hypercall which enables the guest to signal
PANDA to start/stop recording. This is useful e.g. to automate recoding of user
sessions, or in cases where PANDA is deployed as a honeypot.
The plugin includes an utility program which can be used from the guest OS to
send hypercalls to it.

The plugin features two operation modes:

  * Toggle switch mode: The plugin will instruct PANDA to start recording
    at the first hypercall with the proper magic number, and stop recording
    at the next one.
  * Session record mode: The plugin maintains a session counter which is
    incremented or decremented based on the hypercall arguments. When the
    counter raises from 0, recording starts. When the counter falls back
    to 0, recording stops.

**Note:** The plugin has not been tested on ARM. Expect some rough edges.

Arguments
------------------------
  * `session_rec`: The plugin by default operates in toggle switch mode.
    Set `session_rec=y` to enable session record mode.
  * `nrec`: The maximum number of recordings to make. If set to a number
    greater than 0, PANDA will quit after making the defined number of
    recordings.
  * `dry`: When enabled (`dry=y`), the plugin will operate in dry-run mode.
    I.e. it will not actually record any traces. This is useful when you want
    to install and test `recctrlu` guest utility on a VM image.

Dependencies
------------------------
Depends on the `PANDA_CB_GUEST_HYPERCALL` having been implemented for the guest
architecture. See the [PANDA manual][panda-manual] for details.

APIs and Callbacks
------------------------
To make a hypercall that will be processed by `recctrl`, the following
values need to be set to the appropriate registers:

  * `magic`: Must be set to `RECCTRL_MAGIC` (see `recctrl.h`).
  * `action`: Action specific to the current operation mode.
    - `RECCTRL_ACT_TOGGLE`: Required value in toggle switch mode.
    - `RECCTRL_ACT_SESSION_OPEN`: Increment session count in session record mode.
    - `RECCTRL_ACT_SESSION_CLOSE`: Decrement session count in session record mode.
  * `rnamep`: Pointer to string to use to construct recording name in the guest
    address space. Only used when a recording starts.

If `magic` is properly set, the hypercall implemented by `recctrl` returns:

  * `RECCTRL_RET_START`: A new recording started.
  * `RECCTRL_RET_STOP`: Current recording stopped.
  * `RECCTRL_RET_NOOP`: Successful hypercall, recording status didn't change.
  * `RECCTRL_RET_ERROR`: Error processing hypercall with the specified arguments.

Example
------------------------

### Compiling and copying the guest utility
The `recctrlu` guest utility can be found in the `utils` directory.
It can be copied inside the guest VM so that specific events trigger the start
of recording. This is typically a more flexible approach compared to trying to
externally identify when recording should start.

It is recommended to compile the utility as a static binary, so it can be copied
without worrying for runtime dependencies. The following commands can be used to
compile for different platforms:

  - IA-32: `make -C utils clean all`
  - x86-64: `ARCH=x86_64 make -C utils clean all`
  - armel: `ARCH=armel make -C utils clean all`

Then the binary can be copied to the running VM. E.g. if the ssh port is
forwarded to 10022 on localhost:

```sh
# copy to user directory
scp -P 10022 utils/recctrlu panda@localhost:~

# copy to /usr/local/sbin
scp -P 10022 utils/recctrlu root@localhost:/usr/local/sbin
```

### Running the guest utility
Start your PANDA VM as usually, and append `-panda recctrl` to the command line.

```sh
panda-system-i386 -m 512 -hda ubuntu.qcow2 -device e1000,netdev=unet0 -netdev user,id=unet0,hostfwd=tcp::10022-:22 -panda recctrl
```

To toggle recording, simply run:
```sh
recctrlu toggle myrecording
```

Specifying a recording name is mandatory for both starting and stopping
recording. However, the plugin only uses the name when startring recording.

### Hooking guest utility to sshd
The `recctrlu` utility can be hooked to the linux SSH daemon in order to record
the sessions of specific users. The session record operation mode has been
developed with this application in mind. Following the instructions below,
recording will start at the first SSH connection from a set of users, and will
stop when there are no SSH connections from that set of users.

First, edit the `utils/recctrlu.sh` script and set `RECCTRL` and `USERS` to your
liking. E.g.:

```sh
RECCTRL=/usr/local/sbin/recctrl
USERS=(panda ubuntu mstamat)
```

Then, you need to copy the compiled utility and wrapper script to the guest VM:

```sh
scp -P 10022 utils/recctrlu root@localhost:/usr/local/sbin
scp -P 10022 utils/recctrlu.sh root@localhost:/usr/local/bin
```

To prevent users themselves from running the utilities, you should set
appropriate ownership and permissions. Note however that users can still
compile the utility themselves from source and run it.

```sh
sudo chown root:root /usr/local/sbin/recctrlu /usr/local/bin/recctrlu.sh
sudo chmod 700 /usr/local/sbin/recctrlu /usr/local/bin/recctrlu.sh
```

Finally, add the following line at the end of `/etc/pam.d/sshd`:

```
session    optional     pam_exec.so seteuid /usr/local/bin/recctrlu.sh
```

If furthermore you want to limit users to a single ssh session, you can set the
`maxlogins` limit to 1 in `/etc/security/limits.conf`.
Moreover, you will need to edit `/etc/pam.d/sshd` again and change the control
value for `pam_limits.so` to `requisite`. This means that PAM will immediately
abort if `pam_limits.so` checks fail. Note that the session limit applies to the
total number of ssh and sftp connections.

```
session    requisite    pam_limits.so
```

[panda-manual]: https://github.com/panda-re/panda/blob/master/panda/docs/manual.md
