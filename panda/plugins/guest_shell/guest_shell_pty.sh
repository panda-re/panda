socat UNIX-CONNECT:/tmp/guest_shell.sock PTY,link=/tmp/guest_shell_pty & screen /tmp/guest_shell_pty
