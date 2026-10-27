"""Private POSIX group owner for the Claude login PTY (executed as a script)."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading


def main():
    terminal = int(sys.argv[1])
    try:
        child = subprocess.Popen(
            sys.argv[2:], stdin=terminal, stdout=terminal, stderr=terminal,
        )
        os.close(terminal)

        def report_exit():
            print(child.wait(), flush=True)

        threading.Thread(target=report_exit, daemon=True).start()
        # stdin is a private control pipe, not the PTY. EOF also handles the
        # gateway dying. The CLI cannot inherit it (its stdin is the PTY).
        os.read(0, 1)
    finally:
        # We are still the session/group leader created by start_new_session.
        # Even after the CLI is reaped, our lifetime reserves this PGID. Kill
        # ourselves together with remaining group members; never use a saved
        # PID after its owner has exited, or assume descendants cannot setsid().
        os.killpg(os.getpid(), signal.SIGKILL)


if __name__ == "__main__":
    main()
