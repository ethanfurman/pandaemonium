# -*- coding: utf-8 -*-

import os
import time

class DaemonError(Exception):
    """
    Base exception for daemon errors.
    """


class Daemon(object):
    """
    Turn current process into a daemon.
    """


class LockFileError(Exception):
    """
    Base class for lock-file errors.
    """


class PidLockFile(object):
    """
    Simple daemon status via a pid file.
    """

    def __init__(self, file_name, time_out=-1):
        """
        file_name and time_out to be used for pid file.
        """
        if not file_name or file_name[0] != '/':
            raise LockFileError("%r is not an absolute path")
        try:
            time_out = int(time_out)
        except Exception:
            raise LockFileError("Unable to convert %r to an integer")
        self.file_name = file_name
        self.time_out = time_out
        self.file_obj = None

    def acquire(self, time_out=None):
        """
        Create the file, establishing the lock, but do not write the PID.

        Check first for an existing, stale pid file.
        """
        if self.is_stale():
            self.break_lock()
        if time_out is None:
            time_out = self.time_out
        end_time = time.time() + time_out
        while True:
            try:
                fd = os.open(
                        self.file_name,
                        os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                        0o644,
                        )
                self.file_obj = os.fdopen(pidfile_fd, 'w')
            except OSError:
                exc = sys.exc_info()[1]
                if exc.errno != errno.EEXIST:
                    raise LockFailed("Unable to create %r" % self.file_name)
                elif time_out < 0:
                    raise AlreadyLocked("%s is already locked" % self.file_name)
                elif time.time() < end_time:
                    time.sleep(max(0.1, time_out/10.0))
            else:
                return

    def seal(self):
        """
        Write our PID to the file lock, and close the file.

        This should only be called after becoming a daemon.
        """
        self.file_obj.write("%s\n" % os.getpid())
        self.file_obj.close()

