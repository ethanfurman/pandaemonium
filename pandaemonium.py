# -*- coding: utf-8 -*-

import atexit
import errno
import os
import resource
import signal
import socket
import sys
import time

STDIN = 0
STDOUT = 1
STDERR = 2

INIT_PID = 1

signal_map = dict([
    (getattr(signal, name), target) for (name, target) in (
        ('SIGTERM', 'sig_terminate'),
        ('SIGTSTP', None),
        ('SIGTTIN', None),
        ('SIGTTOU', None),
        ) if hasattr(signal, name)
    ])

_verbose = False

class Daemon(object):
    """
    Turn current process into a daemon.
    """

    def __init__(self,
            target=None,                # function to run as daemon
            args=(),                    # args and kwargs for function
            kwargs={},
            working_directory='/',      # directory to change to
            umask=0,                    # don't mask anything for file creation
            prevent_core=True,          # don't write core files
            process_ids=None,           # uid, gid to switch to (None means ask
                                        # the os who is really running things
            pid_file=None,              # string or actual locking file
            inherit_files=None,         # iterable of files or fds to not close
            signal_map=None,            # map of signals:functions for daemon
            stdin=None,                 # redirect stdin after daemonization
            stdout=None,                # redirect stdout after daemonization
            stderr=None,                # redirect stderr after daemonization
            ):
        self.prevent_core = prevent_core
        if prevent_core:
            prevent_core_dump()
        self.target = target
        self.args = args
        self.kwargs = kwargs
        self.working_directory = working_directory
        self.umask = umask
        self.process_ids = process_ids
        if pid_file is not None:
            if isinstance(pid_file, basestring):
                pid_file = PidLockFile(pid_file)
        self.pid_file = pid_file
        self.inherit_files = inherit_files
        self.signal_map = signal_map
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self._two_stage = False
        if _verbose:
            print('finished __init__')

    def __enter__(self):
        """
        Enter context manager, returning self.
        """
        self.start(_two_stage=True)
        return self

    def __exit__(self, *args):
        if args == (None, None, None):
            self._finish()

    def __detach(self):
        """
        Detach from current session.  Parent calls monitor, child keeps going.
        """
        from_daemon, to_parent = os.pipe()
        # first fork
        pid = os.fork()
        if pid > 0:
            os.close(to_parent)
            self._monitor(from_daemon)
        # redirect stdout/err for rest of daemon set up
        for stream in (sys.stderr, ):
            if hasattr(stream, 'fileno') and stream.fileno() in (STDOUT, STDERR):
                os.dup2(to_parent, stream.fileno())
        os.close(from_daemon)
        os.close(to_parent)
        # start a new session
        os.setsid()
        # second fork
        pid = os.fork()
        if pid > 0:
            os._exit(os.EX_OK)

    def _finish(self):
        """
        Primarily used by context manager, but can be called manually on
        ealier Pythons.
        """
        self._two_stage = False
        close_open_files(exclude=self.inherit_files)
        if self._redirect:
            redirect(self.stdin, STDIN)
            redirect(self.stdout, STDOUT)
            redirect(self.stderr, STDERR)
        self.run()
        raise SystemExit

    def _monitor(self, from_daemon):
        """
        Parent reads from_daemon until empty string returned, then quits.
        """
        feedback = []
        try:
            while True:
                data = os.read(from_daemon, 1024)
                if data:
                    feedback.append(data)
                    #print(''.join(feedback), sep='', end='')
                    #sys.stdout.flush()
                    #if feedback[-1][-1] == '\n':
                    #    break
                else:
                    break
        finally:
            if feedback:
                print(''.join(feedback))
                sys.stdout.flush()
                raise SystemExit("Daemon failed.")
        raise SystemExit

    def run(self):
        """
        Either override this method, or pass target function to __init__.
        """
        if _verbose:
            print('run')
        if self._two_stage:
            raise RunTimeError("initialization not complete")
        if self.target is not None:
            print('running target', self.target.__name__)
            return self.target(*self.args, **self.kwargs)

    def __set_signals(self):
        """
        Map terminate and job control signals, and whatever user supplied.
        """
        self.set_signals()
        handler_map = {}
        for sig, func in self.signal_map.items():
            if func is None:
                func = signal.SIG_IGN
            elif isinstance(func, basestring):
                func = getattr(self, func)
            signal.signal(sig, func)


    def set_signals(self):
        """
        Either override this method, or give a signal_map to __init__, for fine
        tuning which signals are handled.
        """
        sm = signal_map.copy()
        sm.update(self.signal_map or {})
        self.signal_map = sm

    def sig_terminate(self, signal, stack_frame):
        raise SystemExit("Terminated by signal %s" % signal)

    def start(self, _two_stage=False):
        """
        Enter daemon mode and call target (if it exists).

        If _two_stage is True then the files are not closed and target (if any)
        is not called.
        """
        if _verbose:
            print('calling start')
        # check to see if detaching is necessary
        self.inherit_files = set(self.inherit_files or [])
        if started_by_init():
            if _verbose:
                print('calling started_by_init')
            self._redirect = False
        elif started_by_super_server():
            if _verbose:
                print('calling started_by_super_server')
            self.inherit_files |= set([0, 1, 2])
            self._redirect = False
        else:
            if _verbose:
                print('checking std streams')
            for stream in (self.stdin, self.stdout, self.stderr):
                if stream is not None:
                    self.inherit_files.add(stream)
            if _verbose:
                print('detaching')
            self.__detach()
            if _verbose:
                print('detached')
            self._redirect = True
        if self.prevent_core:
            prevent_core_dump()
        os.umask(self.umask)
        if self.working_directory:
            os.chdir(self.working_directory)
        if self.pid_file is not None:
            pid = self.pid_file.acquire()
            print('pid: %s' % pid)
        self.__set_signals()
        if not _two_stage:
            self._finish()
        self._two_stage = True


class LockError(Exception):
    """
    Base class for lock-file errors.
    """

class LockFailed(LockError):
    """
    Unable to lock file.
    """

class AlreadyLocked(LockFailed):
    """
    Lock has already been obtained.
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
            raise LockError("%r is not an absolute path")
        try:
            time_out = int(time_out)
        except Exception:
            raise LockError("Unable to convert %r to an integer")
        self.file_name = file_name
        self.time_out = time_out
        self.file_obj = None

    def acquire(self, time_out=None):
        """
        Create the file, establishing the lock, but do not write the PID.

        Check first for an existing, stale pid file.
        """
        if self.is_stale():
            print('pid is stale, breaking')
            self.break_lock()
            print('broken')
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
                self.file_obj = os.fdopen(fd, 'w')
            except OSError:
                exc = sys.exc_info()[1]
                print(str(exc))
                if exc.errno != errno.EEXIST:
                    raise LockFailed("Unable to create %r" % self.file_name)
                elif time_out < 0:
                    raise AlreadyLocked("%s is already locked" % self.file_name)
                elif time.time() < end_time:
                    time.sleep(max(0.1, time_out/10.0))
            else:
                pid = self.seal()
                atexit.register(self.release)
                return pid

    def break_lock(self):
        """
        Remove the file, thus breaking the lock.
        """
        try:
            os.unlink(self.file_name)
        except OSError:
            exc = sys.exc_info()[1]
            if exc.errno == errno.EEXIST:
                return
            raise LockError("Unable to break lock: %d: %s" % (exc.errno, exc.message))
        except Exception:
            exc = sys.exc_info()[1]
            raise LockError("Unable to break lock: %s" % (exc.message, ))

    def is_stale(self):
        """
        Return True if the pid file contains a PID, and no such process exists.
        """
        pid = self.read_pid()
        if pid is None:
            return False
        try:
            # see if there is such a process exists by sending the null-signal
            os.kill(pid, 0)
        except OSError:
            exc = sys.exc_info()[1]
            if exc.errno == errno.ESRCH:
                return True
        return False

    def read_pid(self):
        "Return PID stored in file, or None"
        if self.file_obj is not None:
            # we are in between acquiring and sealing the lock
            return None
        try:
            pid_file = open(self.file_name)
            pid = pid_file.read()
            pid_file.close()
        except Exception:
            return None
        try:
            return int(pid.split('\n')[0])
        except Exception:
            return None

    def release(self):
        pid = self.read_pid()
        if pid != os.getpid():
            raise NotMyLock('Lock is owned by pid: %s' % pid)
        self.break_lock()

    def seal(self):
        """
        Write our PID to the file lock, and close the file.

        This should only be called after becoming a daemon.
        """
        pid = os.getpid()
        self.file_obj.write("%s\n" % pid)
        self.file_obj.close()
        self.file_obj = None
        return pid


def close_open_files(exclude):
    max_files = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    keep = set()
    for file in exclude:
        if isinstance(file, (int, long)):
            keep.add(file)
        elif hasattr(file, 'fileno'):
            keep.add(file.fileno())
        else:
            raise ValueError(
                    'files to not close should be either an file descriptor, '
                    'or a file-type object, not %r (%s)' % (type(file), file))
            for fd in range(max_files, -1, -1):
                if fd in keep:
                    continue
                try:
                    os.close(fd)
                except OSError:
                    exc = sys.exc_info()[1]
                    if exc.errno == errno.EBADF:
                        continue
                    raise

def prevent_core_dump():
    """
    Set resource limits to inhibit creation of a core file.
    """
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def redirect(stream, target_fd):
    """
    Close target_fd and clone stream's fileno() onto it.
    """
    if stream is None:
        stream_fd = os.open(os.devnull, os.O_RDWR)
    else:
        stream_fd = stream.fileno()
    os.dup2(stream_fd, target_fd)

def started_by_init():
    """Return True if this process was started by init.

    This is apparent by the parent process being 1.
    """
    return os.getppid() == INIT_PID

def started_by_super_server():
    """Return True if this process was started by the [x]inetd.

    This is apparent by the std streams being bound to a socket.
    """
    sock = socket.fromfd(STDIN, socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.getsockname()
    except socket.error:
        exc = sys.exc_info()[1]
        if exc.errno == errno.ENOTSOCK:
            return False
    return True
