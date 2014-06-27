# -*- coding: utf-8 -*-
"""
=========
Copyright
=========

    - Copyright 2014 Ethan Furman -- All rights reserved.
    - Author: Ethan Furman
    - Contact: ethan@stoneleaf.us

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    - Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    - The names of contributors may not be used to endorse or promote
      products derived from this software without specific prior written
      permission.

THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


import atexit
import errno
import os
import resource
import signal
import socket
import sys
import threading
import time
import traceback

try:
    from Queue import Queue
except ImportError:
    from queue import Queue

__all__ = [
        'Daemon', 'DaemonError', 'Parent', 'check_stage',
        'LockError', 'NotMyLock', 'LockFailed', 'AlreadyLocked', 'PidLockFile',
        'FileTracker',
        ]

version = 0, 5, 0

STDIN = 0
STDOUT = 1
STDERR = 2

INIT_PID = 1

signal_map = dict(
    SIGTERM = 'sig_terminate',
    SIGTSTP = None,
    SIGTTIN = None,
    SIGTTOU = None,
    )

_verbose = False

try:
    basestring
    baseint = int, long
except NameError:
    basestring = str
    baseint = int

def check_stage(func):
    def wrapper(self):
        first = self._stage_completed + 1
        stage = int(func.__name__[-1])
        if self._stage_completed >= stage or self.i_am == 'parent':
            raise DaemonError("Attempted to run stage %d twice" % stage)
        for i in range(first, stage):
            next_stage = getattr(self, 'stage%d' % i)
            next_stage()
        if _verbose:
            print('stage %d' % stage)
        func(self)
        self._stage_completed = stage
        #return self
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


class Parent(SystemExit):
    """
    raised by parent method after child detaches
    """


class DaemonError(Exception):
    """
    Exception raised if errors found in Daemon set up or processing"
    """


class Daemon(object):
    """
    Turn current process into a daemon.
    """

    i_am = 'main'

    def __init__(self,
            target=None,                # function to run as daemon
            args=None,                  # args and kwargs for function
            kwargs=None,
            detach=None,                # True means do it, False means don't,
                                        # None means True unless started by init
                                        # or superserver
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
        if args is None:
            args = tuple()
        self.args = args
        if kwargs is None:
            kwargs = dict()
        self.kwargs = kwargs
        self.detach = detach
        self.working_directory = working_directory
        self.umask = umask
        if process_ids is None:
            process_ids = os.getuid(), os.getgid()
        self.uid, self.gid = process_ids
        self.pid_file = pid_file
        self.inherit_files = inherit_files
        self.signal_map = signal_map
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self._redirect = False
        self._stage_completed = 0
        if _verbose:
            print('finished __init__')

    def activate(self):
        """
        Enter daemon mode and return to caller (parent exits).
        """
        if _verbose:
            print('calling activate')
        self.i_am = 'daemon'
        if self._stage_completed == 10:
            raise DaemonError("daemon already started/activated")
        try:
            if self._stage_completed < 9:
                self.stage9
            self._stage_completed = 10
        except Parent:
            self.i_am = 'parent'
            os._exit(os.EX_OK)

    def __detach(self):
        """
        Detach from current session.  Parent raises exception, child keeps going.
        """
        from_daemon_stdout, to_parent_out = os.pipe()
        from_daemon_stderr, to_parent_err = os.pipe()
        comms_channel = Queue()
        # first fork
        pid = os.fork()
        if pid > 0:
            self.i_am = 'parent'
            os.close(to_parent_out)
            os.close(to_parent_err)
            self.monitor(comms_channel, from_daemon_stdout, from_daemon_stderr)
            raise Parent
        # redirect stdout/err for rest of daemon set up
        # both activate() and start() will have already set self.i_am to 'daemon'
        for stream, dest in ((sys.stdout, to_parent_out), (sys.stderr, to_parent_err)):
            if (
                    hasattr(stream, 'fileno')
                    and stream.fileno() in (STDOUT, STDERR)
                    and stream.fileno() not in self.inherit_files
                ):
                os.dup2(dest, stream.fileno())
        os.close(from_daemon_stdout)
        os.close(from_daemon_stderr)
        os.close(to_parent_out)
        os.close(to_parent_err)
        # start a new session
        os.setsid()
        # second fork
        pid = os.fork()
        if pid > 0:
            self.i_am = 'child'
            os._exit(os.EX_OK)

    def monitor(self, comms_channel, from_daemon_stdout, from_daemon_stderr):
        """
        Parent gets telemetry readings from daemon
        
        both self._stage_completed and self.output are updated
        """
        def read_comm(name, channel):
            while True:
                data = os.read(channel, 1024)
                comms_channel.put((name, data))
                if not data:
                    os.close(channel)
                    break
        threading.Thread(target=read_comm, args=('out', from_daemon_stdout)).start()
        threading.Thread(target=read_comm, args=('err', from_daemon_stderr)).start()
        output = bytes()
        error = bytes()
        active = 2
        while active:
            source, data = comms_channel.get()
            if not data:
                active -= 1
            if source == 'err':
                error += data
            else:
                output += data
        self.output = output.decode('utf8')
        self.error = error.decode('utf8')

    def report(self):
        """
        print output and error attributes, and quit
        """
        print(self.output)
        if self.error:
            print(self.error)
            raise SystemError('Daemon reported error')
        raise SystemExit
        
    def run(self):
        """
        Either override this method, or pass target function to __init__.
        """
        if self.target is None:
            raise DaemonError('nothing to do')
        if _verbose:
            print('running target', self.target.__name__)
        self.target(*self.args, **self.kwargs)

    def __set_signals(self):
        """
        Map terminate and job control signals, and whatever user supplied.
        """
        self.set_signals()
        handler_map = {}
        for sig, func in self.signal_map.items():
            if not isinstance(sig, baseint):
                raise DaemonError("%r is not a valid signal" % sig)
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
        sm = dict([
            (getattr(signal, name), handler)
            for name, handler in signal_map.items()
            if hasattr(signal, name)
            ])
        sm.update(self.signal_map or {})
        self.signal_map = sm

    def sig_terminate(self, signal, stack_frame):
        raise SystemExit("Terminated by signal %s" % signal)

    @check_stage
    def stage1(self):
        """
        Detach (if necessary), and redirect stdout to monitor_startup (if detaching).
        """
        self.i_am = 'daemon'
        self.inherit_files = set(self.inherit_files or [])
        if self.detach is None:
            if started_by_init():
                if _verbose:
                    print('  started_by_init')
                self.detach = False
            elif started_by_super_server():
                if _verbose:
                    print('  started_by_super_server')
                self.inherit_files |= set([0, 1, 2])
                self.detach = False
            else:
                self.detach = True
        if self.detach:
            if _verbose:
                print('  checking std streams')
            for stream in (self.stdin, self.stdout, self.stderr):
                if stream is not None:
                    self.inherit_files.add(stream)
            if _verbose:
                print('  detaching')
            self.__detach()
            if _verbose:
                print('  detached')
            self._redirect = True

    @check_stage
    def stage2(self):
        """
        Turn off core dumps.
        """
        if self.prevent_core:
            if _verbose:
                print('  turning off core dumps')
            prevent_core_dump()

    @check_stage
    def stage3(self):
        """
        Set uid & gid (possibly losing privilege).
        """
        if self.gid is not None:
            if _verbose:
                print('  setting gid: %s' % self.gid)
            os.setgid(self.gid)
        if self.uid is not None:
            if _verbose:
                print('  setting uid: %s' % self.uid)
            os.setuid(self.uid)

    @check_stage
    def stage4(self):
        """
        Change umask.
        """
        if _verbose:
            print('  setting umask: %s' % self.umask)
        os.umask(self.umask)

    @check_stage
    def stage5(self):
        """
        Change working directory (default is /).
        """
        if not self.working_directory:
            raise DaemonError(
                    'working_directory must be a valid path (received %r)' %
                    self.working_directory
                    )
        if _verbose:
            print('  changing working directory to: %s' % self.working_directory)
        os.chdir(self.working_directory)

    @check_stage
    def stage6(self):
        """
        Set up PID file.
        """
        if _verbose:
            print('  self.pid_file: %r' % self.pid_file)
        if self.pid_file is not None:
            if _verbose:
                print('  locking pid file')
            pid_file = self.pid_file
            if isinstance(pid_file, basestring):
                self.pid_file = pid_file = PidLockFile(pid_file)
                pid_file.acquire()
                atexit.register(self.break_lock)
            pid = pid_file.seal()
            if _verbose:
                print('  pid: %s' % pid)

    @check_stage
    def stage7(self):
        """
        Set up signal handlers.
        """
        if _verbose:
            print('  setting signal handlers')
        self.__set_signals()

    @check_stage
    def stage8(self):
        """
        Close open files.
        """
        if _verbose:
            print('  closing open files')
        close_open_files(exclude=self.inherit_files)

    @check_stage
    def stage9(self):
        """
        If detached, redirect streams to user supplied, or os.devnul.
        """
        if self._redirect:
            if _verbose:
                print('  redirecting standard streams:')
                print('    stdin  --> %s' % self.stdin)
                print('    stdout --> %s' % self.stdout)
                print('    stderr --> %s' % self.stderr)
            redirect(self.stdin, STDIN)
            redirect(self.stdout, STDOUT)
            redirect(self.stderr, STDERR)

    def start(self):
        """
        Enter daemon mode and call target (if it exists).
        """
        if _verbose:
            print('calling start')
        if self._stage_completed == 10:
            raise DaemonError("daemon already started/activated")
        try:
            if self._stage_completed < 9:
                self.stage9()
            self._stage_completed = 10
            self.run()
            raise SystemExit
        except Parent:
            return


class LockError(Exception):
    """
    Base class for lock-file errors.
    """

class NotMyLock(LockError):
    """
    Lock file owned by another PID.
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

    def __enter__(self):
        """
        Acquire and seal the lock.
        """
        self.acquire()
        self.seal()
        return self

    def __exit__(self, *args):
        """
        Release lock.
        """
        self.break_lock()

    def acquire(self, time_out=None):
        """
        Create the file, establishing the lock, but do not write the PID.

        Check first for an existing, stale pid file.
        """
        if _verbose:
            print('acquiring lock')
        if self.is_stale():
            if _verbose:
                print('lock is stale')
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
            except OSError:
                exc = sys.exc_info()[1]
                if exc.errno != errno.EEXIST:
                    raise LockFailed("Unable to create %r" % self.file_name)
                elif time_out < 0:
                    raise AlreadyLocked("%s is already locked" % self.file_name)
                elif time.time() < end_time:
                    time.sleep(max(0.1, time_out/10.0))
            else:
                self.file_obj = os.fdopen(fd, 'w')
                break

    def am_i_locking(self):
        """
        Return True if this file is my lock.
        """
        return self.file_obj is not None or self.read_pid == os.getpid()

    def break_lock(self):
        """
        Remove the file, thus breaking the lock.
        """
        try:
            if _verbose:
                print('breaking lock')
            os.unlink(self.file_name)
        except OSError:
            exc = sys.exc_info()[1]
            if exc.errno == errno.EEXIST:
                if _verbose:
                    print('%s does not exist' % self.file_name)
                return
            raise LockError("Unable to break lock: %d: %s" % (exc.errno, exc.message))
        except Exception:
            exc = sys.exc_info()[1]
            raise LockError("Unable to break lock: %s" % (exc.message, ))
        if _verbose:
            print('lock broken')

    def is_locked(self):
        """
        Return True if the pid file exists, and is not stale.
        """
        if _verbose:
            print('checking if locked')
            print('%s exists: %s' % (self.file_name, os.path.exists(self.file_name)))
        return os.path.exists(self.file_name) and not self.is_stale()

    def is_stale(self, timeout=5):
        """
        Return True if the pid file contains a PID, and no such process exists.
        """
        if self.file_obj is not None:
            if _verbose:
                print('our lock, definitely not stale')
            return False
        elif not os.path.exists(self.file_name):
            if _verbose:
                print("lock doesn't exist, can't be stale")
            return False
        pid = self.read_pid()
        if pid is None:
            if _verbose:
                print('not our lock, but not yet sealed')
            # give it a few seconds to seal; if it doesn't
            # consider it abandoned and therefore stale
            end_time = time.time() + timeout
            while end_time > time.time():
                time.sleep(1)
                pid = self.read_pid()
                if pid is not None:
                    break
            else:
                if _verbose:
                    print('still not sealed')
                return True
        try:
            # see if there is such a process by sending the null-signal
            if _verbose:
                print('checking on pid: %s' % pid)
            os.kill(pid, 0)
        except OSError:
            exc = sys.exc_info()[1]
            if exc.errno == errno.ESRCH:
                if _verbose:
                    print("it's dead")
                return True
            if _verbose:
                print('unhandled exception: %s' % exc)
        if _verbose:
            print("it's alive!")
        return False

    def read_pid(self):
        "Return PID stored in file, or None"
        if self.file_obj is not None:
            # we are in between acquiring and sealing the lock
            if _verbose:
                print('our lock, but not yet sealed, so no PID')
            return None
        try:
            pid_file = open(self.file_name)
            pid = pid_file.read()
            pid_file.close()
            pid = int(pid.split('\n')[0])
        except Exception:
            pid = None
        if _verbose:
            print('pid is %s' % pid)
        return pid

    def release(self):
        """
        delete the file/lock if it is ours
        """
        if self.file_obj is None:
            pid = self.read_pid()
            if pid != os.getpid():
                raise NotMyLock('Lock is owned by pid: %s' % pid)
        self.break_lock()

    def seal(self):
        """
        Write our PID to the file lock, and close the file.

        This should only be called after becoming a daemon.
        """
        if self.file_obj is None:
            self.acquire()
        if _verbose:
            print('sealing lock')
        pid = os.getpid()
        self.file_obj.write("%s\n" % pid)
        self.file_obj.close()
        self.file_obj = None
        if _verbose:
            print('with PID: %s' % pid)
        return pid


class FileTracker(object):
    """
    useful for tracking files that are still open at time of daemonization
    that need to stay open (such as /dev/random)
    """
    builtin_open = open
    _cache = {}
    _active = False
    @classmethod
    def __call__(cls, name, *args, **kwds):
        file = cls.builtin_open(name, *args, **kwds)
        cls._cache[name] = file
        return file
    @classmethod
    def active(cls, name):
        """
        return the open file object referred to by name
        raise an error if no such open file exists
        """
        cls.open_files()
        try:
            return cls._cache[name]
        except KeyError:
            raise ValueError('%s has been closed' % name)
    @classmethod
    def open_files(cls):
        """
        return list of (name, file_object) tuples for all tracked, open files
        """
        closed = []
        for name, file in cls._cache.items():
            if file.closed:
                closed.append(name)
        for name in closed:
            cls._cache.pop(name)
        return cls._cache.items()
    @classmethod
    def install(cls):
        """
        start tracking calls to `open()`
        """
        if cls._active is not True:
            cls._active = True
            if isinstance(__builtins__, dict):
                __builtins__['open'] = cls()
            else:
                __builtins__.open = cls()


def close_open_files(exclude):
    max_files = resource.getrlimit(resource.RLIMIT_NOFILE)[1]
    keep = set()
    for file in exclude:
        if isinstance(file, baseint):
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
    elif not isinstance(stream, int):
        stream_fd = stream.fileno()
    else:
        stream_fd = stream
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
