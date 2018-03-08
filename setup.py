import setuptools; setuptools
from distutils.core import setup

long_desc = """\
pandaemonium
============

n. the abode of all the daemons [1]_

pandaemonium provides a framework for writing daemons in Python.  The API is
based on the threading/multiprocessing model [2]_ [3]_, so the primary way
of creating your own daemon is to either subclass and override the ``run``
method, or provide a function as the ``target`` to the ``Daemon`` class.

Besides ``Daemon`` there is also a locking pid file -- ``PidLockFile``.
``PidLockFile`` can either be used manually, or, if a complete path and file
name are provided to ``Daemon``, used automatically.


simple usage
------------

    from pandaemonium import Daemon

    def DoSomethingInteresting():
        "Just like it says ;)"
        pass

    daemon = Daemon(target=DoSomethingInteresting)
    daemon.start()
    #
    # daemon.output will contain any stdout output generated during the
    # daemonizing process, up to the stdin/stdout/stderr redirection
    #
    # daemon.error contains anything sent to the daemon's stderr -- which
    # most likely means the daemon died due to an exception
    #
    # both can be parsed, examined, ignored, etc.


or:

    from pandaemonium import Daemon

    class MyDaemon(Daemon):
        def run():
            # do some interesting stuff

    md = MyDaemon().start()

The sequence of events that takes place when `start()` is called (adapted from
The Linux Programming Interface by Michael Kerrisk) is:

  - detach from the current process, creating a new session
  - turn off core dumps
  - set uid and gid
  - set umask
  - set working directory
  - create pid file
  - set signal handlers
  - close inherited file handles
  - redirect stdin/stdout/stderr

If any exceptions occur or if any feedback is generated during the `start`
process it will be available as the `error` and `output` attributes of the
daemon instance, where the parent process can analyze, print, etc before
quiting.

Note:  Most guides on writing daemons specify setting the umask to 0, but
this creates a security hole as all files become world readable/writable by
default.  Pandaemonium sets the umask to 077, but that can be changed if
desired.


advanced usage
--------------

If more control is needed than what is provided by the parameters of Daemon
then one has a couple options available:

  - if certain set up / initialization steps need to happen somewhere in the
    `start()` sequence, such as after setting the umask and before changing
    the working directory::

        Daemon.stage4()
        # stages 1-4 have now been completed
        # do custom steps here
        Daemon.start()
        # stages 5-9 have now been completed, and run() called

  - one can also override any of the stages in a subclass (make sure and
    decorate with `check_stage`:

        class MyDaemon(Daemon):
            def run(self, ip):
                # do stuff
            @check_stage
            def stage7(self):
                # do some custom stuff with signals set up

        md = MyDaemon('192.168.11.1')
        md.start()

  - or, to simplify between foreground and daemon operation:

        foreground = sys.argv[2:3] == ['--foreground']
        pid_file = PidLockFile('/some/path/to/lock.pid')
        pid_file.acquire()
        if foreground:
            pid_file.seal()
        else:
            daemon = Daemon()
            daemon.pid_file = pid_file
            daemon.activate()
        # at this point, in either foreground or daemon mode, the pid file has
        # been sealed (has our correct pid written to it, and it has been
        # closed)
        run_main_program()

If one's desire is to start the daemon and automatically have any output
printed to screen, one can use `daemon.report()` which prints whatever was
received from the daemon and then quits.


Daemon
------

``Daemon(target=None, args=None, kwargs=None, working_directory='/', umask=0,
         prevent_core=True, process_ids=None, inherit_files=None,
         signal_map=None, stdin=None, stdout=None, stderr=None)``

    target
        function to call when daemonized

    args
        positional args to provide to target

    kwargs
        keyword args to provide to target

    detach
        `None` (default) means figure it out, `True` means yes, `False` means no.
        Figuring it out means if the parent process is `init`, or a `super
        server`, do not detach

    working_directory
        directory to change to (relative to chroot, if one is in effect)

    umask
        mask to use when creating files

    prevent_core
        prevent core dump files from being created

    process_ids
        tuple of (uid, gid) to switch process to (use (None, None) to disable)

    pid_file
        `None` (default), or
        a PidLockFile instance, or
        the string of where to create a PidLockFile

    inherit_files
        list of open files or file descriptors to keep open

    signal_map
        dictionary of signal names or numbers to method names or functions

    stdin / stdout / stderr
        streams to map the standard streams to
        default is `None` which is mapped to ``os.devnull``


``Daemon.run()``
''''''''''''''''
    Method representing the daemon's activity.

    You may override this method in a subclass.  The standard ``run``
    method invokes the callable object passed to the object's constructor as
    the `target` argument, if any, with sequential and keyword arguments taken
    from the `args` and `kwargs` arguments, respectively.

``Daemon.start()``
''''''''''''''''''
    Start the daemon's activity.

    This may be called at most once per daemon object.  It arranges for the
    object's ``run`` method to be invoked as a daemon process.

``Daemon.monitor()``
''''''''''''''''''''
    Collects stdout and stderr from Daemon process until stage 9 and attaches
    it to the daemon instance as ``output`` and ``error``.  Can be overridden
    if one wants to do more interesting stuff with the daemon's output

``Daemon.stage[1-9]()``
''''''''''''''''''''''''''
    One can override the various stages for even more customizations options.
    Make sure and decorate such functions with ``check_stage``.


PidLockFile
-----------

``PidLockFile(file_name, timeout)``

    file_name
        full path and name of file to use for locking

    timeout
        how long to wait before concluding that an existing held lock is not
        going to be released (default: -1, meaning conclude immediately)

``PidLockFile.acquire(timeout=None)``
''''''''''''''''''''''''''''''''''''''
    attempt to capture the lock file; if timeout is `None` use the time out
    specified when PidLockFile was created.

``PidLockFile.seal()``
''''''''''''''''''''''
    write the current process' PID into the acquired file and close it --
    should only be called by the daemon process or the stored PID will not be
    correct.

``PidLockFile.release()``
'''''''''''''''''''''''''
    remove the lock file, releasing the lock.



[1] http://dictionary.reference.com/browse/pandemonium
[2] https://docs.python.org/2/library/threading.html#threading.Thread
[3] https://docs.python.org/2/library/multiprocessing.html#multiprocessing.Process
"""

py2_only = ()
py3_only = ()
make = []

data = dict(
    name='pandaemonium',
    version='0.9.0',
    license='BSD License',
    description='Framework for writing daemons, with API similar to threading and multiprocessing.',
    long_description=long_desc,
    packages=['pandaemonium'],
    package_data={'pandaemonium': ['CHANGES', 'LICENSE']},
    author='Ethan Furman',
    author_email='ethan@stoneleaf.us',
    url="https://bitbucket.org/stoneleaf/pandaemonium",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development',
        ],
    )

if __name__ == '__main__':
    setup(**data)
