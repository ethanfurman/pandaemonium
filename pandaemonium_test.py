from pandaemonium import Daemon, DaemonError, Parent
from pandaemonium import LockError, NotMyLock, LockFailed, AlreadyLocked, PidLockFile
from pandaemonium import FileTracker

FileTracker.install()

import os
import sys
import tempfile
import time
from unittest import TestCase, main


class TestFileTracker(TestCase):

    def setUp(self):
        self.file_names = []
        for _ in range(3):
            fobj = tempfile.NamedTemporaryFile()
            self.file_names.append(fobj.name)
            fobj.close()

    def takeDown(self):
        for fn in self.file_names:
            try:
                os.unlink(fn)
            except OSError:
                pass

    def test(self):
        files = [open(fn, 'w') for fn in self.file_names]
        open_files = [p[0] for p in FileTracker.open_files()]
        self.assertTrue(self.file_names[0] in open_files)
        self.assertTrue(self.file_names[1] in open_files)
        self.assertTrue(self.file_names[2] in open_files)
        files[1].close()
        open_files = [p[0] for p in FileTracker.open_files()]
        self.assertTrue(self.file_names[0] in open_files)
        self.assertFalse(self.file_names[1] in open_files)
        self.assertTrue(self.file_names[2] in open_files)


class TestPidLockFile(TestCase):

    def setUp(self):
        fobj = tempfile.NamedTemporaryFile()
        self.file_name = fobj.name
        fobj.close()
        try:
            os.unlink(self.file_name)
        except OSError:
            pass

    def takeDown(self):
        try:
            os.unlink(self.file_name)
        except OSError:
            pass

    def test_acquire_file_missing(self):
        "file doesn't exist"
        plf = PidLockFile(self.file_name)
        plf.acquire()

    def test_acquire_file_stale(self):
        open(self.file_name, 'w').close()
        plf = PidLockFile(self.file_name)
        plf.acquire()

    def test_acquire_file_locked(self):
        locker = PidLockFile(self.file_name)
        locker.seal()
        too_late = PidLockFile(self.file_name)
        self.assertRaises(AlreadyLocked, too_late.acquire)
        locker.release()


class TestDaemon(object):

    passed = failed = 0
    messages = []

    def test_target(self):
        print('.')
        def leave_message():
            print("Okay, I made it!  G'bye!")
        r, w = os.pipe()
        d = Daemon(target=leave_message, stdout=w)
        d.start()
        passed = os.read(r, 1024) == "Okay, I made it!  G'bye!\n"
        if passed:
            self.passed += 1
        else:
            self.failed += 1
        self.messages.append('test_target: %s' % (['failed', 'passed'][passed], ))

    def test_run(self):
        print('.')
        class MyDaemon(Daemon):
            def run(self):
                print("Running like the wind!")
                raise SystemExit
        r, w = os.pipe()
        d = MyDaemon(stdout=w)
        d.start()
        passed = os.read(r, 1024) == "Running like the wind!\n"
        if passed:
            self.passed += 1
        else:
            self.failed += 1
        self.messages.append('test_run: %s' % (['failed', 'passed'][passed], ))

    def run(self):
        self.test_target()
        self.test_run()
        if '-v' in sys.argv:
            print('\n'.join(self.messages))
        print('----------------------------------------------------------------------')
        print('ran %d tests for Daemon\n' % self.passed)
        if self.failed:
            print('failed: %d\n' % self.failed)
        else:
            print('OK\n')


#class TcpServer(Daemon):
#    """
#    Serve up the handler.
#    """
#    def run(self):
#        server = SocketServer.TCPServer(('127.0.0.1', 8069), RequestHandler)
#        server.serve_forever()

#class RequestHandler(SocketServer.BaseRequestHandler):
#    """
#    Return the incoming number doubled.
#    """
#    timeout = 15
#    def handle(self):
#        request = self.request.recv(1024).strip().split('\n')
#        response = int(request) * 2
#        self.request.sendall(str(response) + '\n')


if __name__ == '__main__':
    TestDaemon().run()
    main()
