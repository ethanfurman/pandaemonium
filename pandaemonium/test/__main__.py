from pandaemonium import *

FileTracker.install()

import os
import sys
import tempfile
from unittest import TestCase, main

try:
    TestCase.assertRaisesRegex
except AttributeError:
    TestCase.assertRaisesRegex = TestCase.assertRaisesRegexp

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
        files[0].close()
        files[2].close()


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
        plf.release()

    def test_acquire_file_stale(self):
        "file exists but is empty"
        open(self.file_name, 'w').close()
        plf = PidLockFile(self.file_name)
        plf.acquire()
        plf.release()

    def test_acquire_file_locked(self):
        "file exists and has active PID"
        locker = PidLockFile(self.file_name)
        locker.seal()
        too_late = PidLockFile(self.file_name)
        self.assertRaises(AlreadyLocked, too_late.acquire)
        locker.release()

    def test_acquire_file_locked_with_timeout(self):
        "file exists and has active PID"
        locker = PidLockFile(self.file_name)
        locker.seal()
        too_late = PidLockFile(self.file_name, timeout=3)
        self.assertRaises(AlreadyLocked, too_late.acquire)
        locker.release()

    def test_context_reentrant(self):
        "lock is reentrant as context manager"
        locker = PidLockFile(self.file_name, reentrant=True)
        locker.seal()
        with locker:
            pass
        locker.release()

    def test_context_not_reentrant_without_context_manager(self):
        "lock is not reentrant outside of context manager"
        locker = PidLockFile(self.file_name, reentrant=True)
        locker.seal()
        with self.assertRaisesRegex(LockError, "context manager"):
            locker.seal()
        locker.release()

    def test_context_not_reentrant(self):
        "lock is not reentrant without flag"
        locker = PidLockFile(self.file_name)
        locker.seal()
        with self.assertRaisesRegex(AlreadyLocked, 'is not reentrant'):
            with locker:
                pass
        locker.release()

class TestDaemon(object):
    # this is not a TestCase because unittest cannot handle the daemons
    # (it keeps combining the outputs, and failing the tests)

    passed = failed = 0
    messages = []

    def test_target(self):
        def leave_message():
            print("Okay, I made it!  G'bye!")
        r, w = os.pipe()
        d = Daemon(target=leave_message, stdout=w)
        d.start()
        passed = os.read(r, 1024).decode('ascii') == "Okay, I made it!  G'bye!\n"
        if passed:
            print('.')
            self.passed += 1
        else:
            print('F')
            self.failed += 1
        self.messages.append('test_target: %s' % (['failed', 'passed'][passed], ))

    def test_run(self):
        class MyDaemon(Daemon):
            def run(self):
                print("Running like the wind!")
                raise SystemExit
        r, w = os.pipe()
        d = MyDaemon(stdout=w)
        d.start()
        passed = os.read(r, 1024).decode('ascii') == "Running like the wind!\n"
        if passed:
            print('.')
            self.passed += 1
        else:
            print('F')
            self.failed += 1
        self.messages.append('test_run: %s' % (['failed', 'passed'][passed], ))

    def test_failure(self):
        class DeadDaemon(Daemon):
            def run():
                print("wow! it happenned!")
            @check_stage
            def stage5(self):
                1 / 0
        d = DeadDaemon()
        try:
            d.start()
        except DaemonError:
            pass
        if 'ZeroDivisionError' in d.error:
            self.passed += 1
            print('.')
        else:
            print('F')
            self.failed += 1

    def run(self):
        self.test_target()
        self.test_run()
        self.test_failure()
        if '-v' in sys.argv:
            print('\n'.join(self.messages))
        print('----------------------------------------------------------------------')
        print('ran %d tests for Daemon\n' % (self.passed + self.failed))
        if self.failed:
            print('failed: %d\n' % self.failed)
        else:
            print('OK\n')


if __name__ == '__main__':
    TestDaemon().run()
    main()
