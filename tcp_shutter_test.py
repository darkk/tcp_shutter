import unittest

import contextlib
import errno
import select
import socket
import time

import tcp_shutter

INTERVAL = 0.5
TO = 10

class TestKilling(unittest.TestCase):
    shutter = None
    listener = None
    laddr = None

    @classmethod
    def setUpClass(cls):
        cls.shutter = tcp_shutter.TcpShutter(interval=INTERVAL, timeout=TO)
        cls.shutter.start()
        cls.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        cls.listener.bind(('127.0.0.1', 0))
        cls.laddr = cls.listener.getsockname()
        cls.listener.listen(1024)

    @classmethod
    def tearDownClass(cls):
        if cls.shutter is not None:
            cls.shutter.stop()
            cls.shutter.join()
            cls.shutter = None
        if cls.listener is not None:
            cls.listener.close()
            cls.listener = None

    def tearDown(self):
        assert self.shutter.is_alive()

    def test_silent_socket(self):
        with contextlib.closing(socket.create_connection(self.laddr)) as fd:
            r, _, _ = select.select([fd], [], [], TO / 2.)
            assert fd not in r
            begin = time.time()
            r, _, _ = select.select([fd], [], [], TO)
            end = time.time()
            assert fd in r
            assert fd.recv(16) == ''
            assert TO / 4. < (end - begin) < TO * 3./4 # < 1/2 + epsilon

class TestPressure(TestKilling):
    # XXX: This class can be used only with `python -m unittest
    # tcp_shutter_test.TestPressure`, it does not work with `py.test`.
    def setUp(self):
        self.__leak = []
        while True:
            try:
                self.__leak.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0))
            except socket.error, err:
                if err.errno == errno.EMFILE:
                    break
        self.__leak.pop().close()

    def tearDown(self):
        TestKilling.tearDown(self)
        for fd in self.__leak:
            fd.close()
        del self.__leak
