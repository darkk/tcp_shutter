# This module calls shutdown() on every TCP socket that got no packets (either
# data or ACK) from the peer for the specified amount of time.  It's ugly
# workaround for lack of timeout options in zillion of network libraries.
# shutdown() call unlocks thread that's locked on recv() or send() call.
#
# The module is not portable and uses Linux-specific TCP_INFO structure.
#
# -- Leonid Evdokimov <leon@darkk.net.ru>

import contextlib
import traceback
import ctypes
import ctypes.util
import errno
import logging
import os
import resource
import socket
import time
import threading


libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.getsockopt.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.shutdown.argtypes = [ctypes.c_int, ctypes.c_int]
libc.getsockname.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.getpeername.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]


def ctypes_repr(self):
    return self.__class__.__name__ + '(' + ', '.join('%s=%s' % (f[0], getattr(self, f[0])) for f in self._fields_) + ')'


class sockaddr_in(ctypes.Structure):
    __repr__ = ctypes_repr
    _fields_ = (
        ('sin_family', ctypes.c_ushort),
        ('sin_port', ctypes.c_uint16),
        ('sin_addr', ctypes.c_uint8 * 4),
        ('sin_zero', ctypes.c_uint8 * (16 - 4 - 2- 2)), # padding
    )
    def __str__(self):
        return '%s:%d' % (socket.inet_ntop(self.sin_family, ''.join(map(chr, self.sin_addr))), socket.ntohs(self.sin_port))


class sockaddr_in6(ctypes.Structure):
    __repr__ = ctypes_repr
    _fields_ = (
        ('sin6_family', ctypes.c_ushort),
        ('sin6_port', ctypes.c_uint16),
        ('sin6_flowinfo', ctypes.c_uint32),
        ('sin6_addr', ctypes.c_uint8 * 16),
        ('sin6_scope_id', ctypes.c_uint32)
    )
    def __str__(self):
        return '[%s]:%d' % (socket.inet_ntop(self.sin6_family, ''.join(map(chr, self.sin6_addr))), socket.ntohs(self.sin6_port))


# NB: It's not true mapping of `sockaddr_storage` structure!
class sockaddr_storage(ctypes.Union):
    __repr__ = ctypes_repr
    _fields_ = (('v4', sockaddr_in), ('v6', sockaddr_in6))


# tcpi_state
TCP_ESTABLISHED = 1
TCP_SYN_SENT = 2
TCP_SYN_RECV = 3
TCP_FIN_WAIT1 = 4
TCP_FIN_WAIT2 = 5
TCP_TIME_WAIT = 6
TCP_CLOSE = 7
TCP_CLOSE_WAIT = 8
TCP_LAST_ACK = 9
TCP_LISTEN = 10
TCP_CLOSING = 11

class tcp_info(ctypes.Structure):
    __repr__ = ctypes_repr

    __state_str = {
            TCP_ESTABLISHED: 'TCP_ESTABLISHED',
            TCP_SYN_SENT: 'TCP_SYN_SENT',
            TCP_SYN_RECV: 'TCP_SYN_RECV',
            TCP_FIN_WAIT1: 'TCP_FIN_WAIT1',
            TCP_FIN_WAIT2: 'TCP_FIN_WAIT2',
            TCP_TIME_WAIT: 'TCP_TIME_WAIT',
            TCP_CLOSE: 'TCP_CLOSE',
            TCP_CLOSE_WAIT: 'TCP_CLOSE_WAIT',
            TCP_LAST_ACK: 'TCP_LAST_ACK',
            TCP_LISTEN: 'TCP_LISTEN',
            TCP_CLOSING: 'TCP_CLOSING' }
    def state(self):
        return self.__state_str.get(self.tcpi_state)

    _fields_ = (
        ('tcpi_state', ctypes.c_uint8),
        ('tcpi_ca_state', ctypes.c_uint8),
        ('tcpi_retransmits', ctypes.c_uint8),
        ('tcpi_probes', ctypes.c_uint8),
        ('tcpi_backoff', ctypes.c_uint8),
        ('tcpi_options', ctypes.c_uint8),
        ('tcpi_snd_wscale', ctypes.c_uint8, 4),
        ('tcpi_rcv_wscale', ctypes.c_uint8, 4),

        ('tcpi_rto', ctypes.c_uint32),
        ('tcpi_ato', ctypes.c_uint32),
        ('tcpi_snd_mss', ctypes.c_uint32),
        ('tcpi_rcv_mss', ctypes.c_uint32),

        ('tcpi_unacked', ctypes.c_uint32),
        ('tcpi_sacked', ctypes.c_uint32),
        ('tcpi_lost', ctypes.c_uint32),
        ('tcpi_retrans', ctypes.c_uint32),
        ('tcpi_fackets', ctypes.c_uint32),

        # Times in msec
        ('tcpi_last_data_sent', ctypes.c_uint32),
        ('tcpi_last_ack_sent', ctypes.c_uint32), # /* Not remembered, sorry. */
        ('tcpi_last_data_recv', ctypes.c_uint32),
        ('tcpi_last_ack_recv', ctypes.c_uint32),

        # unused # ('tcpi_pmtu', ctypes.c_uint32),
        # unused # ('tcpi_rcv_ssthresh', ctypes.c_uint32),
        # unused # ('tcpi_rtt', ctypes.c_uint32),
        # unused # ('tcpi_rttvar', ctypes.c_uint32),
        # unused # ('tcpi_snd_ssthresh', ctypes.c_uint32),
        # unused # ('tcpi_snd_cwnd', ctypes.c_uint32),
        # unused # ('tcpi_advmss', ctypes.c_uint32),
        # unused # ('tcpi_reordering', ctypes.c_uint32),

        # unused # ('tcpi_rcv_rtt', ctypes.c_uint32),
        # unused # ('tcpi_rcv_space', ctypes.c_uint32),

        # unused # ('tcpi_total_retrans', ctypes.c_uint32),

        # unused # ('tcpi_pacing_rate', ctypes.c_uint64),
        # unused # ('tcpi_max_pacing_rate', ctypes.c_uint64),
    )


def get_tcpinfo(fileno):
    # It's called from libc to avoid `socket` module garbage collection,
    # socket.socket has no way to create socket from file fileno.
    ti = tcp_info()
    sizeof = ctypes.c_size_t(ctypes.sizeof(tcp_info))
    if libc.getsockopt(fileno, socket.SOL_TCP, socket.TCP_INFO, ctypes.byref(ti), ctypes.byref(sizeof)) != -1:
        if sizeof.value != ctypes.sizeof(tcp_info):
            return None, errno.EBADSLT
        return ti, 0
    else:
        return None, ctypes.get_errno()


def shutdown(fileno, how):
    if libc.shutdown(fileno, how) == 0:
        return None
    else:
        return ctypes.get_errno()


def get_x_name(fileno, libcfunc):
    sa = sockaddr_storage()
    sizeof = ctypes.c_size_t(ctypes.sizeof(sockaddr_storage))
    if libcfunc(fileno, ctypes.byref(sa), ctypes.byref(sizeof)) == 0:
        return (sa.v4 if sa.v4.sin_family == socket.AF_INET else sa.v6), None
    else:
        return None, ctypes.get_errno()


def getsockname(fileno):
    return get_x_name(fileno, libc.getsockname)


def getpeername(fileno):
    return get_x_name(fileno, libc.getpeername)


def fd_upper_bound():
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    return soft


class TcpShutter(threading.Thread):
    def __init__(self, interval=5.0, timeout=30.0):
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)) as fd:
            # kernel struct may be extended, the code checks ONLY for required fields
            assert ctypes.sizeof(tcp_info) <= 1024
            l = fd.getsockopt(socket.SOL_TCP, socket.TCP_INFO, 1024)
            if len(l) < ctypes.sizeof(tcp_info):
                raise NotImplementedError('socket.getsockopt truncates tcpinfo, got only %d bytes' % len(l))
            ti, err = get_tcpinfo(fd.fileno())
            if ti == None:
                raise OSError(err, os.strerror(err))
            if ord(l[0]) != ti.tcpi_state:
                raise NotImplementedError('socket.getsockopt and libc.getsockopt mismatch')
            if ti.tcpi_state != TCP_CLOSE:
                raise NotImplementedError('getsockopt() mismatch: tcpi_state of fresh socket is not TCP_CLOSE')

        assert interval < timeout

        threading.Thread.__init__(self, name='SocketKiller-%x' % id(self))
        self.__stop = threading.Event()
        self.__prev_almost_deaf = set()
        self.interval = interval
        self.timeout = timeout
        self.max_free_in_a_row = 128

    # Stop-the-world is not implemented due to following reasons:
    # * it's possible to stop non-python thread holding malloc() lock
    #   and get deadlock
    # * it's hard to implement consistent stop without ptrace,
    #   and ptrace may be blocked via LSM
    #
    # oneshot() is NOT race-free, but using shutdown() instead of close()
    # minimises race impact, e.g. shutdown works only for sockets :)

    def oneshot(self):
        almost_deaf = set()
        nofd = 0
        for fd in xrange(fd_upper_bound()):
            ti, err = get_tcpinfo(fd)
            # Only ESTABLISHED sockets are touched as the goal of the code is
            # to drop hung connections. connect() timeout is usually somehow
            # handled and shutdown() can't help half-closed connections.
            if ti is not None and ti.tcpi_state == TCP_ESTABLISHED:
                last_recv = min(ti.tcpi_last_data_recv, ti.tcpi_last_ack_recv) / 1000.0
                if self.timeout < last_recv and fd in self.__prev_almost_deaf:
                    shuterr = shutdown(fd, socket.SHUT_RDWR)
                    peeraddr, peererr = getpeername(fd)
                    sockaddr, sockerr = getsockname(fd)
                    peeraddr = peeraddr if peeraddr is not None else ('<%s>' % os.strerror(peererr))
                    sockaddr = sockaddr if sockaddr is not None else ('<%s>' % os.strerror(sockerr))
                    if shuterr is None:
                        logging.warning('shutdown FD#%d (%s -> %s), %s',
                                fd, sockaddr, peeraddr, ti)
                    else:
                        logging.warning('Error while shutdown FD#%d (%s -> %s) <%d, %s>, %s',
                                fd, sockaddr, peeraddr, shuterr, os.strerror(shuterr), ti)
                elif (self.timeout - self.interval) < last_recv:
                    # to be killed during next iteration
                    almost_deaf.add(fd)

            if ti is None and err == errno.EBADF:
                nofd += 1
                # There is enough `free` file descriptors in a row. The library
                # assumes, there is no need to go to the upper bound.
                # NB: `almost_deaf` set may become inconsistent in this case.
                if nofd >= self.max_free_in_a_row:
                    logging.debug('Stopped at FD#%d, got %d free FDs in a row', fd, nofd)
                    break
            else:
                nofd = 0

        self.__prev_almost_deaf.clear()
        self.__prev_almost_deaf.update(almost_deaf)

    def run(self):
        try:
            # threading.Event in python2 contains 50ms semi-busyloop, that's why
            # time.sleep() is used instead of __stop.wait(timeout=...)
            while not self.__stop.is_set():
                self.oneshot()
                time.sleep(self.interval)
        except Exception:
            logging.critical('Thread dies. %s', traceback.format_exc())

    def stop(self):
        self.__stop.set()
