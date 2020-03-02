import base64
import gevent
import os
import socket
import sys

if sys.platform == 'win32':
    import winkerberos as kerberos
else:
    import gssapi
    import fcntl

from logging import getLogger

from gevent.server import StreamServer
from gevent.socket import create_connection, wait_read

logger = getLogger(__name__)


def forward(src, dst, server):
    try:
        source_address = '%s:%s' % src.getpeername()[:2]
        dest_address = '%s:%s' % dst.getpeername()[:2]
    except socket.error as e:
        # We could be racing signals that close the server
        # and hence a socket.
        log("Failed to get all peer names: %s", e)
        return

    while True:
        try:
            data = src.recv(1024)
            log('%s->%s', source_address, dest_address)
            if not data:
                break
            dst.sendall(data)
        except KeyboardInterrupt:
            # On Windows, a Ctrl-C signal (sent by a program) usually winds
            # up here, not in the installed signal handler.
            if not server.closed:
                server.close()
            break
        except socket.error:
            log('Socket error. Closing connection %s->%s',
                source_address,
                dest_address)
            if not server.closed:
                server.close()
            break


def forward_stdin(sock):
    if sys.platform != 'win32':
        # set stdin to non-blocking so we can read available bytes
        fd = sys.stdin.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    try:
        while True:
            wait_read(sys.stdin.fileno())
            data = sys.stdin.read()
            if not data:
                break
            sock.sendall(data)
    finally:
        sock.close()


def forward_stdout(sock):
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            sys.stdout.write(data)
            sys.stdout.flush()
    finally:
        sock.close()


class NegotiateProxy(StreamServer):

    def __init__(self, listener, upstream, **kwargs):
        super().__init__(listener, **kwargs)

        self.upstream = upstream

    def handle(self, src, addr):
        data = bytearray()
        while True:
            data += src.recv(1024)
            if b'\r\n\r\n' in data:
                break

        log(f'{addr[0]}:{addr[1]} accepted')

        krb_token = get_krb_token(self.upstream[0])

        headers, data = data.split(b'\r\n\r\n', 1)
        headers = headers.split(b'\r\n')

        replaced = False
        for i, header in enumerate(headers):
            if header.startswith(b'Proxy-Authorization:'):
                headers[i] = f'Proxy-Authorization: Negotiate {krb_token}'.encode()
                replaced = True
                break

        if not replaced:
            headers.append(f'Proxy-Authorization: Negotiate {krb_token}'.encode())

        dst = create_connection(self.upstream)
        dst.sendall(b'\r\n'.join(headers) + b'\r\n\r\n' + data)

        forwarders = (gevent.spawn(forward, src, dst, self),
                      gevent.spawn(forward, dst, src, self))

        gevent.joinall(forwarders)

    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            log('Closing listener socket')
            StreamServer.close(self)


def netcat(host, port, proxy_host, proxy_port):
    request = list(f'CONNECT {host}:{port} HTTP/1.1'.encode())
    request.append(f'Host: {host}:{port}'.encode())
    request.append(b'Proxy-Connection: Keep-Alive')
    request.append(b'\r\n')

    dst = create_connection((proxy_host, proxy_port))
    dst.sendall(b'\r\n'.join(request))

    data = bytearray()
    while True:
        data += dst.recv(1024)
        if b'\r\n\r\n' in data:
            break

    if b'200 Connection established' not in data and b'407' in data:
        krb_token = get_krb_token(proxy_host)
        request[-1] = f'Proxy-Authorization: Negotiate {krb_token}'.encode()

        request.append(b'\r\n')

        try:
            dst.sendall(b'\r\n'.join(request))
        except:
            # if proxy does not support Keep-Alive
            dst.close()
            dst = create_connection((proxy_host, proxy_port))
            dst.sendall(b'\r\n'.join(request))

        data = bytearray()
        while True:
            data += dst.recv(1024)
            if b'\r\n\r\n' in data:
                break

    if b'200 Connection established' in data:
        sys.stderr.write('Proxy connection established\n')
        data = data.split(b'\r\n\r\n', 1)[1]
        if data:
            dst.sendall(data)

        forwarders = (gevent.spawn(forward_stdin, dst),
                      gevent.spawn(forward_stdout, dst))

        gevent.joinall(forwarders)
    elif b'407' in data:
        sys.stderr.write('Proxy authentication failed\n')
    else:
        version, status_code, status_message = (
            data.split(b'\r\n', 1)[0].split(b' ', 2)
        )
        sys.stderr.write(f'Proxy returned {status_code} {status_message}\n')


def log(message, *args):
    message = message % args
    sys.stderr.write(message + '\n')


def get_krb_token(host):
    if sys.platform == 'win32':
        # previously used with parameters `gssflags=0` and
        # `mech_oid=kerberos.GSS_MECH_OID_KRB5`
        # neither are required.
        status, ctx = kerberos.authGSSClientInit(f'HTTP/{host}')
        _ = kerberos.authGSSClientStep(ctx, '')
        krb_token = kerberos.authGSSClientResponse(ctx)
    else:
        service = gssapi.Name(f'HTTP@{host}',
                              gssapi.NameType.hostbased_service)
        ctx = gssapi.SecurityContext(name=service, usage='initiate')
        token = ctx.step()
        krb_token = base64.b64encode(token)

    return krb_token
