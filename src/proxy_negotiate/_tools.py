import os
import sys
import base64
import socket
import logging

from urllib.parse import urlparse

from gevent.socket import wait_read


if sys.platform == "win32":
    import winkerberos as kerberos
else:
    import gssapi
    import fcntl


LOG_LEVEL = {0: logging.NOTSET, 1: logging.INFO, 2: logging.DEBUG}


def proxy_forward(src, dst, server):
    try:
        source_address = '%s:%s' % src.getpeername()[:2]
        dest_address = '%s:%s' % dst.getpeername()[:2]
    except socket.error as e:
        # We could be racing signals that close the server
        # and hence a socket.
        logging.debug("Failed to get all peer names: %s", e)
        return

    while True:
        try:
            data = src.recv(1024)
            logging.info('%s->%s', source_address, dest_address)
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
            logging.info('Socket error. Closing connection %s->%s',
                         source_address,
                         dest_address)
            if not server.closed:
                server.close()
            break


def nc_forward_stdin(sock):
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


def nc_forward_stdout(sock):
    try:
        while True:
            data = sock.recv(1024)
            if not data:
                break
            sys.stdout.write(data)
            sys.stdout.flush()
    finally:
        sock.close()


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


def proxy_host_from_env():
    if 'HTTPS_PROXY' in os.environ:
        return urlparse(os.environ['HTTPS_PROXY']).hostname
    elif 'HTTP_PROXY' in os.environ:
        return urlparse(os.environ['HTTP_PROXY']).hostname
    else:
        raise RuntimeError('No PROXY environment variable set.')


def proxy_port_from_env():
    if 'HTTPS_PROXY' in os.environ:
        return urlparse(os.environ['HTTPS_PROXY']).port
    elif 'HTTP_PROXY' in os.environ:
        return urlparse(os.environ['HTTP_PROXY']).port
    else:
        raise RuntimeError('No PROXY environment variable set.')
