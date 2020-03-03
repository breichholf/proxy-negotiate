import sys
import logging
import argparse
import gevent

from urllib.parse import urlparse
from gevent.socket import create_connection

from ._tools import (LOG_LEVEL, nc_forward_stdin, nc_forward_stdout,
                     get_krb_token, proxy_host_from_env, proxy_port_from_env)


def netcat(host, port, proxy_host, proxy_port, verbose):
    logger = logging.getLogger()
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    verbose = 0 if verbose <= 0 else 1
    if verbose:
        logger.setLevel(LOG_LEVEL[verbose])
    else:
        logging.disable(LOG_LEVEL[0])

    request = bytearray(
        b'CONNECT %b:%d HTTP/1.1' % (host.encode(), port) +
        b'\r\n' + b'Host: %b:%d' % (proxy_host.encode(), proxy_port) +
        b'\r\n' + b'Proxy-Connection: Keep-Alive'
    )

    dst = create_connection((proxy_host, proxy_port))
    dst.sendall(request)

    data = bytearray()
    while True:
        data.extend(dst.recv(1024))
        if b'\r\n\r\n' in data:
            break

    if b'200 Connection established' not in data and b'407' in data:
        krb_token = get_krb_token(proxy_host)
        request.extend(b'\r\n' + b'Proxy-Authorization: Negotiate %b' %
                       krb_token)

        try:
            dst.sendall(request)
        except:
            # if proxy does not support Keep-Alive
            dst.close()
            dst = create_connection((proxy_host, proxy_port))
            dst.sendall(request)

        data = bytearray()
        while True:
            data.extend(dst.recv(1024))
            if b'\r\n\r\n' in data:
                break

    if b'200 Connection established' in data:
        logging.info('Proxy connection established\n')
        data = data.split(b'\r\n\r\n', 1)[1]
        if data:
            dst.sendall(data)

        forwarders = (gevent.spawn(nc_forward_stdin, dst),
                      gevent.spawn(nc_forward_stdout, dst))

        gevent.joinall(forwarders)
    elif b'407' in data:
        logging.info('Proxy authentication failed\n')
    else:
        version, status_code, status_message = (
            data.split(b'\r\n', 1)[0].split(b' ', 2)
        )
        logging.info(f'Proxy returned {status_code} {status_message}\n')


def main():
    default_proxy = "%s:%d".format(proxy_host_from_env(), proxy_port_from_env())

    parser = argparse.ArgumentParser(
        description='A thin netcat-like implementation that handles Proxy '
                    'Authentication for applications that cannot do so on their'
                    'own.')
    parser.add_argument('host', metavar='TARGET:PORT',
                        help='Hostname or IP to tunnel a connection to. '
                             'Provide in format of hostname:port')
    parser.add_argument('proxy', metavar='PROXY:PORT', nargs="?",
                        default=default_proxy,
                        help='Address/hostname of the proxy and port. '
                             'Provide in format hostname:port')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help="Add verbose output")
    args = parser.parse_args()

    host, port = urlparse(args.target).host, urlparse(args.target).port
    proxy_host, proxy_port = urlparse(args.proxy).host, urlparse(args.proxy).port

    try:
        netcat(host, port, proxy_host, proxy_port, args.verbose)
    except KeyboardInterrupt:
        sys.exit("Closing down")
