import re
import sys
import logging
import argparse
import gevent

from gevent.server import StreamServer
from gevent.socket import create_connection

from ._tools import proxy_forward, get_krb_token, LOG_LEVEL


class NegotiateProxy(StreamServer):

    def __init__(self, listener, upstream, verbose: int = 0, **kwargs):
        super().__init__(listener, **kwargs)
        self.upstream = upstream
        self.logger = logging.getLogger()
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        if verbose < 0:
            verbose = 0
        elif verbose > 2:
            verbose = 2
        self.logger.setLevel(LOG_LEVEL[verbose])

    def handle(self, src, addr):
        data = bytearray()
        while True:
            data.extend(src.recv(1024))
            if b'\r\n\r\n' in data:
                break

        logging.info('%s:%d accepted', addr[0], addr[1])

        krb_token = get_krb_token(self.upstream[0])

        header, data = data.split(b'\r\n\r\n', 1)
        auth_msg = b'Proxy-Authorization: Negotiate %b' % krb_token

        if header.find(b'Proxy-Authorization:') == -1:
            header.extend(b'\r\n' + auth_msg)
        else:
            header = re.sub(b'^Proxy-Authorization: [\S ]+$', auth_msg, header)

        dst = create_connection(self.upstream)
        dst.sendall(header + b'\r\n\r\n' + data)

        forwarders = (gevent.spawn(proxy_forward, src, dst, self),
                      gevent.spawn(proxy_forward, dst, src, self))

        gevent.joinall(forwarders)

    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            logging.info('Closing listener socket')
            StreamServer.close(self)


def main():
    parser = argparse.ArgumentParser(
        description='A thin, transparent proxy server for applications that '
                    'do not natively support Negotiate authentication.')
    parser.add_argument('proxy', metavar='PROXY:PORT',
                        help='Address/hostname of the proxy and port. '
                        'Provide in format hostname:port')
    parser.add_argument('--host', default='127.0.0.1',
                        help='Hostname or IP to listen for connections on.')
    parser.add_argument('--port', type=int, default=8080,
                        help='Port to listen for connections on.')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help="Add verbose output")
    args = parser.parse_args()

    proxy_host, proxy_port = args.proxy.split(':')
    print(''.join("Initiating proxy. Listening and forwarding on:\n"
                  "{}:{}->{}:{}\n".format(args.host, args.port,
                                          proxy_host, proxy_port)))
    proxy = NegotiateProxy((args.host, args.port), (proxy_host, proxy_port),
                           verbose=args.verbose)
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        # Ctrl-C to end the proxy server gracefully
        if not proxy.closed:
            proxy.close()
        sys.exit('Closing Proxy server.')
