import sys
import base64
import gevent

from logging import getLogger
from gevent.server import StreamServer
from gevent.socket import create_connection

from ._tools import simple_log, proxy_forward

if sys.platform == 'win32':
    import winkerberos as kerberos
else:
    import gssapi

logger = getLogger(__name__)


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

        simple_log(f'{addr[0]}:{addr[1]} accepted')
        if sys.platform == 'win32':
            status, ctx = kerberos.authGSSClientInit(f'HTTP@{self.upstream[0]}')
            # gssflags=0,
            # mech_oid=kerberos.GSS_MECH_OID_SPNEGO)
            _ = kerberos.authGSSClientStep(ctx, '')
            krb_token = kerberos.authGSSClientResponse(ctx)
        else:
            service = gssapi.Name(f'HTTP@{self.upstream[0]}',
                                  gssapi.NameType.hostbased_service)
            ctx = gssapi.SecurityContext(name=service, usage='initiate')
            token = ctx.step()
            krb_token = base64.b64encode(token)

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

        forwarders = (gevent.spawn(proxy_forward, src, dst, self),
                      gevent.spawn(proxy_forward, dst, src, self))

        gevent.joinall(forwarders)

    def close(self):
        if self.closed:
            sys.exit('Multiple exit signals received - aborting.')
        else:
            simple_log('Closing listener socket')
            StreamServer.close(self)
