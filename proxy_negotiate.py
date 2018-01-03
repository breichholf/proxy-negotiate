import base64
import gevent
import winkerberos as kerberos
import os
import socket
import sys

from logging import getLogger
from gevent.server import StreamServer
from gevent.socket import create_connection, wait_read

logger = getLogger(__name__)

__version__ = '1.0.0'

def forward(src, dst):
    try:
        while True:
            data = src.recv(1024)
            if not data:
                break
            dst.sendall(data)
    finally:
        src.close()


class NegotiateProxy(StreamServer):
    def __init__(self, listener, upstream, **kwargs):
        super(NegotiateProxy, self).__init__(listener, **kwargs)

        self.upstream = upstream

    def handle(self, src, addr):
        data = b''
        while True:
            data += src.recv(1024)
            if b'\r\n\r\n' in data:
                break

        status, ctx = kerberos.authGSSClientInit('HTTP/%s' % self.upstream[0], gssflags=0, mech_oid=kerberos.GSS_MECH_OID_KRB5)
        status = kerberos.authGSSClientStep(ctx, "")
        b64token = kerberos.authGSSClientResponse(ctx)

        headers, data = data.split(b'\r\n\r\n', 1)
        headers = headers.split('\r\n')

        replaced = False
        for i, header in enumerate(headers):
            if header.startswith('Proxy-Authorization:'):
                headers[i] = b'Proxy-Authorization: Negotiate %s' % b64token
                replaced = True
                break

        if not replaced:
            headers.append(b'Proxy-Authorization: Negotiate %s' % b64token)

        dst = create_connection(self.upstream)
        dst.sendall(b'\r\n'.join(headers) + b'\r\n\r\n' + data)

        forwarders = (gevent.spawn(forward, src, dst),
                      gevent.spawn(forward, dst, src))

        gevent.joinall(forwarders)

