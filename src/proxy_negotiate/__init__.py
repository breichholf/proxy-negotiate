"""proxy_negotiate
Thin transparent proxy, for apps that don't support Authentication via
Proxy Negotiation
"""
__author__ = "Brian Reichholf"
__email__ = "brian.reichholf@gmail.com"

import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

from ._proxy import NegotiateProxy
from ._netcat import netcat
from ._tools import (get_krb_token, proxy_forward,
                     nc_forward_stdin, nc_forward_stdout,
                     proxy_host_from_env, proxy_port_from_env)

try:
    from ._version import __version__
except ImportError:
    __version__ = None
