"""proxy-negotiate
Thin transparent proxy, for apps that don't support proxy-negotiation
"""
__author__ = "Brian Reichholf"
__email__ = "brian.reichholf@gmail.com"

from ._proxy import NegotiateProxy

try:
    from ._proxy import __version__
except ImportError:
    __version__ = None
