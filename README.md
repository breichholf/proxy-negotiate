# Proxy-Negotiate


[![MIT license](http://img.shields.io/badge/license-MIT-yellowgreen.svg)](http://opensource.org/licenses/MIT)

**Refactored to provide functionality for windows and include best-practice
`setuptools`.**

A thin transparent proxy that handles kerberos-based Proxy authentification,
for applications that cannot do that themselves. Most notably, this is
needed for wide-spread applications such as SSH, Telnet, the python `requests` 
package (and by extension `conda`) when used behind a proxy server, requiring
kerberos/GSSAPI/SPNEGO authentication. 

## Requirements

* `winkerberos` (for Windows/Kerberos authentication)
* `gevent`


## Installation

To install this forked repo with pip, you use the following command:

```bash
$ pip install git+https://github.com/breichholf/proxy-negotiate
```

Or alternatively download and build it yourself:

```bash
$ git clone https://github.com/breichholf/proxy-negotiate
$ cd proxy-negotiate
$ python setup.py install
```

# Usage
You will need to be a member of a domain for Negotiate authentication to work.
On Windows, you will need to be running a Kerberos ticket manager. Authentication
should be handled transparently from there on out.

## proxy-negotiate
While running, this provides a transparent proxy from `listen_host` (usually
`localhost`/`127.0.0.1`, but if you have multiple IP addresses any local IP
could make sense) and `listen_port` (default: `8080`).
You can then use `http://localhost:8080` as proxy for your desired application.

```
$ proxy-negotiate PROXY_HOST:PROXY_PORT [listen_host:127.0.0.1] [listen_port:8080]
```

Using proxy in `requests`:

```python
import requests
PROXY = dict(http="http://127.0.0.1:8080",
             https="http://127.0.0.1:8080")
r = requests.get("http://www.example.org", proxies=PROXY)
``` 

## nc-negotiate
A `netcat`-like implementation for use with programs such as SSH and Telnet:

```bash
$ nc-negotiate HOST:PORT [PROXY_HOST:PROXY_PORT]
```

Moreover, `nc-negotiate` can now be used as `ProxyCommand` with OpenSSH and others.

```bash
$ ssh -o ProxyCommand="nc-negotiate %h:%p" myexternalhost.com
```

This can also be added to your `~/.ssh/config` to provide the functionality on
a per host basis:

```
  Host myexternalhost.com:
      ProxyCommand nc-negotiate %h:%p
```