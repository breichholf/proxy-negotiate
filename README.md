# Proxy-Negotiate

[![MIT license](http://img.shields.io/badge/license-MIT-yellowgreen.svg)](http://opensource.org/licenses/MIT)

**This has been completely rewritten as of version 1.0.0.**

A thin transparent proxy that handles kerberos-based Proxy authentification,
for applications that cannot do that themselves. Most notably, this is
needed for wide-spread applications such as SSH, Telnet, the python `requests` 
package (and by extension `conda`) when used behind a proxy server, requiring
kerberos/GSSAPI/SPNEGO authentication. 

## Requirements


* `winkerberos` (for Windows/Kerberos authentication)
* `gevent`


## Installation

Install the easy way through PyPi:

```
$ pip install proxy-negotiate
```

Or alternatively download and build yourself:

```
$ git clone https://github.com/cour4g3/proxy-negotiate
$ cd proxy-negotiate
$ python setup.py install
```

# Usage
You will need to be a member of a domain for Negotiate authentication to work.
On Windows, you will need to be running a Kerberos ticket manager. Authentication
should be handled transparently from there on out. 

## proxy-negotiate
While running, this provides a transparent proxy from `listen_host` (usually
`localhost`, but any local IP could make sense) and `listen_port` (default:
`8080`). You can then use `http://localhost:8080` as proxy for your desired
application.

```
$ proxy-negotiate proxy_host proxy_port [listen_host:127.0.0.1] [listen_port:8080]
```

Using proxy in `requests`:

```python
import requests
proxy = dict(http="http://127.0.0.1:8080",
             https="http://127.0.0.1:8080")
r = requests.get("http://www.example.org", proxies=proxy)
``` 

## nc-negotiate
A netcat-like implementation for use with programs such as SSH and Telnet:

```
$ nc-negotiate host port [proxy_host] [proxy_port]
```

Example of usage with OpenSSH command line:

```
$ ssh -o ProxyCommand="nc-negotiate %h %p" myexternalhost.com
```

Or in your `~/.ssh/config`:

```
  Host myexternalhost.com:
      ProxyCommand nc-negotiate %h %p
```

