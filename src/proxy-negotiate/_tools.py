import sys


def simple_log(message, *args):
    message = message % args
    sys.stderr.write(message + '\n')


def proxy_forward(src, dst, server):
    try:
        while True:
            data = src.recv(1024)
            if not data:
                break
            dst.sendall(data)
    finally:
        src.close()
