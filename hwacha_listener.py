import argparse
import sys
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ThreadingMixIn
from urlparse import urlparse

CRED = '\033[91m'
CEND = '\033[0m'
CGREEN = '\33[32m'
CYELLOW = '\33[33m'


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        """Serve a GET request."""
        SimpleHTTPRequestHandler.do_GET(self)
        return

    def url_parse(self):
        query = urlparse(self.path).query
        query_components = dict(qc.split("=") for qc in query.split("&"))
        return query_components


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    pass


def banner():
    art = CGREEN + """
 _____                                                       _       
/  ___|                                                     (_)      
\ `--.  ___ _ ____   _____ _ __ _ __   ___ _ __   __ _ _   _ _ _ __  
 `--. \/ _ \ '__\ \ / / _ \ '__| '_ \ / _ \ '_ \ / _` | | | | | '_ \ 
/\__/ /  __/ |   \ V /  __/ |  | |_) |  __/ | | | (_| | |_| | | | | |
\____/ \___|_|    \_/ \___|_|  | .__/ \___|_| |_|\__, |\__,_|_|_| |_|
                               | |                __/ |              
                               |_|               |___/               
""" + CEND
    return art


def help():
    print CGREEN + 'Usage: hwacha_listener.py [-h] -a ADDRESS -p PORT'
    print CRED + 'Example usage:' + CEND
    print CYELLOW + 'python hwacha_listener.py -a 0.0.0.0 -p 8080' + CEND
    print CRED + 'For further explanation use:' + CEND
    print CYELLOW + 'python hwacha_listener.py -h'


def main():
    print banner()
    parser = argparse.ArgumentParser(
        description='A separated, decoupled listener for Mimipenguin')
    parser.add_argument('-a', '--address', help='Listening host IP address', required=False, default=False)
    parser.add_argument('-p', '--port', help='Port for the listener', required=False, default=False)
    args = parser.parse_args()
    if not args or not args.address or not args.port:
        help()
        sys.exit()
    server = ThreadedHTTPServer((args.address, int(args.port)), Handler)
    print 'Starting server, use <Ctrl-C> to stop'
    server.serve_forever()


if __name__ == '__main__':
    main()
