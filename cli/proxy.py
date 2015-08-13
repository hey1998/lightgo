#!/usr/bin/env python

import sys
import os
import glob

import errno
import time
import struct
import collections
import zlib
import functools
import re
import io
import copy
import fnmatch
import traceback
import random
import base64
import hashlib
import threading
import socket
import ssl
import select

try:
    import queue
except ImportError:
    import Queue as queue
try:
    import socketserver
except ImportError:
    import SocketServer as socketserver
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
try:
    import http.server
    import http.client
except ImportError:
    http = type(sys)('http')
    http.server = __import__('BaseHTTPServer')
    http.client = __import__('httplib')
    http.client.parse_headers = http.client.HTTPMessage
try:
    import urllib.request
    import urllib.parse
except ImportError:
    import urllib
    urllib.request = __import__('urllib2')
    urllib.parse = __import__('urlparse')
try:
    import ctypes
except ImportError:
    ctypes = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

class CertUtil(object):
    ca_vendor = 'GoAgent'
    ca_keyfile = 'CA.crt'
    ca_certdir = 'certs'
    ca_lock = threading.Lock()

    @staticmethod
    def create_ca():
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
        ca = OpenSSL.crypto.X509()
        ca.set_serial_number(0)
        ca.set_version(2)
        subj = ca.get_subject()
        subj.commonName = '%s CA' % CertUtil.ca_vendor
        ca.gmtime_adj_notBefore(0)
        ca.gmtime_adj_notAfter(24 * 60 * 60 * 3652)
        ca.set_issuer(ca.get_subject())
        ca.set_pubkey(key)
        ca.add_extensions([OpenSSL.crypto.X509Extension(b'nsCertType', True, b'sslCA')])
        ca.sign(key, 'sha1')
        return key, ca

    @staticmethod
    def dump_ca():
        key, ca = CertUtil.create_ca()
        try:
            fp = open(CertUtil.ca_keyfile, 'wb')
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        except Exception, e:
            print e

    @staticmethod
    def _get_cert(commonname):
        try:
            fp = open(CertUtil.ca_keyfile, 'rb')
            content = fp.read()
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
        except Exception, e:
            print e

        pkey = OpenSSL.crypto.PKey()
        pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

        req = OpenSSL.crypto.X509Req()
        subj = req.get_subject()
        subj.commonName = commonname
        req.set_pubkey(pkey)
        req.sign(pkey, 'sha1')

        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(int(hashlib.md5(commonname).hexdigest(), 16))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 3652)
        cert.set_issuer(ca.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.sign(key, 'sha1')

        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        try:
            fp = open(certfile, 'wb')
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey))
        except Exception, e:
            print e
        return certfile

    @staticmethod
    def get_cert(commonname):
        certfile = os.path.join(CertUtil.ca_certdir, commonname + '.crt')
        if os.path.exists(certfile):
            return certfile
        else:
            return CertUtil._get_cert(commonname)

    @staticmethod
    def check_ca():
        #Check CA exists
        capath = os.path.join(os.path.dirname(os.path.abspath(__file__)), CertUtil.ca_keyfile)
        certdir = os.path.join(os.path.dirname(__file__), CertUtil.ca_certdir)
        if not os.path.exists(capath):
            if not OpenSSL:
                print 'CA.key is not exist and OpenSSL is disabled, ABORT!'
                sys.exit(-1)
            CertUtil.dump_ca()
        if not os.path.exists(certdir):
            os.makedirs(certdir)

class SSLConnection(object):
    """wrapper for python2 OpenSSL.SSL.Connection"""

    def __init__(self, context, sock):
        self._context = context
        self._sock = sock
        self._timeout = sock.gettimeout()
        self._connection = OpenSSL.SSL.Connection(context, sock)
        self._makefile_refs = 0

    def __getattr__(self, attr):
        if attr not in ('_context', '_sock', '_timeout', '_connection'):
            return getattr(self._connection, attr)

    def accept(self):
        sock, addr = self._sock.accept()
        client = SSLConnection(sock._context, sock)
        return client, addr

    def do_handshake(self):
        waited = 0
        ticker = 1.0
        while True:
            try:
                self._connection.do_handshake()
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError, OpenSSL.SSL.WantWriteError):
                sys.exc_clear()
                select.select([self._connection], [], [], ticker)
                waited += ticker
                if self._timeout and waited > self._timeout:
                    raise socket.timeout('timed out')

    def connect(self, address, **kwargs):
        waited = 0
        ticker = 1.0
        while True:
            try:
                self._connection.connect(address, **kwargs)
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                select.select([self._connection], [], [], ticker)
                waited += ticker
                if self._timeout and waited > self._timeout:
                    raise socket.timeout('timed out')
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                select.select([], [self._connection], [], ticker)
                waited += ticker
                if self._timeout and waited > self._timeout:
                    raise socket.timeout('timed out')

    def send(self, data, flags=0):
        waited = 0
        ticker = 1.0
        while True:
            try:
                self._connection.send(data, flags)
                break
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                select.select([self._connection], [], [], ticker)
                waited += ticker
                if self._timeout and waited > self._timeout:
                    raise socket.timeout('timed out')
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                select.select([], [self._connection], [], ticker)
                waited += ticker
                if self._timeout and waited > self._timeout:
                    raise socket.timeout('timed out')
            except OpenSSL.SSL.SysCallError, e:
                if e[0] == -1 and not data:
                    # errors when writing empty strings are expected and can be ignored
                    return 0
                raise

    def recv(self, bufsiz, flags=0):
        waited = 0
        ticker = 1.0
        pending = self._connection.pending()
        if pending:
            return self._connection.recv(min(pending, bufsiz))
        while True:
            try:
                return self._connection.recv(bufsiz, flags)
            except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantX509LookupError):
                sys.exc_clear()
                select.select([self._connection], [], [], ticker)
                waited += ticker
                if self._timeout and waited > self._timeout:
                    raise socket.timeout('timed out')
            except OpenSSL.SSL.WantWriteError:
                sys.exc_clear()
                select.select([], [self._connection], [], ticker)
                waited += ticker
                if self._timeout and waited > self._timeout:
                    raise socket.timeout('timed out')
            except OpenSSL.SSL.ZeroReturnError:
                return

    def read(self, bufsiz, flags=0):
        return self.recv(bufsiz, flags)

    def write(self, buf, flags=0):
        return self.sendall(buf, flags)

    def makefile(self, mode='rb', bufsize=-1):
        self._makefile_refs += 1
        return socket._fileobject(self, mode, bufsize, close=True)

    def close(self):
        if self._makefile_refs < 1:
            self._connection.shutdown()
            del self._connection
        else:
            self._makefile_refs -= 1


class HTTPUtil(object):
    """HTTP Request Class"""

    protocol_version = 'HTTP/1.1'
    skip_headers = frozenset(['Vary', 'Via', 'X-Forwarded-For', 'Proxy-Authorization', 'Proxy-Connection', 'Upgrade', 'X-Chrome-Variations', 'Connection', 'Cache-Control'])
    ssl_validate = False
    ssl_obfuscate = False

    def __init__(self, max_window=4, max_timeout=16, max_retry=4, proxy='', ssl_validate=False, ssl_obfuscate=False):
        self.max_window = max_window
        self.max_retry = max_retry
        self.max_timeout = max_timeout
        self.tcp_connection_time = collections.defaultdict(float)
        self.ssl_connection_time = collections.defaultdict(float)
        self.dns = {}
        self.crlf = 0
        self.ssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        self.wrap_socket = self.pyopenssl_wrap_socket

    def pyopenssl_wrap_socket(self, sock, **kwargs):
        connection = SSLConnection(self.ssl_context, sock)
        if kwargs.get('server_side', False):
            connection.set_accept_state()
        else:
            connection.set_connect_state()
        server_hostname = kwargs.get('server_hostname')
        if server_hostname:
            connection.set_tlsext_host_name(server_hostname.encode())
        if kwargs.get('do_handshake_on_connect', True):
            connection.do_handshake()
        return connection

    def dns_resolve(self, host, dnsserver='', ipv4_only=True):
        return self.dns.get(host)

    def create_connection(self, address, timeout=None, source_address=None):
        def _create_connection(address, timeout, queobj):
            sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in address[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                sock.connect(address)
                # record TCP connection time
                self.tcp_connection_time[address] = time.time() - start_time
                # put ssl socket object to output queobj
                queobj.put(sock)
            except Exception, e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the address
                self.tcp_connection_time[address] = self.max_timeout+random.random()
                # close tcp socket
                if sock:
                    sock.close()

        def _close_connection(count, queobj):
            for i in range(count):
                queobj.get()
        host, port = address
        result = None
        addresses = [(x, port) for x in self.dns_resolve(host)]
        if port == 443:
            get_connection_time = lambda addr: self.ssl_connection_time.__getitem__(addr) or self.tcp_connection_time.__getitem__(addr)
        else:
            get_connection_time = self.tcp_connection_time.__getitem__
        for i in range(self.max_retry):
            window = min((self.max_window+1)/2 + i, len(addresses))
            addresses.sort(key=get_connection_time)
            addrs = addresses[:window] + random.sample(addresses, window)
            queobj = queue.Queue()
            for addr in addrs:
                threading._start_new_thread(_create_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, (socket.error, ssl.SSLError, OSError)):
                    threading._start_new_thread(_close_connection, (len(addrs)-i-1, queobj))
                    return result
                else:
                    if i == 0:
                        # only output first error
                        print 'create_connection to %s return %r, try again.' % (addrs, result)

    def create_ssl_connection(self, address, timeout=None, source_address=None):
        def _create_ssl_connection(ipaddr, timeout, queobj):
            sock = None
            ssl_sock = None
            try:
                # create a ipv4/ipv6 socket object
                sock = socket.socket(socket.AF_INET if ':' not in ipaddr[0] else socket.AF_INET6)
                # set reuseaddr option to avoid 10048 socket error
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # resize socket recv buffer 8K->32K to improve browser releated application performance
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32*1024)
                # disable negal algorithm to send http request quickly.
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, True)
                # set a short timeout to trigger timeout retry more quickly.
                sock.settimeout(timeout or self.max_timeout)
                # pick up the certificate
                server_hostname = 'www.google.com' if address[0].endswith('.appspot.com') else None
                ssl_sock = self.wrap_socket(sock, do_handshake_on_connect=False, server_hostname=server_hostname)
                ssl_sock.settimeout(timeout or self.max_timeout)
                # start connection time record
                start_time = time.time()
                # TCP connect
                ssl_sock.connect(ipaddr)
                connected_time = time.time()
                # SSL handshake
                ssl_sock.do_handshake()
                handshaked_time = time.time()
                # record TCP connection time
                self.tcp_connection_time[ipaddr] = connected_time - start_time
                # record SSL connection time
                self.ssl_connection_time[ipaddr] = handshaked_time - start_time
                # sometimes, we want to use raw tcp socket directly(select/epoll), so setattr it to ssl socket.
                ssl_sock.sock = sock
                # verify SSL certificate.
                if self.ssl_validate and address[0].endswith('.appspot.com'):
#                    if hasattr(ssl_sock, 'get_peer_certificate'):
#                        cert = ssl_sock.get_peer_certificate()
#                        commonname = next((v for k, v in cert.get_subject().get_components() if k == 'CN'))
#                    elif hasattr(ssl_sock, 'getpeercert'):
#                        cert = ssl_sock.getpeercert()
#                        commonname = next((v for ((k, v),) in cert['subject'] if k == 'commonName'))
                    if '.google' not in commonname and not commonname.endswith('.appspot.com'):
                        raise ssl.SSLError("Host name '%s' doesn't match certificate host '%s'" % (address[0], commonname))
                # put ssl socket object to output queobj
                queobj.put(ssl_sock)
            except Exception, e:
                # any socket.error, put Excpetions to output queobj.
                queobj.put(e)
                # reset a large and random timeout to the ipaddr
                self.ssl_connection_time[ipaddr] = self.max_timeout + random.random()
                # close ssl socket
                if ssl_sock:
                    ssl_sock.close()
                # close tcp socket
                if sock:
                    sock.close()

        def _close_ssl_connection(count, queobj):
            for i in range(count):
                queobj.get()
        host, port = address
        result = None
        addresses = [(x, port) for x in self.dns_resolve(host)]
        for i in range(self.max_retry):
            window = min((self.max_window+1)/2 + i, len(addresses))
            addresses.sort(key=self.ssl_connection_time.__getitem__)
            addrs = addresses[:window] + random.sample(addresses, window)
            queobj = queue.Queue()
            for addr in addrs:
                threading._start_new_thread(_create_ssl_connection, (addr, timeout, queobj))
            for i in range(len(addrs)):
                result = queobj.get()
                if not isinstance(result, (socket.error, ssl.SSLError, OSError)):
                    threading._start_new_thread(_close_ssl_connection, (len(addrs)-i-1, queobj))
                    return result
                else:
                    if i == 0:
                        # only output first error
                        print 'create_ssl_connection to %s return %r, try again.' % (addrs, result)

    def create_connection_withproxy(self, address, timeout=None, source_address=None, proxy=None):
        assert isinstance(proxy, str)
        host, port = address
        print 'create_connection_withproxy connect (%r, %r)' % (host, port)
#        scheme, username, password, address = ProxyUtil.parse_proxy(proxy or self.proxy)
        try:
            try:
                self.dns_resolve(host)
            except (socket.error, ssl.SSLError, OSError):
                pass
            proxyhost, _, proxyport = address.rpartition(':')
            sock = socket.create_connection((proxyhost, int(proxyport)))
            hostname = random.choice(self.dns.get(host) or [host if not host.endswith('.appspot.com') else 'www.google.com'])
            request_data = 'CONNECT %s:%s HTTP/1.1\r\n' % (hostname, port)
#            if username and password:
#                request_data += 'Proxy-authorization: Basic %s\r\n' % base64.b64encode(('%s:%s' % (username, password)).encode()).strip().decode()
            request_data += '\r\n'
            sock.sendall(request_data)
            response = http.client.HTTPResponse(sock)
            response.begin()
            if response.status >= 400:
                print 'create_connection_withproxy return http error code %s' % (response.status)
                sock = None
            return sock
        except Exception, e:
            print 'create_connection_withproxy error %s' % e
            raise

    def forward_socket(self, local, remote, timeout=60, tick=2, bufsize=8192, maxping=None, maxpong=None, pongcallback=None, bitmask=None):
        try:
            timecount = timeout
            while 1:
                timecount -= tick
                if timecount <= 0:
                    break
                (ins, _, errors) = select.select([local, remote], [], [local, remote], tick)
                if errors:
                    break
                if ins:
                    for sock in ins:
                        data = sock.recv(bufsize)
                        if bitmask:
                            data = ''.join(chr(ord(x) ^ bitmask) for x in data)
                        if data:
                            if sock is remote:
                                local.sendall(data)
                                timecount = maxpong or timeout
                                if pongcallback:
                                    try:
                                        pongcallback()
                                    except Exception, e:
                                        print 'remote=%s pongcallback=%s failed: %s' % (remote, pongcallback, e)
                                    finally:
                                        pongcallback = None
                            else:
                                remote.sendall(data)
                                timecount = maxping or timeout
                        else:
                            return
        except Exception, e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.ENOTCONN, errno.EPIPE):
                raise
        finally:
            if local:
                local.close()
            if remote:
                remote.close()

    def _request(self, sock, method, path, protocol_version, headers, payload, bufsize=8192, crlf=None, return_sock=None):
        skip_headers = self.skip_headers
        need_crlf = http_util.crlf
        if crlf:
            need_crlf = 1
        if need_crlf:
            request_data = 'GET / HTTP/1.1\r\n\r\n'
        else:
            request_data = ''
        request_data += '%s %s %s\r\n' % (method, path, protocol_version)
        request_data += ''.join('%s: %s\r\n' % (k, v) for k, v in headers.items() if k not in skip_headers)
#        if self.proxy:
#            _, username, password, _ = ProxyUtil.parse_proxy(self.proxy)
#            if username and password:
#                request_data += 'Proxy-Authorization: Basic %s\r\n' % base64.b64encode('%s:%s' % (username, password))
        request_data += '\r\n'

        if isinstance(payload, bytes):
            sock.sendall(request_data.encode() + payload)
        elif hasattr(payload, 'read'):
            sock.sendall(request_data.encode())
            while 1:
                data = payload.read(bufsize)
                if not data:
                    break
                sock.sendall(data)
        else:
            raise TypeError('http_util.request(payload) must be a string or buffer, not %r' % type(payload))

        if need_crlf:
            try:
                response = http.client.HTTPResponse(sock)
                response.begin()
                response.read()
            except Exception:
                print 'crlf skip read'
                return None

        if return_sock:
            return sock

        response = http.client.HTTPResponse(sock)
        try:
            response.begin()
        except http.client.BadStatusLine:
            response = None
        return response

    def request(self, method, url, payload=None, headers={}, realhost='', fullurl=False, bufsize=8192, crlf=None, return_sock=None):
        scheme, netloc, path, params, query, fragment = urllib.parse.urlparse(url)
        if netloc.rfind(':') <= netloc.rfind(']'):
            # no port number
            host = netloc
            port = 443 if scheme == 'https' else 80
        else:
            host, _, port = netloc.rpartition(':')
            port = int(port)
        path += '?' + query

        if 'Host' not in headers:
            headers['Host'] = host

        for i in range(self.max_retry):
            sock = None
            ssl_sock = None
            try:
                if scheme == 'https':
                    ssl_sock = self.create_ssl_connection((realhost or host, port), self.max_timeout)
                    if ssl_sock:
                        sock = ssl_sock.sock
                        del ssl_sock.sock
                    else:
                        raise socket.error('timed out', 'create_ssl_connection(%r,%r)' % (realhost or host, port))
                else:
                    sock = self.create_connection((realhost or host, port), self.max_timeout)

                if sock:
                    if scheme == 'https':
                        crlf = 0
                    return self._request(ssl_sock or sock, method, path, self.protocol_version, headers, payload, bufsize=bufsize, crlf=crlf, return_sock=return_sock)

            except Exception, e:
                print 'request "%s %s" failed:%s' % (method, url, e)
                if ssl_sock:
                    ssl_sock.close()
                if sock:
                    sock.close()
                if i == self.max_retry - 1:
                    raise
                else:
                    continue


class Common(object):
    """Global Config Object"""

    def __init__(self):

        """load configure"""
        configparser.RawConfigParser.OPTCRE = re.compile(r'(?P<option>[^=\s][^=]*)\s*(?P<vi>[=])\s*(?P<value>.*)$')
        self.CONFIG = configparser.ConfigParser()
        self.CONFIG.read('config.ini')

        self.LISTEN_IP = self.CONFIG.get('listen', 'ip')
        self.LISTEN_PORT = self.CONFIG.getint('listen', 'port')

        self.GAE_APPIDS = re.findall('[\w\-\.]+', self.CONFIG.get('gae', 'appid').replace('.appspot.com', ''))
        self.GAE_PASSWORD = self.CONFIG.get('gae', 'password').strip()
        self.GAE_PATH = self.CONFIG.get('gae', 'path')
        self.GAE_PROFILE = self.CONFIG.get('gae', 'profile')
        self.GAE_CRLF = self.CONFIG.getint('gae', 'crlf')
        self.GAE_VALIDATE = self.CONFIG.getint('gae', 'validate')
        self.GAE_OBFUSCATE = self.CONFIG.getint('gae', 'obfuscate') if self.CONFIG.has_option('gae', 'obfuscate') else 0

        self.GOOGLE_MODE = self.CONFIG.get(self.GAE_PROFILE, 'mode')
        self.GOOGLE_WINDOW = self.CONFIG.getint(self.GAE_PROFILE, 'window') if self.CONFIG.has_option(self.GAE_PROFILE, 'window') else 4
        self.GOOGLE_HOSTS = [x for x in self.CONFIG.get(self.GAE_PROFILE, 'hosts').split('|') if x]
        self.GOOGLE_SITES = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'sites').split('|') if x)
        self.GOOGLE_FORCEHTTPS = tuple('http://'+x for x in self.CONFIG.get(self.GAE_PROFILE, 'forcehttps').split('|') if x)
        self.GOOGLE_WITHGAE = tuple(x for x in self.CONFIG.get(self.GAE_PROFILE, 'withgae').split('|') if x)

        self.AUTORANGE_MAXSIZE = self.CONFIG.getint('autorange', 'maxsize')
        self.AUTORANGE_WAITSIZE = self.CONFIG.getint('autorange', 'waitsize')
        self.AUTORANGE_BUFSIZE = self.CONFIG.getint('autorange', 'bufsize')
        self.AUTORANGE_THREADS = self.CONFIG.getint('autorange', 'threads')

        self.FETCHMAX_LOCAL = self.CONFIG.getint('fetchmax', 'local') if self.CONFIG.get('fetchmax', 'local') else 3
#        self.FETCHMAX_SERVER = self.CONFIG.get('fetchmax', 'server')

        self.USERAGENT_ENABLE = self.CONFIG.getint('useragent', 'enable')
        self.USERAGENT_STRING = self.CONFIG.get('useragent', 'string')

        random.shuffle(self.GAE_APPIDS)
        self.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (self.GOOGLE_MODE, self.GAE_APPIDS[0], self.GAE_PATH)

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'GoAgent Version    : special (python/%s pyopenssl/%s)\n' % (sys.version[:5], getattr(OpenSSL, '__version__', 'Disabled'))
        info += 'Listen Address     : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'GAE Mode           : %s\n' % self.GOOGLE_MODE
        info += 'GAE Profile        : %s\n' % self.GAE_PROFILE
        info += 'GAE APPID          : %s\n' % '|'.join(self.GAE_APPIDS)
        info += '------------------------------------------------------\n'
        return info

common = Common()
http_util = HTTPUtil(max_window=common.GOOGLE_WINDOW, ssl_validate=common.GAE_VALIDATE, ssl_obfuscate=common.GAE_OBFUSCATE)


def message_html(self, title, banner, detail=''):
    MESSAGE_TEMPLATE = '''
    <html><head>
    <meta http-equiv="content-type" content="text/html;charset=utf-8">
    <title>{{ title }}</title>
    <style><!--
    body {font-family: arial,sans-serif}
    div.nav {margin-top: 1ex}
    div.nav A {font-size: 10pt; font-family: arial,sans-serif}
    span.nav {font-size: 10pt; font-family: arial,sans-serif; font-weight: bold}
    div.nav A,span.big {font-size: 12pt; color: #0000cc}
    div.nav A {font-size: 10pt; color: black}
    A.l:link {color: #6f6f6f}
    A.u:link {color: green}
    //--></style>
    </head>
    <body text=#000000 bgcolor=#ffffff>
    <table border=0 cellpadding=2 cellspacing=0 width=100%>
    <tr><td bgcolor=#3366cc><font face=arial,sans-serif color=#ffffff><b>Message</b></td></tr>
    <tr><td> </td></tr></table>
    <blockquote>
    <H1>{{ banner }}</H1>
    {{ detail }}
    <p>
    </blockquote>
    <table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
    </body></html>
    '''
    kwargs = dict(title=title, banner=banner, detail=detail)
    template = MESSAGE_TEMPLATE
    for keyword, value in kwargs.items():
        template = template.replace('{{ %s }}' % keyword, value)
    return template


def gae_urlfetch(method, url, headers, payload, fetchserver, **kwargs):
    assert isinstance(payload, bytes)
    if payload:
        if len(payload) < 10 * 1024 * 1024 and 'Content-Encoding' not in headers:
            zpayload = zlib.compress(payload)[2:-4]
            if len(zpayload) < len(payload):
                payload = zpayload
                headers['Content-Encoding'] = 'deflate'
        headers['Content-Length'] = str(len(payload))
    # GAE donot allow set `Host` header
    if 'Host' in headers:
        del headers['Host']
    metadata = 'G-Method:%s\nG-Url:%s\n%s' % (method, url, ''.join('G-%s:%s\n' % (k, v) for k, v in kwargs.items() if v))
    skip_headers = http_util.skip_headers
    metadata += ''.join('%s:%s\n' % (k.title(), v) for k, v in headers.items() if k not in skip_headers)
    metadata = zlib.compress(metadata.encode())[2:-4]
    need_crlf = 0 if fetchserver.startswith('https') else common.GAE_CRLF
    if common.GAE_OBFUSCATE:
        cookie = base64.b64encode(metadata).strip().decode()
        if not payload:
            response = http_util.request('GET', fetchserver, payload, {'Cookie': cookie}, crlf=need_crlf)
        else:
            response = http_util.request('POST', fetchserver, payload, {'Cookie': cookie, 'Content-Length': str(len(payload))}, crlf=need_crlf)
    else:
        payload = b''.join((struct.pack('!h', len(metadata)), metadata, payload))
        response = http_util.request('POST', fetchserver, payload, {'Content-Length': str(len(payload))}, crlf=need_crlf)
    response.app_status = response.status
    if response.status != 200:
        if response.status in (400, 405):
            # filter by some firewall
            common.GAE_CRLF = 0
        return response
    data = response.read(4)
    if len(data) < 4:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short leadtype data=' + data)
        return response
    response.status, headers_length = struct.unpack('!hh', data)
    data = response.read(headers_length)
    if len(data) < headers_length:
        response.status = 502
        response.fp = io.BytesIO(b'connection aborted. too short headers data=' + data)
        return response
    response.headers = response.msg = http.client.parse_headers(io.BytesIO(zlib.decompress(data, -zlib.MAX_WBITS)))
    return response


class RangeFetch(object):
    """Range Fetch Class"""

    maxsize = 1024*1024*4
    bufsize = 8192
    threads = 1
    waitsize = 1024*512
    urlfetch = staticmethod(gae_urlfetch)

    def __init__(self, wfile, response, method, url, headers, payload, fetchservers, password, maxsize=0, bufsize=0, waitsize=0, threads=0):
        self.wfile = wfile
        self.response = response
        self.command = method
        self.url = url
        self.headers = headers
        self.payload = payload
        self.fetchservers = fetchservers
        self.password = password
        self.maxsize = maxsize or self.__class__.maxsize
        self.bufsize = bufsize or self.__class__.bufsize
        self.waitsize = waitsize or self.__class__.bufsize
        self.threads = threads or self.__class__.threads
        self._stopped = None
        self._last_app_status = {}

    def fetch(self):
        response_status = self.response.status
        response_headers = dict((k.title(), v) for k, v in self.response.getheaders())
        content_range = response_headers['Content-Range']
        #content_length = response_headers['Content-Length']
        start, end, length = list(map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3)))
        if start == 0:
            response_status = 200
            response_headers['Content-Length'] = str(length)
        else:
            response_headers['Content-Range'] = 'bytes %s-%s/%s' % (start, end, length)
            response_headers['Content-Length'] = str(length-start)

        print '>>>>>>>>>>>>>>> RangeFetch started(%r) %d-%d' % (self.url, start, end)
        self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response_status, ''.join('%s: %s\r\n' % (k, v) for k, v in response_headers.items()))).encode())

        data_queue = queue.PriorityQueue()
        range_queue = queue.PriorityQueue()
        range_queue.put((start, end, self.response))
        for begin in range(end+1, length, self.maxsize):
            range_queue.put((begin, min(begin+self.maxsize-1, length-1), None))
        for i in range(self.threads):
            threading._start_new_thread(self.__fetchlet, (range_queue, data_queue))
        has_peek = hasattr(data_queue, 'peek')
        peek_timeout = 90
        expect_begin = start
        while expect_begin < length-1:
            try:
                if has_peek:
                    begin, data = data_queue.peek(timeout=peek_timeout)
                    if expect_begin == begin:
                        data_queue.get()
                    elif expect_begin < begin:
                        time.sleep(0.1)
                        continue
                    else:
                        print 'RangeFetch Error: begin(%r) < expect_begin(%r), quit.' % (begin, expect_begin)
                        break
                else:
                    begin, data = data_queue.get(timeout=peek_timeout)
                    if expect_begin == begin:
                        pass
                    elif expect_begin < begin:
                        data_queue.put((begin, data))
                        time.sleep(0.1)
                        continue
                    else:
                        print 'RangeFetch Error: begin(%r) < expect_begin(%r), quit.' % (begin, expect_begin)
                        break
            except queue.Empty:
                print 'data_queue peek timeout, break'
                break
            try:
                self.wfile.write(data)
                expect_begin += len(data)
            except (socket.error, ssl.SSLError, OSError) as e:
                print 'RangeFetch client connection aborted(%s).' % e
                break
        self._stopped = True

    def __fetchlet(self, range_queue, data_queue):
        headers = copy.copy(self.headers)
        headers['Connection'] = 'close'
        while 1:
            try:
                if self._stopped:
                    return
                if data_queue.qsize() * self.bufsize > 180*1024*1024:
                    time.sleep(10)
                    continue
                try:
                    start, end, response = range_queue.get(timeout=1)
                    headers['Range'] = 'bytes=%d-%d' % (start, end)
                    fetchserver = ''
                    if not response:
                        fetchserver = random.choice(self.fetchservers)
                        if self._last_app_status.get(fetchserver, 200) >= 500:
                            time.sleep(5)
                        response = self.urlfetch(self.command, self.url, headers, self.payload, fetchserver, password=self.password)
                except queue.Empty:
                    continue
                except (socket.error, ssl.SSLError, OSError) as e:
                    print "Response %r in __fetchlet" % e
                if not response:
                    print 'RangeFetch %s return %r' % (headers['Range'], response)
                    range_queue.put((start, end, None))
                    continue
                if fetchserver:
                    self._last_app_status[fetchserver] = response.app_status
                if response.app_status != 200:
                    print 'Range Fetch "%s %s" %s return %s' % (self.command, self.url, headers['Range'], response.app_status)
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                if response.getheader('Location'):
                    self.url = response.getheader('Location')
                    print 'RangeFetch Redirect(%r)' % self.url
                    response.close()
                    range_queue.put((start, end, None))
                    continue
                if 200 <= response.status < 300:
                    content_range = response.getheader('Content-Range')
                    if not content_range:
                        print 'RangeFetch "%s %s" return Content-Range=%r: response headers=%r' % (self.command, self.url, content_range, response.getheaders())
                        response.close()
                        range_queue.put((start, end, None))
                        continue
                    content_length = int(response.getheader('Content-Length', 0))
                    print '>>>>>>>>>>>>>>> [thread %s] %s %s' % (threading.currentThread().ident, content_length, content_range)
                    while 1:
                        try:
                            data = response.read(self.bufsize)
                            if not data:
                                break
                            data_queue.put((start, data))
                            start += len(data)
                        except (socket.error, ssl.SSLError, OSError) as e:
                            print 'RangeFetch "%s %s" %s failed: %s' % (self.command, self.url, headers['Range'], e)
                            break
                    if start < end:
                        print 'RangeFetch "%s %s" retry %s-%s' % (self.command, self.url, start, end)
                        response.close()
                        range_queue.put((start, end, None))
                        continue
                else:
                    print 'RangeFetch %r return %s' % (self.url, response.status)
                    response.close()
                    #range_queue.put((start, end, None))
                    continue
            except Exception as e:
                print 'RangeFetch._fetchlet error:%s'% e
                raise


class LocalProxyServer(socketserver.ThreadingTCPServer): pass

class GAEProxyHandler(http.server.BaseHTTPRequestHandler):

    bufsize = 256*1024
    first_run_lock = threading.Lock()
    urlfetch = staticmethod(gae_urlfetch)
    normcookie = functools.partial(re.compile(', ([^ =]+(?:=|$))').sub, '\\r\\nSet-Cookie: \\1')

    def _update_google_iplist(self):
        for appid in common.GAE_APPIDS:
            http_util.dns['%s.appspot.com' % appid] = list(set(common.GOOGLE_HOSTS))
        print 'resolve common.GOOGLE_HOSTS domain to iplist=%r' % common.GOOGLE_HOSTS

    def first_run(self):
        iplist = []
        try:
            ips = socket.gethostbyname_ex('www.google.cn')[-1]
            if len(ips) > 1:
                iplist += ips
        except Exception, e:
            print 'socket.gethostbyname_ex(host=%r) failed:%s' % (host, e)
        self._update_google_iplist()

    def setup(self):
        if isinstance(self.__class__.first_run, collections.Callable):
            try:
                with self.__class__.first_run_lock:
                    if isinstance(self.__class__.first_run, collections.Callable):
                        self.first_run()
                        self.__class__.first_run = None
            except Exception, e:
                print 'GAEProxyHandler.first_run() return %r' % e

        self.__class__.setup = http.server.BaseHTTPRequestHandler.setup
        self.__class__.do_GET = self.__class__.do_METHOD
        self.__class__.do_PUT = self.__class__.do_METHOD
        self.__class__.do_POST = self.__class__.do_METHOD
        self.__class__.do_HEAD = self.__class__.do_METHOD
        self.__class__.do_DELETE = self.__class__.do_METHOD
        self.__class__.do_OPTIONS = self.__class__.do_METHOD
        self.setup()

    def finish(self):
        """make python2 BaseHTTPRequestHandler happy"""
        try:
            if not self.wfile.closed:
                self.wfile.flush()
            self.wfile.close()
        except (socket.error, ssl.SSLError, OSError):
            pass
        self.rfile.close()

    def do_METHOD(self):
        """GAE http urlfetch"""
        if common.USERAGENT_ENABLE:
            self.headers['User-Agent'] = common.USERAGENT_STRING
        self.parsed_url = urllib.parse.urlparse(self.path)
        host = self.headers.get('Host', '')
        path = self.parsed_url.path
        range_in_query = 'range=' in self.parsed_url.query
#        special_range = (any(x(host) for x in common.AUTORANGE_HOSTS_MATCH) or path.endswith(common.AUTORANGE_ENDSWITH)) and not path.endswith(common.AUTORANGE_NOENDSWITH)
        if 'Range' in self.headers:
            m = re.search('bytes=(\d+)-', self.headers['Range'])
            start = int(m.group(1) if m else 0)
            self.headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
            print 'autorange range=%r match url=%r' % (self.headers['Range'], self.path)
#        elif not range_in_query and special_range:
#            try:
#                print 'Found [autorange]endswith match url=%r' % self.path
#                m = re.search('bytes=(\d+)-', self.headers.get('Range', ''))
#                start = int(m.group(1) if m else 0)
#                self.headers['Range'] = 'bytes=%d-%d' % (start, start+common.AUTORANGE_MAXSIZE-1)
#            except StopIteration:
#                pass

        payload = b''
        if 'Content-Length' in self.headers:
            try:
                payload = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            except (EOFError, socket.error, ssl.SSLError, OSError) as e:
                print 'handle_method_urlfetch read payload failed:%s' % e
                return
        response = None
        errors = []
        headers_sent = False
        fetchserver = common.GAE_FETCHSERVER
        for retry in range(common.FETCHMAX_LOCAL):
            try:
                content_length = 0
                kwargs = {}
                if common.GAE_PASSWORD:
                    kwargs['password'] = common.GAE_PASSWORD
                if common.GAE_VALIDATE:
                    kwargs['validate'] = 1
                response = self.urlfetch(self.command, self.path, self.headers, payload, fetchserver, **kwargs)
                if not response and retry == common.FETCHMAX_LOCAL-1:
                    html = message_html('502 URLFetch failed', 'Local URLFetch %r failed' % self.path, str(errors))
                    self.wfile.write(b'HTTP/1.0 502\r\nContent-Type: text/html\r\n\r\n' + html.encode('utf-8'))
                    return
                # gateway error, switch to https mode
                if response.app_status in (400, 504) or (response.app_status == 502 and common.GAE_PROFILE == 'google_cn'):
                    common.GOOGLE_MODE = 'https'
                    common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                    continue
                # appid over qouta, switch to next appid
                if response.app_status == 503:
                    common.GAE_APPIDS.append(common.GAE_APPIDS.pop(0))
                    common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                    http_util.dns[urllib.parse.urlparse(common.GAE_FETCHSERVER).netloc] = common.GOOGLE_HOSTS
                    print 'APPID Over Quota,Auto Switch to [%s]' % (common.GAE_APPIDS[0])
                    continue
                # bad request, disable CRLF injection
                if response.app_status in (400, 405):
                    http_util.crlf = 0
                    continue
#                if response.app_status == 500 and range_in_query and special_range:
#                    fetchserver = re.sub(r'//\w+\.appspot\.com', '//%s.appspot.com' % random.choice(common.GAE_APPIDS), fetchserver)
#                    print '500 with range in query, trying another APPID'
#                    continue
                if response.app_status != 200 and retry == common.FETCHMAX_LOCAL-1:
                    print '%s "GAE %s %s HTTP/1.1" %s -' % (self.address_string(), self.command, self.path, response.status)
                    self.wfile.write(('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k != 'Transfer-Encoding'))).encode())
                    self.wfile.write(response.read())
                    response.close()
                    return
                # first response, has no retry.
                if not headers_sent:
                    print '%s "GAE %s %s HTTP/1.1" %s %s' % (self.address_string(), self.command, self.path, response.status, response.getheader('Content-Length', '-'))
                    if response.status == 206:
                        fetchservers = [re.sub(r'//\w+\.appspot\.com', '//%s.appspot.com' % appid, common.GAE_FETCHSERVER) for appid in common.GAE_APPIDS]
                        rangefetch = RangeFetch(self.wfile, response, self.command, self.path, self.headers, payload, fetchservers, common.GAE_PASSWORD, maxsize=common.AUTORANGE_MAXSIZE, bufsize=common.AUTORANGE_BUFSIZE, waitsize=common.AUTORANGE_WAITSIZE, threads=common.AUTORANGE_THREADS)
                        return rangefetch.fetch()
                    if response.getheader('Set-Cookie'):
                        response.headers['Set-Cookie'] = self.normcookie(response.getheader('Set-Cookie'))
                    headers_data = ('HTTP/1.1 %s\r\n%s\r\n' % (response.status, ''.join('%s: %s\r\n' % (k.title(), v) for k, v in response.getheaders() if k.title() != 'Transfer-Encoding'))).encode()
                    self.wfile.write(headers_data)
                    headers_sent = True
                content_length = int(response.getheader('Content-Length', 0))
                content_range = response.getheader('Content-Range', '')
                accept_ranges = response.getheader('Accept-Ranges', 'none')
                if content_range:
                    start, end, length = list(map(int, re.search(r'bytes (\d+)-(\d+)/(\d+)', content_range).group(1, 2, 3)))
                else:
                    start, end, length = 0, content_length-1, content_length
                while 1:
                    data = response.read(8192)
                    if not data:
                        response.close()
                        return
                    start += len(data)
                    self.wfile.write(data)
                    if start >= end:
                        response.close()
                        return
            except Exception, e:
                errors.append(e)
                if response:
                    response.close()
                if e.args[0] in (errno.ECONNABORTED, errno.EPIPE):
                    print 'GAEProxyHandler.do_METHOD_GAE return %r' % e
                elif e.args[0] in (errno.ECONNRESET, errno.ETIMEDOUT, errno.ENETUNREACH, 11004):
                    # connection reset or timeout, switch to https
                    common.GOOGLE_MODE = 'https'
                    common.GAE_FETCHSERVER = '%s://%s.appspot.com%s?' % (common.GOOGLE_MODE, common.GAE_APPIDS[0], common.GAE_PATH)
                elif e.args[0] == errno.ETIMEDOUT or isinstance(e.args[0], str) and 'timed out' in e.args[0]:
                    if content_length and accept_ranges == 'bytes':
                        # we can retry range fetch here
                        print 'GAEProxyHandler.do_METHOD_GAE timed out, url=%r, content_length=%r, try again' % (self.path, content_length)
                        self.headers['Range'] = 'bytes=%d-%d' % (start, end)
                elif isinstance(e, ssl.SSLError) and 'bad write retry' in e.args[1]:
                    print 'GAEProxyHandler.do_METHOD_GAE url=%r return %r, abort.' % (self.path, e)
                    return
                else:
                    print 'GAEProxyHandler.do_METHOD_GAE %r return %r, try again' % (self.path, e)

    def do_CONNECT(self):
        """handle CONNECT cmmand, socket forward or deploy a fake cert"""
        host = self.path.rpartition(':')[0]
        if host.endswith(common.GOOGLE_SITES) and not host.endswith(common.GOOGLE_WITHGAE):
            http_util.dns[host] = common.GOOGLE_HOSTS
            self.do_CONNECT_FWD()
        else:
            self.do_CONNECT_AGENT()

    def do_CONNECT_FWD(self):
        """socket forward for http CONNECT command"""
        host, _, port = self.path.rpartition(':')
        port = int(port)
        print '%s "FWD %s %s:%d HTTP/1.1" - -' % (self.address_string(), self.command, host, port)
        #http_headers = ''.join('%s: %s\r\n' % (k, v) for k, v in self.headers.items())
        self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
        data = self.connection.recv(1024)
        for i in range(5):
            try:
                timeout = 4
                remote = http_util.create_connection((host, port), timeout)
                if remote is not None and data:
                    remote.sendall(data)
                    break
                elif i == 0:
                    # only print first create_connection error
                    print 'http_util.create_connection((host=%r, port=%r), %r) timeout' % (host, port, timeout)
            except (socket.error, ssl.SSLError, OSError) as e:
                if e.args[0] == 9:
                    print 'GAEProxyHandler direct forward remote (%r, %r) failed' % (host, port)
                    continue
                else:
                    raise
        if hasattr(remote, 'fileno'):
            # reset timeout default to avoid long http upload failure, but it will delay timeout retry :(
            remote.settimeout(None)
            http_util.forward_socket(self.connection, remote, bufsize=self.bufsize)

    def do_CONNECT_AGENT(self):
        """deploy fake cert to client"""
        host, _, port = self.path.rpartition(':')
        port = int(port)
        certfile = CertUtil.get_cert(host)
        print '%s "AGENT %s %s:%d HTTP/1.1" - -' % (self.address_string(), self.command, host, port)
        self.__realconnection = None
        self.wfile.write(b'HTTP/1.1 200 OK\r\n\r\n')
        try:
            ssl_sock = ssl.wrap_socket(self.connection, certfile=certfile, keyfile=certfile, server_side=True, ssl_version=ssl.PROTOCOL_SSLv23)
        except Exception as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET):
                print 'ssl.wrap_socket(self.connection=%r) failed: %s' % (self.connection, e)
            return
        self.__realconnection = self.connection
        self.__realwfile = self.wfile
        self.__realrfile = self.rfile
        self.connection = ssl_sock
        self.rfile = self.connection.makefile('rb', self.bufsize)
        self.wfile = self.connection.makefile('wb', 0)
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if not self.parse_request():
                return
        except (socket.error, ssl.SSLError, OSError) as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE):
                raise
        if self.path[0] == '/' and host:
            self.path = 'https://%s%s' % (self.headers['Host'], self.path)
        try:
            self.do_METHOD()
        except (socket.error, ssl.SSLError, OSError) as e:
            if e.args[0] not in (errno.ECONNABORTED, errno.ETIMEDOUT, errno.EPIPE):
                raise
        finally:
            if self.__realconnection:
                try:
                    self.__realconnection.shutdown(socket.SHUT_WR)
                    self.__realconnection.close()
                except (socket.error, ssl.SSLError, OSError):
                    pass
                finally:
                    self.__realconnection = None

def main():

    CertUtil.check_ca()
    sys.stdout.write(common.info())

    server = LocalProxyServer((common.LISTEN_IP, common.LISTEN_PORT), GAEProxyHandler)
    server.serve_forever()

if __name__ == '__main__':
    main()
