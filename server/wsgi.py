#!/usr/bin/env python
# coding=utf-8

__version__ = '2.1.18'
__password__ = ''

import sys
import os
import re
import time
import struct
import zlib
import base64
import logging
import httplib
import urlparse
import errno
try:
    from io import BytesIO
except ImportError:
    from cStringIO import StringIO as BytesIO
try:
    from google.appengine.api import urlfetch
    from google.appengine.runtime import apiproxy_errors
except ImportError:
    urlfetch = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

URLFETCH_MAX = 2
URLFETCH_MAXSIZE = 4*1024*1024
URLFETCH_DEFLATE_MAXSIZE = 4*1024*1024
URLFETCH_TIMEOUT = 60


class base92:
    """https://github.com/thenoviceoof/base92"""
    @staticmethod
    def encode(bytstr):
        def base92_chr(val):
            if val < 0 or val >= 91:
                raise ValueError('val must be in [0, 91)')
            if val == 0:
                return '!'
            elif val <= 61:
                return chr(ord('#') + val - 1)
            else:
                return chr(ord('a') + val - 62)
        # always encode *something*, in case we need to avoid empty strings
        if not bytstr:
            return '~'
        # make sure we have a bytstr
        if not isinstance(bytstr, basestring):
            # we'll assume it's a sequence of ints
            bytstr = ''.join([chr(b) for b in bytstr])
        # prime the pump
        bitstr = ''
        while len(bitstr) < 13 and bytstr:
            bitstr += '{:08b}'.format(ord(bytstr[0]))
            bytstr = bytstr[1:]
        resstr = ''
        while len(bitstr) > 13 or bytstr:
            i = int(bitstr[:13], 2)
            resstr += base92_chr(i / 91)
            resstr += base92_chr(i % 91)
            bitstr = bitstr[13:]
            while len(bitstr) < 13 and bytstr:
                bitstr += '{:08b}'.format(ord(bytstr[0]))
                bytstr = bytstr[1:]
        if bitstr:
            if len(bitstr) < 7:
                bitstr += '0' * (6 - len(bitstr))
                resstr += base92_chr(int(bitstr, 2))
            else:
                bitstr += '0' * (13 - len(bitstr))
                i = int(bitstr, 2)
                resstr += base92_chr(i / 91)
                resstr += base92_chr(i % 91)
        return resstr

    @staticmethod
    def decode(bstr):
        def base92_ord(val):
            num = ord(val)
            if val == '!':
                return 0
            elif ord('#') <= num and num <= ord('_'):
                return num - ord('#') + 1
            elif ord('a') <= num and num <= ord('}'):
                return num - ord('a') + 62
            else:
                raise ValueError('val is not a base92 character')
        bitstr = ''
        resstr = ''
        if bstr == '~':
            return ''
        # we always have pairs of characters
        for i in range(len(bstr)/2):
            x = base92_ord(bstr[2*i])*91 + base92_ord(bstr[2*i+1])
            bitstr += '{:013b}'.format(x)
            while 8 <= len(bitstr):
                resstr += chr(int(bitstr[0:8], 2))
                bitstr = bitstr[8:]
        # if we have an extra char, check for extras
        if len(bstr) % 2 == 1:
            x = base92_ord(bstr[-1])
            bitstr += '{:06b}'.format(x)
            while 8 <= len(bitstr):
                resstr += chr(int(bitstr[0:8], 2))
                bitstr = bitstr[8:]
        return resstr


def message_html(title, banner, detail=''):
    ERROR_TEMPLATE = '''
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
<tr><td>&nbsp;</td></tr></table>
<blockquote>
<H1>{{ banner }}</H1>
{{ detail }}
<!--
<script type="text/javascript" src="http://www.qq.com/404/search_children.js" charset="utf-8"></script>
//-->
<p>
</blockquote>
<table width=100% cellpadding=0 cellspacing=0><tr><td bgcolor=#3366cc><img alt="" width=1 height=4></td></tr></table>
</body></html>
'''
    kwargs = dict(title=title, banner=banner, detail=detail)
    template = ERROR_TEMPLATE
    for keyword, value in kwargs.items():
        template = template.replace('{{ %s }}' % keyword, value)
    return template


def gae_application(environ, start_response):
    cookie = environ.get('HTTP_COOKIE', '')
    if environ['REQUEST_METHOD'] == 'GET' and not cookie:
        if '204' in environ['QUERY_STRING']:
            start_response('204 No Content', [])
            yield ''
        else:
            timestamp = long(os.environ['CURRENT_VERSION_ID'].split('.')[1])/2**28
            ctime = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp+8*3600))
            html = u'GoAgent Python Server %s \u5df2\u7ecf\u5728\u5de5\u4f5c\u4e86\uff0c\u90e8\u7f72\u65f6\u95f4 %s\n' % (__version__, ctime)
            start_response('200 OK', [('Content-Type', 'text/plain; charset=utf-8')])
            yield html.encode('utf8')
        raise StopIteration

    # inflate = lambda x:zlib.decompress(x, -zlib.MAX_WBITS)
    wsgi_input = environ['wsgi.input']
    if cookie:
        metadata = zlib.decompress(base64.b64decode(cookie), -zlib.MAX_WBITS)
    else:
        data = wsgi_input.read(2)
        metadata_length, = struct.unpack('!h', data)
        metadata = wsgi_input.read(metadata_length)
        metadata = zlib.decompress(metadata, -zlib.MAX_WBITS)

    headers = dict(x.split(':', 1) for x in metadata.splitlines() if x)
    method = headers.pop('G-Method')
    url = headers.pop('G-Url')

    kwargs = {}
    any(kwargs.__setitem__(x[2:].lower(), headers.pop(x)) for x in headers.keys() if x.startswith('G-'))

    abbv_headers = {'A': ('Accept', 'text/html, */*; q=0.01'),
                    'AC': ('Accept-Charset', 'UTF-8,*;q=0.5'),
                    'AL': ('Accept-Language', 'zh-CN,zh;q=0.8,en-US;q=0.6,en;q=0.4'),
                    'AE': ('Accept-Encoding', 'gzip,deflate'), }
    abbv_args = kwargs.get('abbv', '').split(',')
    headers.update(v for k, v in abbv_headers.iteritems() if k in abbv_args and v[0] not in headers)

    #logging.info('%s "%s %s %s" - -', environ['REMOTE_ADDR'], method, url, 'HTTP/1.1')
    #logging.info('request headers=%s', headers)

    if __password__ and __password__ != kwargs.get('password', ''):
        start_response('403 Forbidden', [('Content-Type', 'text/html')])
        yield message_html('403 Wrong password', 'Wrong password(%r)' % kwargs.get('password', ''), 'GoAgent proxy.ini password is wrong!')
        raise StopIteration

    netloc = urlparse.urlparse(url).netloc

    if netloc.startswith(('127.0.0.', '::1', 'localhost')):
        start_response('400 Bad Request', [('Content-Type', 'text/html')])
        html = ''.join('<a href="https://%s/">%s</a><br/>' % (x, x) for x in ('google.com', 'mail.google.com'))
        yield message_html('GoAgent %s is Running' % __version__, 'Now you can visit some websites', html)
        raise StopIteration

    fetchmethod = getattr(urlfetch, method, None)
    if not fetchmethod:
        start_response('405 Method Not Allowed', [('Content-Type', 'text/html')])
        yield message_html('405 Method Not Allowed', 'Method Not Allowed: %r' % method, detail='Method Not Allowed URL=%r' % url)
        raise StopIteration

    deadline = URLFETCH_TIMEOUT
    validate_certificate = bool(int(kwargs.get('validate', 0)))
    headers = dict(headers)
    payload = wsgi_input.read() if 'Content-Length' in headers else None
    if 'Content-Encoding' in headers:
        if headers['Content-Encoding'] == 'deflate':
            payload = zlib.decompress(payload, -zlib.MAX_WBITS)
            headers['Content-Length'] = str(len(payload))
            del headers['Content-Encoding']

    accept_encoding = headers.get('Accept-Encoding', '')

    errors = []
    for i in xrange(int(kwargs.get('fetchmax', URLFETCH_MAX))):
        try:
            response = urlfetch.fetch(url, payload, fetchmethod, headers, allow_truncated=False, follow_redirects=False, deadline=deadline, validate_certificate=validate_certificate)
            break
        except apiproxy_errors.OverQuotaError as e:
            time.sleep(5)
        except urlfetch.DeadlineExceededError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            logging.error('DeadlineExceededError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.DownloadError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            logging.error('DownloadError(deadline=%s, url=%r)', deadline, url)
            time.sleep(1)
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.ResponseTooLargeError as e:
            errors.append('%r, deadline=%s' % (e, deadline))
            response = e.response
            logging.error('ResponseTooLargeError(deadline=%s, url=%r) response(%r)', deadline, url, response)
            m = re.search(r'=\s*(\d+)-', headers.get('Range') or headers.get('range') or '')
            if m is None:
                headers['Range'] = 'bytes=0-%d' % int(kwargs.get('fetchmaxsize', URLFETCH_MAXSIZE))
            else:
                headers.pop('Range', '')
                headers.pop('range', '')
                start = int(m.group(1))
                headers['Range'] = 'bytes=%s-%d' % (start, start+int(kwargs.get('fetchmaxsize', URLFETCH_MAXSIZE)))
            deadline = URLFETCH_TIMEOUT * 2
        except urlfetch.SSLCertificateError as e:
            errors.append('%r, should validate=0 ?' % e)
            logging.error('%r, deadline=%s', e, deadline)
        except Exception as e:
            errors.append(str(e))
            if i == 0 and method == 'GET':
                deadline = URLFETCH_TIMEOUT * 2
    else:
        start_response('500 Internal Server Error', [('Content-Type', 'text/html')])
        error_string = '<br />\n'.join(errors)
        if not error_string:
            logurl = 'https://appengine.google.com/logs?&app_id=%s' % os.environ['APPLICATION_ID']
            error_string = 'Internal Server Error. <p/>try <a href="javascript:window.location.reload(true);">refresh</a> or goto <a href="%s" target="_blank">appengine.google.com</a> for details' % logurl
        yield message_html('502 Urlfetch Error', 'Python Urlfetch Error: %r' % method,  error_string)
        raise StopIteration

    #logging.debug('url=%r response.status_code=%r response.headers=%r response.content[:1024]=%r', url, response.status_code, dict(response.headers), response.content[:1024])

    data = response.content
    response_headers = response.headers
    if response_headers.get('content-encoding') == 'gzip' and 'deflate' in accept_encoding and len(response.content) < URLFETCH_DEFLATE_MAXSIZE:
        data = data[10:-8]
        response_headers['Content-Encoding'] = 'deflate'
    elif 'content-encoding' not in response_headers and len(response.content) < URLFETCH_DEFLATE_MAXSIZE and response_headers.get('content-type', '').startswith(('text/', 'application/json', 'application/javascript')):
        if 'deflate' in accept_encoding:
            response_headers['Content-Encoding'] = 'deflate'
            data = zlib.compress(data)[2:-4]
        elif 'gzip' in accept_encoding:
            response_headers['Content-Encoding'] = 'gzip'
            compressobj = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -zlib.MAX_WBITS, zlib.DEF_MEM_LEVEL, 0)
            dataio = BytesIO()
            dataio.write('\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff')
            dataio.write(compressobj.compress(data))
            dataio.write(compressobj.flush())
            dataio.write(struct.pack('<LL', zlib.crc32(data) & 0xFFFFFFFFL, len(data) & 0xFFFFFFFFL))
            data = dataio.getvalue()
    response_headers['Content-Length'] = str(len(data))
    response_headers_data = zlib.compress('\n'.join('%s:%s' % (k.title(), v) for k, v in response_headers.items() if not k.startswith('x-google-')))[2:-4]
    start_response('200 OK', [('Content-Type', 'image/gif')])
    yield struct.pack('!hh', int(response.status_code), len(response_headers_data))+response_headers_data
    yield data

if __name__ == '__main__':
    print 'Content-Type: text/plain'
