#!/usr/bin/python

import tornado.web
import tornado.httpserver
import ssl
import pysslcontext_psk_wrapper

print('''**
**
** Test this server by running the following command in another terminal:
*** openssl s_client -psk 31323334 -psk_identity foobar -cipher PSK-AES128-CBC-SHA256 -connect 127.0.0.1:8443
**
**''')

def psk_server_cb(clt_identity) :
        print(f'*** got a client connection with identity {clt_identity} ***')
        return '1234' # psk

print('app...')
app = tornado.web.Application([])

print('ctx...')
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
ctx.set_ciphers('ALL:PSK')

print('wrap...')
wrap = pysslcontext_psk_wrapper.PySSLContext_PSK_Wrapper(ctx)

print('cb...')
wrap.psk_server_cb = psk_server_cb

print('server...')
https_server = tornado.httpserver.HTTPServer(app,ssl_options=ctx)

print('listen...')
https_server.listen(8443)

print('loop...')
tornado.ioloop.IOLoop.current().start()
