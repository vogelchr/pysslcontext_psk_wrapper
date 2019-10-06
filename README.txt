A wrapper to make SSL TLSv1 preshared keys work with python ssl, using contexts.

This is still horribly broken, but seems to work, at least with s_client!

See test_wrapper.py on how to make it work with Tornado.

I intend to use this as a replacement of psk-frontend within tuya-convert.
   https://github.com/ct-Open-Source/tuya-convert
which in turn uses
   https://pypi.org/project/sslpsk/
...which somehow didn't work right for me. Also I didn't want to have two
proccesses running, with psk-frontend just being a dumb proxy.
