all : pysslcontext_psk_wrapper.so

CFLAGS=-ggdb -Wall -Wextra -fPIC
CPPFLAGS=-I/usr/include/python3.7m

%.so : %.o
	cc -shared -o $@ $^ -lssl

.PHONY : clean
clean :
	rm -f *~ *.o *.so *.bak
