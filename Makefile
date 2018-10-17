all : arpspoofing

arpspoofing: arpspoofing.o
	gcc -g -o arpspoofing arpspoofing.o -lpcap

arpspoofing.o:
	gcc -g -c -o arpspoofing.o arpspoofing.c

clean:
	rm -f arpspoofing
	rm -f *.o

