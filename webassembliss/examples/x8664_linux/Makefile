all: hello

hello: hello.s
	x86_64-linux-gnu-as hello.s -g --gdwarf-5 -o hello.o
	x86_64-linux-gnu-ld hello.o -o hello.out

clean:
	rm *.o *.out
