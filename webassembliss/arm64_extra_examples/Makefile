all: hello infiniteLoop ioExample multiExample cExample

hello: hello.S
	aarch64-linux-gnu-as hello.S -g --gdwarf-5 -o hello.o
	aarch64-linux-gnu-ld hello.o -o hello.out

infiniteLoop: infiniteLoop.S
	aarch64-linux-gnu-as infiniteLoop.S -g --gdwarf-5 -o infiniteLoop.o
	aarch64-linux-gnu-ld infiniteLoop.o -o infiniteLoop.out

ioExample: ioExample.S
	aarch64-linux-gnu-as ioExample.S -g --gdwarf-5 -o ioExample.o
	aarch64-linux-gnu-ld ioExample.o -o ioExample.out

multiExample: multiDriver.S sampleLib.S
	aarch64-linux-gnu-as multiDriver.S -g --gdwarf-5 -o multiDriver.o
	aarch64-linux-gnu-as sampleLib.S -g --gdwarf-5 -o sampleLib.o
	aarch64-linux-gnu-ld multiDriver.o sampleLib.o -o multiExample.out -lc

cExample: cDriver.c sampleLib.S
	aarch64-linux-gnu-gcc cDriver.c -c -g -gdwarf -o cDriver.o
	aarch64-linux-gnu-as sampleLib.S -g --gdwarf-5 -o sampleLib.o
	aarch64-linux-gnu-ld cDriver.o sampleLib.o -o cExample.out -lc

clean:
	rm *.o *.out
