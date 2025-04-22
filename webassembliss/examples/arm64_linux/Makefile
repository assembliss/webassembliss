all: hello changingFlags infiniteLoop ioExample multiExample multiExampleWithPrintf cExample clArgs fileIO

hello: hello.S
	aarch64-linux-gnu-as hello.S -g --gdwarf-5 -o hello.o
	aarch64-linux-gnu-ld hello.o -o hello.out

changingFlags: changingFlags.S
	aarch64-linux-gnu-as changingFlags.S -g --gdwarf-5 -o changingFlags.o
	aarch64-linux-gnu-ld changingFlags.o -o changingFlags.out

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

multiExampleWithPrintf: multiDriverWithPrintf.S sampleLib.S
	aarch64-linux-gnu-as multiDriverWithPrintf.S -g --gdwarf-5 -o multiDriverWithPrintf.o
	aarch64-linux-gnu-as sampleLib.S -g --gdwarf-5 -o sampleLib.o
	aarch64-linux-gnu-ld multiDriverWithPrintf.o sampleLib.o -o multiExampleWithPrintf.out -lc

cExample: cDriver.c sampleLib.S
	aarch64-linux-gnu-gcc cDriver.c -c -g -gdwarf -o cDriver.o
	aarch64-linux-gnu-as sampleLib.S -g --gdwarf-5 -o sampleLib.o
	aarch64-linux-gnu-ld cDriver.o sampleLib.o -o cExample.out -lc

clArgs: clArgs.S
	aarch64-linux-gnu-as clArgs.S -g --gdwarf-5 -o clArgs.o
	aarch64-linux-gnu-ld clArgs.o -o clArgs.out -lc

fileIO: fileIO.S
	aarch64-linux-gnu-as fileIO.S -g --gdwarf-5 -o fileIO.o
	aarch64-linux-gnu-ld fileIO.o -o fileIO.out -lc

clean:
	rm *.o *.out
