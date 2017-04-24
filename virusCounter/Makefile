all: avmod

testcall: testcall.o
	gcc -g testcall.o -o testcall

testcall.o: testcall.c
	gcc -g testcall.c -c

avmod:
	cd LKM; make; insmod avmod.ko; cd ../; make testcall

clean:
	cd LKM; rmmod avmod.ko; make clean; cd ../
	rm -rf *.o testcall
