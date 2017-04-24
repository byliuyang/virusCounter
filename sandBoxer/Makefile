all: s2u glu

shift2user: shift2user.o
	gcc -g shift2user.o -o shift2user
shift2user.o: shift2user.h shift2user.c
	gcc -g shift2user.c -c
getloginuid: getloginuid.o
	gcc -g getloginuid.o -o getloginuid
getloginuid.o: getloginuid.c getloginuid.h
	gcc -g getloginuid.c -c

s2u:
	cd LKM/s2u;make clean;make;rmmod shift2user_mod.ko;insmod shift2user_mod.ko; cd ../../;make shift2user

glu:
	cd LKM/glu;make clean;make;rmmod getloginuid_mod.ko;insmod getloginuid_mod.ko; cd ../../;make getloginuid

clean:
	cd LKM/s2u;make clean;cd ../glu;make clean; cd ../../
	rm -rf *.o shift2user getloginuid
