#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/syscall.h>

int main(int argc, char **argv){
	unsigned int k0; /* Lower half of AES key */
	unsigned int k1; /* Upper half of AES key */
	unsigned long long key; /* 64 bit key for user */
	
	if((argc == 2) && (strlen(argv[1]) == 16)) {
		key = (long long) strtoll(argv[1],NULL,16);
		
		/*
		Int is a 32 bit integer at most, so AND will give result of
		operation with only most significant 32 bits of the 64
		*/
		k0 = key & 0xffffffff; 
		
		/*
		Shifting right by 32 bits will give us the second half of the 64-bit key */
		k1=(key >> 32); 
		
		if(k0 == 0 && k1 == 0){
			fprintf(stderr, "Encryption and decrytion are now disabled for this user\n");
		}
		syscall(548, k0, k1);
		printf("Key has been set to %s\n", argv[1]);
		
	} else {
		fprintf(stderr, "setkey usage: setkey <16 digit hex key>\n");
		return 1;
	}
}