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
#include "rijndael.h"

int main(int argc, char **argv){
	unsigned int k0 = syscall(549, 0); /* Lower half of AES key */
	unsigned int k1 = syscall(549, 1); /* Upper half of AES key */
	unsigned char key[KEYLENGTH(128)];/* cipher key */
	char	buf[100];
	int i;
	
	/* Combine the two key values */
	bzero (key, sizeof (key));
	bcopy (&k0, &(key[0]), sizeof (k0));
	bcopy (&k1, &(key[sizeof(k0)]), sizeof (k1));
		
	/* Print the key, just in case */
	for (i = 0; i < sizeof (key); i++) {
		sprintf (buf+2*i, "%02x", key[sizeof(key)-i-1]);
	}
	fprintf (stderr, "KEY: %s\n", buf);
	
}
