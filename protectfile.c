#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "rijndael.h"

/*
* This code encrypts input data using the Rijndael (AES) cipher.  The
* key length is hard-coded to 128 key bits; this number may be changed
* by redefining a constant near the start of the file.
*
* This program uses CTR mode encryption.
*
* Usage: encrypt <key1> <key2> <file name>
*
* Author: Ethan L. Miller (elm@cs.ucsc.edu)
* Based on code from Philip J. Erdelsky (pje@acm.org)
*
*/


static char rcsid[] = "$Id: encrypt.c,v 1.2 2003/04/15 01:05:36 elm Exp elm $";

#define KEYBITS 128
#define ENCRYPTION 1
#define DECRYPTION 2

/***********************************************************************
*
* hexvalue
*
* This routine takes a single character as input, and returns the
* hexadecimal equivalent.  If the character passed isn't a hex value,
* the program exits.
*
***********************************************************************
*/
int hexvalue (char c)
{
	if (c >= '0' && c <= '9') {
		return (c - '0');
	} else if (c >= 'a' && c <= 'f') {
		return (10 + c - 'a');
	} else if (c >= 'A' && c <= 'F') {
		return (10 + c - 'A');
	} else {
		fprintf (stderr, "ERROR: key digit %c isn't a hex digit!\n", c);
		exit (-1);
	}
}



/*********************************************************************
*
* keyhexchk
*
* This routine takes in a char array and checks each of the characters 
* to see if they are all valid hexadecimal characters.
*
***********************************************************************
*/
void
keyhexchk (char key[]) {
	size_t i;
	for (i = 0; key[i]; i++) {
		hexvalue(key[i]);
	}
}

/*********************************************************************
*
* keyconvert
*
* This routine takes in a char array, converts and splits it into
* two 32-bit length unsigned integers.
*
***********************************************************************
*/
void
keyconvert (char key[], unsigned int *k0, unsigned int *k1) {
	unsigned long long newkey;
	newkey = (long long) strtoll(key, NULL, 16);
	/*
	Int is a 32 bit integer at most, so AND will give result of
	operation with only most significant 32 bits of the 64
	*/
	*k0 = newkey & 0xffffffff; 
	
	/*
	Shifting right by 32 bits will give us the second half of the 64-bit key */
	*k1 = (newkey >> 32);
}

int main(int argc, char **argv)
{
	unsigned long rk[RKLENGTH(KEYBITS)];	/* round key */
	unsigned char key[KEYLENGTH(KEYBITS)];/* cipher key */
	char	buf[100];
	int i, nbytes, nwritten , ctr;
	int totalbytes;
	int	k0, k1;
	int fileId;
	int nrounds;				/* # of Rijndael rounds */
	char *password;			/* supplied (ASCII) password */
	int	fd;
	char *filename;
	unsigned char filedata[16];
	unsigned char ciphertext[16];
	unsigned char ctrvalue[16];
	unsigned int ck0, ck1, gk0, gk1;

	/* If user is setting key for the first time */
	if (argc == 4) {
		
		filename = argv[3];
		
		/* Create structure for file statistics */
		struct stat finfo;
		stat (filename, &finfo);
		/*Get file's associated user using stat()*/
		uid_t fowner = finfo.st_uid;
		
		keyhexchk(argv[2]); /* Check if key is correct i.e. only hex values*/
		keyconvert(argv[2], &ck0, &ck1); /* Convert key to two unsigned ints */
		
		/* Check if key input is correct, if not error out */
		//gk0 = syscall(549, 0); /* Get k0 of the key */
		//gk1 = syscall(549, 1); /* Get k1 of the key */
		
		/*if (!((gk0 == ck0) && (gk1 == ck1))) {
			fprintf(stderr, "User key is incorrect or has not been set yet.\n");
			return 1;
		}*/

		/* If user input is -e */
		if (!strcmp(argv[1], "-e")) {
			if (finfo.st_mode & S_ISVTX) {
				fprintf (stderr, "Error: %s is already encrypted.\n", filename);
				return 1;
			} else {
				fileId = finfo.st_ino;
				if (chmod(filename, S_ISVTX)) {
					perror("protectfile");
					exit (-1);
				}
			}
		} 
		/* If user input is -d */
		else if (!strcmp(argv[1], "-d")) {
			if (!(finfo.st_mode & S_ISVTX)) {
				fprintf (stderr, "Error: %s is already decrpyted.\n", filename);
				return 1;
			} else {
				fileId = finfo.st_ino;
				if (chmod(filename, S_IFREG)) {
					perror("protectfile");
					exit (-1);
				}
			}
		}
	}
	
	/* If user has set key previously */
	else if (argc == 3) {
		filename = argv[2];
		
		/* Create structure for file statistics */
		struct stat finfo;
		stat (filename, &finfo);
		/*Get file's associated user using stat()*/
		uid_t fowner = finfo.st_uid;
		
		/* Get the user's key using getkey system call */
		gk0 = syscall (549, 0);
		gk1 = syscall (549, 1);
		if ((gk0 == 0) && (gk1 == 0)) {
			fprintf(stderr, "User has not set a key.\n");
			return 1;
		}
		
		/* Combine the two key values */
		bzero (key, sizeof (key));
		bcopy (&gk0, &(key[0]), sizeof (gk0));
		bcopy (&gk1, &(key[sizeof(gk0)]), sizeof (gk1));
	
		/* If user input is -e */
		if (!strcmp(argv[1], "-e")) {
			if (finfo.st_mode & S_ISVTX) {
				fprintf (stderr, "Error: %s is already encrypted.\n", filename);
				return 1;
			} else {
				fileId = finfo.st_ino;
				if (chmod(filename, S_ISVTX)) {
					perror("protectfile");
					exit (-1);
				}
			}
		} 
		/* If user input is -d */
		else if (!strcmp(argv[1], "-d")) {
			if (!(finfo.st_mode & S_ISVTX)) {
				fprintf (stderr, "Error: %s is already decrpyted.\n", filename);
				return 1;
			} else {
				fileId = finfo.st_ino;
				if (chmod(filename, S_IFREG)) {
					perror("protectfile");
					exit (-1);
				}
			}
		}
	}
	
	/* If number of arguments is incorrect */
	else {
		fprintf (stderr, "Usage for first time users: %s <-e/-d option> <key> <file>\nOtherwise: %s <-e/-d option> <file>\n", argv[0], argv[0]);
		return 1;
	}
	
	/* Print the key, just in case */
	/*for (i = 0; i < sizeof (key); i++) {
		sprintf (buf+2*i, "%02x", key[sizeof(key)-i-1]);
	}
	fprintf (stderr, "KEY: %s\n", buf);*/
	
/*
 * Initialize the Rijndael algorithm.  The round key is initialized by this
 * call from the values passed in key and KEYBITS.
 */
	nrounds = rijndaelSetupEncrypt(rk, key, KEYBITS);

/*
 * Open the file.
 */
	fd = open(filename, O_RDWR);
	if (fd < 0)
	{
		fprintf(stderr, "Error opening file %s\n", argv[3]);
		return 1;
	}

	/* fileID goes into bytes 8-11 of the ctrvalue */
	bcopy (&fileId, &(ctrvalue[8]), sizeof (fileId));

/*	This loop reads 16 bytes from the file, XORs it with the encrypted
	CTR value, and then writes it back to the file at the same position.
	Note that CTR encryption is nice because the same algorithm does
	encryption and decryption.  In other words, if you run this program
	twice, it will first encrypt and then decrypt the file.
*/
	for (ctr = 0, totalbytes = 0; /* loop forever */; ctr++)
	{
		/* Read 16 bytes (128 bits, the blocksize) from the file */
		nbytes = read (fd, filedata, sizeof (filedata));
		if (nbytes <= 0) {
			break;
		}
		if (lseek (fd, totalbytes, SEEK_SET) < 0)
		{
			perror ("Unable to seek back over buffer");
			exit (-1);
		}

		/* Set up the CTR value to be encrypted */
		bcopy (&ctr, &(ctrvalue[0]), sizeof (ctr));

		/* Call the encryption routine to encrypt the CTR value */
		rijndaelEncrypt(rk, nrounds, ctrvalue, ciphertext);

		/* XOR the result into the file data */
		for (i = 0; i < nbytes; i++) {
			filedata[i] ^= ciphertext[i];
		}

		/* Write the result back to the file */
		nwritten = write(fd, filedata, nbytes);
		if (nwritten != nbytes)
		{
			fprintf (stderr,
			"%s: error writing the file (expected %d, got %d at ctr %d\n)",
			argv[0], nbytes, nwritten, ctr);
			break;
		}

		/* Increment the total bytes written */
		totalbytes += nbytes;
	}
	close (fd);
}