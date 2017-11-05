README:

Group Members: Aryan Samuel, Alan Duncan, Khoa Hoang

Description:
Our group attempted to modify the FreeBSD file system to create a crypto file system.
This was done specifically by making a copy of the nullfs file system to create a cryptofs
version. Changing everything appropriate from null to crypto and going through every
appropriate file and adding the changes.  This is discussed in more detail within our
design document.  In addition to the file system a system call was created to convert
a hex key into 2 int keys and associate them with the user ID and a protectfile to actively
encrypt and decrypt files.

To mount the cryptofs folder you run the following commands:

First to install mount_cryptofs go to the /mount_cryptofs folder and run
"sudo make" and then "sudo make install"

Then to actually mount it run:

sudo mount_cryptofs [dir1] [mount_point]

where dir1 is the directory path of fs/cryptofs folder and mount_point is the directory
path of the folder you wish to mount to.

To set the keys go to the asgn4/ folder

run: 
make

to set the key to a user run:
./setkey <key>

to check and see if the key was set properly run
./getkey

to encrypt/decrypt a file run:
sudo ./protectfile <-e/-d> <key> <file>

Note that since we could not fully implement protectfile's functionality, it only runs when all these
arguments are passed. When trying to run without the key, since the program has trouble getting the keys even though
the system call for getting keys works fully, the program will always assume that the keys for the user
are not set. We did our best to fix this, even trying to use the seteuid and setuid functions but to
no avail. 



