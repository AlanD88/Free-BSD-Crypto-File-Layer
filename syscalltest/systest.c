#include<sys/syscall.h>
#include<unistd.h>
#include<stdio.h>

int main() {
	syscall(548, 0, 0);
	return(0);
}
