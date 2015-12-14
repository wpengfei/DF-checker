/*
 * testmem.cpp
 *
 *  Created on: 2015年11月6日
 *      Author: wpf
 */

#include "stdio.h"
#include "string.h"
#include <stdlib.h>

typedef struct test_message{
	char msg[20];
	unsigned int msglength ;
} MSG;


void kernel_func(MSG *uptr){
	/*char* o;
	char c;
	printf("aa%s", uptr->msg);
	printf("aa%s", uptr->msglength);
	o = uptr->msg;
	c = uptr->msg[0];*/

	char * localbuffer =(char*) malloc(uptr->msglength);
	if (localbuffer != NULL) {
		memcpy(localbuffer, uptr->msg, uptr->msglength);
	}
	printf("Kernel() Copied msg is %s\n", localbuffer);
/*
	char* buffer2;
	buffer2 = localbuffer;
	if (!buffer2){
		printf("buffer2 is null\n");
	}
	else{
		printf("assigned msg is %s\n", buffer2);
	}
*/
	free(localbuffer);

}

/*
int main(){

	MSG mymsg;
	mymsg.msglength = strlen("hello world!");
	strcpy(mymsg.msg, "hello world!");

	kernel_func(&mymsg);

	return 0;
}
*/




