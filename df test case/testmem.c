/*
 * testmem.cpp
 *
 *  Created on: 2015年11月6日
 *      Author: wpf
 */

#include "stdio.h"
#include "stdlib.h"
#include <string.h>
//#include "linux/slab.h"
//#include "asm/uaccess.h"
//#include <iostream>
#include "assert.h"

struct test_message{
	char msg[12];
	int msglength;
};


struct test_message * init_struct(void){
	struct test_message * myptr;
	myptr = (struct test_message*) malloc(sizeof(struct test_message));

	char*  str = "helloworld";
	myptr->msglength = strlen("helloworld")+1;
	memcpy(myptr->msg, str, myptr->msglength);

	printf("struct init finished, msg is: %s, and length is %d\n", myptr->msg, myptr->msglength);
	return myptr;
}

int main(){

	struct test_message *rtptr;
	rtptr = init_struct();

	//char* KernelBuffer;
	char * localbuffer =(char*) malloc(rtptr->msglength);
	//KernelBuffer = (char*)kmalloc(mptr->length,GFP_KERNEL);

	if (localbuffer != NULL) {
		//copy_from_user(KernelBuffer, mptr->msg, mptr->length);
		//copy_to_user
		memcpy(localbuffer, rtptr->msg, rtptr->msglength);
	} else {
		assert(0);
	}

	printf("Main() Copied msg is %s\n", localbuffer);

	int a =123;
	if (a > 0){
		printf("%s\n",rtptr->msg);
	}

	free(rtptr);
	//kfree(KernelBuffer);
	free(localbuffer);
	return 0;
}





