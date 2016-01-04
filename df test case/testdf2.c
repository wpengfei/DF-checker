/*
 * testdf2.c
 *
 *  Created on: 2015年12月17日
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

	unsigned int len = uptr->msglength;// t0, t0
	unsigned int len2 = len+2;// t0, t0

	char * localbuffer =(char*) malloc(uptr->msglength);//t1, t1
	if (localbuffer != NULL){ //t1
		memcpy(localbuffer, uptr->msg, len2);// t1,t2,t0
	}
	else{
		printf("1");

	}

	printf("Kernel() Copied msg is %s\n", localbuffer);

	free(localbuffer);

}


