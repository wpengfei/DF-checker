/*
 * test_alias.c
 *
 *  Created on: 2016年1月29日
 *      Author: wpf
 */

#include "stdio.h"
#include "string.h"
#include <stdlib.h>

typedef struct test_message{
	char msg[20];
	unsigned int msglength ;
} MSG;

// test case for basic pattern B
void kernel_func(MSG *uptr){

	signed int len = uptr->msglength + 3;

	MSG *tp;

	tp = uptr;

	char *pc;

	pc = uptr->msg;


	char * localbuffer =(char*) malloc(uptr->msglength);//t1, t1
	if (localbuffer != NULL){ //t1
		memcpy(localbuffer, uptr->msg, uptr->msglength);// t1,t2,t0

	}

	unsigned int x = tp->msglength;


	free(localbuffer);

}


