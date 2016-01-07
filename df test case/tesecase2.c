/*
 * tesecase2.c
 *
 *  Created on: 2016年1月5日
 *      Author: wpf
 */

#include "stdio.h"
#include "string.h"
#include <stdlib.h>

typedef struct test_message{
	char msg[20];
	unsigned int msglength ;
} MSG;

// test case to distinguish  multiple function with multiple parameters

void kernel_func1(MSG *uptr, char* str1, int x){
	unsigned int len = uptr->msglength;// t0, t0
	unsigned int len2 = len +2;// t0, t0
	unsigned int len3 = len2 +2;

	if (len2 > 0)
		len2 = uptr->msglength;

	printf("len %d", len2);
}

void kernel_func2(MSG *uptr, char* str){


	char * localbuffer =(char*) malloc(uptr->msglength);//t1, t1
	if (localbuffer != NULL){ //t1
		memcpy(localbuffer, str, uptr->msglength);// t1,t2,t0
	}

	free(localbuffer);

}


