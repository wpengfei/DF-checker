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
	char *ptr;
	unsigned int msglength ;
} MSG;

// test case to distinguish  multiple function with multiple parameters

void kernel_func1(MSG *uptr, char* str1, int x){
	MSG* p = uptr;
	MSG* q = uptr; // ---
	MSG m1 = *uptr;
	MSG m2 = *uptr; // ***
	char* cp1 = uptr->ptr;
	char* cp2 = uptr->ptr; // ***
	unsigned int l1 = p->msglength;
	unsigned int l2 = p->msglength; // ***
	unsigned int len = uptr->msglength;// t0, t0
	unsigned int len2 = len +2;// t0, t0
	unsigned int len3 = uptr->msglength +2;

	if (len2 == len3)
		printf("len %d", uptr->msglength);
}

void kernel_func2(MSG *uptr, char* str){


	char * localbuffer =(char*) malloc(uptr->msglength);//t1, t1
	if (localbuffer != NULL){ //t1
		memcpy(localbuffer, str, uptr->msglength);// t1,t2,t0
	}

	free(localbuffer);

}


