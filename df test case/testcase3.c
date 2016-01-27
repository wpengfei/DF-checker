/*
 * testcase3.c
 *
 *  Created on: 2016年1月14日
 *      Author: wpf
 */

#include "stdio.h"
#include "string.h"
#include <stdlib.h>

typedef struct test_message{
	char msg[20];
	char *msgptr;
	unsigned int msglength ;
} MSG;

// test case to distinguish  multiple function with multiple parameters
void copy_msg(MSG *uptr, char* str){

	if (uptr->msgptr){
		printf("ss%c", uptr->msgptr);
	}

	char * localbuffer =(char*) malloc(uptr->msglength);//t1, t1
	if (localbuffer != NULL){ //t1
		memcpy(localbuffer, str, uptr->msglength);// t1,t2,t0
	}

	free(localbuffer);

}

void kernel_func1(MSG *uptr, char* str1, int x){
	if (uptr){
		copy_msg(uptr,str1);
	}
	printf("ss%s", str1);
}





