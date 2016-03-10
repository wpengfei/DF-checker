/*
 * test_record_func.c
 *
 *  Created on: 2016年2月2日
 *      Author: wpf
 */


#include "stdio.h"
#include "string.h"
#include <stdlib.h>

typedef struct test_message{
	char msg[20];
	char *msgptr;
	int n;
	unsigned int msglength ;
} MSG;


// none invoke functions

void func3(MSG *uptr, int a){
	printf("func3:%d",a);
	int b = uptr->msglength;
}

void func2(MSG *uptr){
	//printf("func2:%d",*a);
	int b = uptr->msglength;
}

void func1(MSG *uptr, int x){
	printf("func1:%d",uptr->msglength);
	func2(uptr);
	func3(uptr, x);
}



// test case to distinguish  multiple function with multiple parameters
void copy_msg(MSG *uptr, int in){
	printf("funccopy:%d",in);
	char * localbuffer =(char*) malloc(uptr->msglength);//t1, t1
	if (localbuffer != NULL){ //t1
		memcpy(localbuffer, uptr->msg, uptr->msglength);// t1,t2,t0
	}
	free(localbuffer);
}

void kernel_func2(MSG *uptr, int *p){
	int len = uptr->msglength;
	copy_msg(uptr, len);
	printf("func1:%d", *p);
}

void sys_call(MSG *uptr, int x){
	int len2 = uptr->msglength;
	kernel_func2(uptr, &len2);
	printf("func1:%d", x);
}

//-----------------------------
//-----------------------------



