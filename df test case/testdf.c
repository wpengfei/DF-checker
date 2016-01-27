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
	unsigned int msglength;
	char* c;
} MSG;

// test case for basic pattern A
void kernel_func(MSG *uptr ){

	uptr->msglength = 10;

	char * localbuffer =(char*) malloc(uptr->msglength);//t0 ,t0
	if (localbuffer != NULL){//t0
		memcpy(localbuffer, uptr->msg, uptr->msglength);//t0, t1, t2

	}

	printf("local buffer is %s\n", localbuffer);
	printf("Kernel() Copied msg is %s\n", uptr->msg);

	free(localbuffer);

}

void func1(char* str){

	if(str){
		printf("Kernel() Copied msg is %c\n", str);
		printf("Kernel() Copied msg is %c\n", *str);
		char d = *str;
	}
}
int main(){
	char *p = 'a';
	printf("hello %c\n", p);
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




