/*
 * testmem.cpp
 *
 *  Created on: 2015年11月6日
 *      Author: wpf
 */

#include "stdio.h"
#include "string.h"
#include <stdlib.h>

struct atom{
	int x;
	char *y;
};

typedef struct test_message{
	char msg[20];
	unsigned int msglength;
	char* c;
	struct atom *arp;
} MSG;

// test case for basic pattern A
void kernel_func(MSG *uptr ){

	//uptr->msglength = 10;

	char x = *uptr->c;

	int h = uptr->arp->x;
	char* g = *uptr->arp->y;

	printf("Kernel() Copied msg is %s\n", *uptr->msg);

	char * localbuffer =(char*) malloc(uptr->msglength);//t0 ,t0
	if (localbuffer != NULL){//t0
		memcpy(localbuffer, uptr->msg, uptr->msglength);//t0, t1, t2

	}

	free(localbuffer);

}

void func1(char* str, int* i){

	if(str){
		printf("Kernel() Copied msg is %c\n", str);
		int in = *i;
		char d = *str;
	}
}
/*
int main(){
	char *p = 'a';
	printf("hello %c\n", p);
}

int main(){

	MSG mymsg;
	mymsg.msglength = strlen("hello world!");
	strcpy(mymsg.msg, "hello world!");

	kernel_func(&mymsg);

	return 0;
}
*/




