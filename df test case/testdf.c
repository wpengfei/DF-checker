/*
 * testdf.c
 *
 *  Created on: 2016年1月29日
 *      Author: wpf
 */

/*
 * testdf.c
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

// test case for basic pattern B
void kernel_func(MSG *uptr){

	char * localbuffer =(char*) malloc(uptr->msglength);//t1, t1
	if (localbuffer != NULL){ //t1
		memcpy(localbuffer, uptr->msg, uptr->msglength);// t1,t2,t0

	}
	printf("Kernel() Copied msg is %s\n", localbuffer);

	free(localbuffer);

}





