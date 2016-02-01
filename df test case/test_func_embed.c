/*
 * test_func_embed.c
 *
 *  Created on: 2016年1月27日
 *      Author: wpf
 */


#include "stdio.h"
#include "string.h"
#include <stdlib.h>

void func3(int *a){
	printf("func3:%d",*a);
	int b = *a;
}


void func1(int *a){
	printf("func1:%d",*a);
	int b = *a;
}

void func2(int *a){
	printf("func2:%d",*a);
	func1(a);
}


int func_main(int* m){

	int n = *m;
	func2(m);

	int *p;
	p = m;

	func1(p);

	printf("func main :%d",*p);


}

