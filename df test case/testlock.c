/*
 * testlock.c
 *
 *  Created on: 2015年10月28日
 *      Author: wpf
 */

#include<stdio.h>
#include<pthread.h>

static pthread_mutex_t lock;
pthread_t thread_1;
pthread_t thread_2;

int a = 0;

void* func_1()
{
	pthread_mutex_lock(&lock);
	pthread_mutex_lock(&lock);
	printf("thread fun1() lock\n");
	a = 2;
	printf("thread fun1() a= %d\n", a);
	printf("thread fun1() unlock\n");
	pthread_mutex_unlock(&lock);
	return NULL;
}

void* func_2()
{
	pthread_mutex_lock(&lock);
	printf("thread fun2() lock\n");
	a = 3;
	printf("thread fun2() a= %d\n", a);

	return NULL;
}

int main()
{
	pthread_mutex_init(&lock, NULL);

	pthread_mutex_lock(&lock);
	a = 1;
	printf("Main thread lock, a = %d\n", a);


	if (pthread_create(&thread_1, NULL, func_1, NULL) != 0)
		printf("Create thread_1 failed\n");
	if (pthread_create(&thread_2, NULL, func_2, NULL) != 0)
		printf("Create thread_2 failed\n");

	sleep(1);
	printf("Main thread unlock, a = %d \n",a);

	// double unlock
	pthread_mutex_unlock(&lock);
	pthread_mutex_unlock(&lock);


	pthread_join(thread_1,NULL);
	pthread_join(thread_2,NULL);
	pthread_mutex_destroy(&lock);
	return 0;
}

//make
//gcc -D_REENTRANT -lpthread -o test test.c
