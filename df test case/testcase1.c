/*
 * testcase1.c

 *
 *  Created on: 2016年1月5日
 *      Author: wpf
 */

#include <stdint.h>

typedef uint32_t DWORD;
typedef uint8_t BYTE;
typedef uint32_t* PDWORD;
typedef uint8_t* PBYTE;

int test_memcmp(const void *ptr1, const void *ptr2, uint64_t num) {
	while(num >= sizeof(DWORD)){
		if(*(PDWORD)ptr1 != *(PDWORD)ptr2){
			num = sizeof(DWORD);
			break;
		}
		ptr1 += sizeof(DWORD);
		ptr2 += sizeof(DWORD);
		num -= sizeof(DWORD);
	}
	while(num > 0){
		BYTE x = *(PBYTE)ptr1;
		BYTE y = *(PBYTE)ptr2;
		if(x < y){
			return -1;
		}else if(y > x){
			return 1;
		}
		ptr1++; ptr2++;
		num--;
	}
	return 0;
}



