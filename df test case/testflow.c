#include "stdio.h"
#include "string.h"

int main(){
	char p[256] = {0};
	char *q;


	system(p);

	FILE * pFile=fopen ("myfile.txt","r");
	p[0] = getc(pFile);

	system(p);
	q=p;
	system(q);

	return 0;
}
