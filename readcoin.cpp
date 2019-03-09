#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "windows.h"
#include "iostream"
#include "vector"
#include "openssl/ripemd.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include "openssl/rand.h"
#include "openssl/ssl.h"
#include "openssl/ecdsa.h"
#include "openssl/bn.h"
#include "bh.h"
#include "eckey.h"
using namespace std;
int main()
{
	FILE *fp;//block file pointer
	BH *bnow;//genesis block pointer
	BH *bh1;//current block pointer
	clock_t start_t, end_t;//time
	char path[100];

	//input binary file path
	printf("please input binary file path\n");
	memset(path, 0, sizeof(path));
	fgets(path, 100, stdin);
	path[strlen(path) - 1] = 0;
	fp = fopen(path, "rb");//open binary block file
	int num = 0;
	start_t = clock();//start to time
	bnow = NULL;
	bnow = (BH*)malloc(sizeof(BH));
	b_finput(bnow, fp);//input genesis block information from file
	bh1 = bnow;

	//output genesis block information
	printf("block %d\n", num++);
	b_print(bnow);

	while (1)
	{
		//output block information
		printf("\nblock %d\n", num++);
		b_print(bnow);

		bnow->next = (BH*)malloc(sizeof(BH));
		//input block information from file
		if (b_finput(bnow->next, fp))//if file is end
		{
			free(bnow->next);
			bnow->next = NULL;
			break;
		}
		bnow->next->pre = bnow;
		bnow = bnow->next;
	}
	fclose(fp);//close file

	//verify block in blockchain
	bnow = bh1;
	while (1)
	{
		if (bnow->next == NULL)//if blockchain is end
			break;
		if (b_cmp(bnow))//correct
			printf("correct\n");
		else//erroir
		{
			printf("error\n");
		}
		bnow = bnow->next;
	}
	end_t = clock();//stop timing
	printf("time cost %f\n", (double)(end_t - start_t) / CLOCKS_PER_SEC);//output time

	system("pause");
	return 0;
}