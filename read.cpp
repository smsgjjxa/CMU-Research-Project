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
	FILE *fp;//区块文件指针
	BH *bnow;//当前区块指针
	BH *bh1;//创世区块指针
	fp = fopen("bitcoin.bin", "rb");//打开二进制区块文件

	bnow = NULL;
	bnow = (BH*)malloc(sizeof(BH));
	b_finput(bnow, fp);//从文件读区块头
	bh1 = bnow;
	while (1)
	{
		b_print(bnow);
		bnow->next = (BH*)malloc(sizeof(BH));
		//从文件读区块
		if (b_finput(bnow->next, fp))//如果读到了文件尾
		{
			free(bnow->next);
			bnow->next = NULL;
			break;
		}
		bnow->next->pre = bnow;
		bnow = bnow->next;
	}
	fclose(fp);//关闭区块文件

	bnow = bh1;
	while (1)
	{
		if (bnow->next == NULL)//是否到达区块链末尾
			break;
		if (b_cmp(bnow))//验证成功
			printf("correct\n");
		else//验证失败
		{
			printf("error\n");
		}
		bnow = bnow->next;
	}
	system("pause");
	return 0;
}
