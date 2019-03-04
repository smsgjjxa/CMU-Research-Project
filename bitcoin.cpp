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

FILE *fp;//区块文件指针
BH *bh0;//创世区块指针
BH *bnow;//当前区块指针
unsigned int version = 1;//版本（没啥卵用的常数）
unsigned int dif = 2;//挖矿难度（前导0的数量）
unsigned char inf[44];//挖矿者想输入的信息（为了简化先设为一个字符串）
int order = 0;//区块序数
CRITICAL_SECTION Critical;//临界区

DWORD WINAPI mine(LPVOID lpParamter)//挖矿线程函数
{
	int flag = 0;//是否挖到区块标识
	int sq;//当前的区块序数
	int num = 0;//挖到的总区块数量
	unsigned char sk[32];//电子钱包私钥
	unsigned char pk0[33];//33位电子钱包公钥
	unsigned char pk[32];//32位电子钱包公钥
	unsigned char str[32];//哈希值缓存区
	BH *bnext;//挖到的新区块指针

	memset(pk, 0, sizeof(pk));
	memset(pk0, 0, sizeof(pk0));

	RAND_screen();//根据屏幕内容设定随机数种子
	while (1)
	{
		memset(sk, 0, sizeof(sk));
		RAND_bytes(sk, 32);//获取随机的32为unsigned char数组
		if (ECKey_Check(sk))//检查sk是否符合要求
			break;
		else
			continue;
	}
	EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);//创建椭圆曲线算法的结构
	ECKey_GenKeypair(pkey, sk);//根据sk生成密钥
	ECKey_GetPubkey(pkey, pk0, 2);//将公钥转换为unsigned char数组结构（采用压缩格式，输出33位数组）
	memcpy(pk, &pk0[1], 32);//将33位公钥转换为32位（目的为简化，后期可修改）

	while (1)
	{
		//进入临界区（防止全局变量order受到其他线程的修改）
		EnterCriticalSection(&Critical);
		sq = order;
		LeaveCriticalSection(&Critical);

		printf("mining...\n");
		//创建新的区块结构

		bnext = NULL;
		bnext = (BH*)malloc(sizeof(BH));
		memset(str, 0, sizeof(str));
		hashb(bnow, str);//对当前区块做哈希
		b_init(bnext, str, pk, inf, version, dif);//初始化区块


		while (1)
		{
			EnterCriticalSection(&Critical);
			if (order != sq)//总区块序数不等于当前线程所挖区块序数（当前区块已被其他线程挖到）
			{
				LeaveCriticalSection(&Critical);
				break;
			}
			LeaveCriticalSection(&Critical);

			flag = 0;
			bnext->t = time(0);//获取时间戳

			memset(str, 0, sizeof(str));
			hashb(bnext, str);//对新区块做哈希

			for (int i = 0; i < dif; i++)//检测是否挖到区块（是否符合挖矿难度规定的前导0的数量）
			{
				if (str[i] != 0)
				{
					flag = 1;
					break;
				}
			}

			if (flag)//没挖到
			{
				bnext->n++;//nonce递增
				continue;
			}
			else//挖到了
			{
				EnterCriticalSection(&Critical);
				if (order != sq)//检测是否已被其他线程（挖矿者）挖到
				{
					LeaveCriticalSection(&Critical);
					break;
				}
				order++;//总区块序数增加
				num++;//当前进程挖到的总区块数增加
				//输出区块信息
				printf("block %d has been mined\n", order);
				b_print(bnext);
				b_fprint(bnext, fp);//输出区块信息到二进制文件
				//调整当前区块指针
				bnow->next = bnext;
				bnext->pre = bnow;
				bnow = bnow->next;
				bnext = bnext->next;
				if (order == 100 || order == 0)//检测是否挖到了第2016个区块
					order = 0;
				LeaveCriticalSection(&Critical);
				break;
			}
		}
		if (order == 0)//检测是否挖到了第2016个区块
			break;
	}
	//挖矿结束

	BIGNUM *pk_bn = BN_new();
	BN_bin2bn(pk, 32, pk_bn);
	char *pkh = BN_bn2hex(pk_bn);
	BIGNUM *sk_bn = BN_new();
	BN_bin2bn(sk, 32, sk_bn);
	char *skh = BN_bn2hex(sk_bn);

	//输出挖矿者的信息（挖到的总区块等）
	EnterCriticalSection(&Critical);
	printf("\nPK:%s\n", pkh);
	printf("SK:%s\n", skh);
	printf("number of block:%d\n", num);
	LeaveCriticalSection(&Critical);

	OPENSSL_free(pkh);
	OPENSSL_free(skh);
	return 0;
}
int main()
{
	vector<HANDLE>miner(10);//设定10个挖矿线程句柄
	clock_t start_t, end_t;//时间戳
	unsigned char str0[32];//创世区块的hpb和pk信息
	memset(inf, 0, sizeof(inf));
	memset(str0, 0, sizeof(str0));
	strcpy((char*)inf, "I CAN FLY");
	strcpy((char*)str0, "0");
	InitializeCriticalSection(&Critical);//初始化临界区
	start_t = clock();//开始计时
	fp = fopen("bitcoin.bin", "wb+");

	//初始化创世区块指针
	bh0 = (BH*)malloc(sizeof(BH));
	bnow = bh0;
	b_init(bh0, str0, str0, inf, version, dif);
	for (int i = 0; i < 10; i++)
	{
		miner[i] = CreateThread(NULL, 0, mine, NULL, 0, 0);//创建并开始挖矿线程
	}

	for (int i = 0; i < 10; i++)
	{
		WaitForSingleObject(miner[i], INFINITE);//等待挖矿线程退出
	}

	end_t = clock();//停止计时
	printf("time cost %f\n", (double)(end_t - start_t) / CLOCKS_PER_SEC);//输出总耗时
	fclose(fp);

	//以下为验证所有挖到的区块，可以注释掉
	BH *bh1;//创世区块指针
	fp = fopen("bitcoin.bin", "rb");//打开二进制区块文件

	bnow = NULL;
	bnow = (BH*)malloc(sizeof(BH));
	b_finput(bnow, fp);//从文件读创世区块
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
