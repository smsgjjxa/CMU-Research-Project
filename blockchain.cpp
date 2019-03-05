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
#define BLOCK_NUM 100
#define MINER_NUM 10
FILE *fp;//block file pointer
BH *bh0;//genesis block pointer
BH *bnow;//current block pointer
unsigned int version = 1;//version(a useless constant)
unsigned int dif = 0;//target:difficulty of mining(the number of front 0)
unsigned char inf[43];//information miners want to write in block(for simplification set all information the same string)
int order = 0;//the order of block
CRITICAL_SECTION Critical;//critical area(prevent thread interaction)
int front0;//the max value of hash of block(compute from taget)

DWORD WINAPI mine(LPVOID lpParamter)//thread fucnction of miners
{
	int sq;//current order of mining block
	int num = 0;//total number of mined block
	unsigned char sk[32];//32 bit serect key of e-wallet
	unsigned char pk[33];//33 bit public key of e-wallet
	unsigned char str[32];//hash value buffer
	BH *bnext;//mining block pointer
	memset(pk, 0, sizeof(pk));
	
	RAND_screen();//set random seed according to screen
	while (1)
	{
		memset(sk, 0, sizeof(sk));
		RAND_bytes(sk, 32);//get random 32 bit unsigned char array 
		if (eckey_check(sk))//check if sk meet the need
			break;
		else
			continue;
	}
	EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);//creat a structure of ecc
	eckey_pk(pkey, sk);//generate pk structure according to sk
	eckey_getpk(pkey, pk, POINT_CONVERSION_COMPRESSED);//turn pkey into pk(compressed 33 bit uchar array)
	
	while (1)
	{
		//critical area(prevent order from modifying by other thread)
		EnterCriticalSection(&Critical);
		sq = order;
		LeaveCriticalSection(&Critical);

		printf("mining...\n");

		//create new block
		bnext = NULL;
		bnext = (BH*)malloc(sizeof(BH));
		memset(str, 0, sizeof(str));
		hashb(bnow, str);//compute hash value of current block
		b_init(bnext, str, pk, inf, version, dif);//init new block

		while (1)
		{
			EnterCriticalSection(&Critical);
			if (order != sq)//current block has been already mined by other thread
			{
				LeaveCriticalSection(&Critical);
				break;
			}
			LeaveCriticalSection(&Critical);

			bnext->t = time(0);//get timestamp

			memset(str, 0, sizeof(str));
			hashb(bnext, str);//compute hash value of new block

			//check if new block is correct(meet the need of front 0)	
			if (!b_check(str, dif, front0))//not meet
			{
				bnext->n++;//nonce++
				continue;
			}
			else//meet
			{
				EnterCriticalSection(&Critical);
				if (order != sq)//check if current block has been already mined by other thread
				{
					LeaveCriticalSection(&Critical);
					break;
				}
				order++;
				num++;
				//print information of new block
				printf("block %d has been mined\n", order);
				b_print(bnext);
				b_fprint(bnext, fp);//output information of new block into binary file
				//adjust the pointer of block
				bnow->next = bnext;
				bnext->pre = bnow;
				bnow = bnow->next;
				bnext = bnext->next;
				if (order == BLOCK_NUM || order == 0)//check if it should stop mining(the number of block meet the need)
					order = 0;
				LeaveCriticalSection(&Critical);
				break;
			}
		}
		if (order == 0)//check if it should stop mining(the number of block meet the need)
			break;
	}
	//stop mining

	BIGNUM *pk_bn = BN_new();
	BN_bin2bn(pk, 33, pk_bn);
	char *pkh = BN_bn2hex(pk_bn);
	BIGNUM *sk_bn = BN_new();
	BN_bin2bn(sk, 32, sk_bn);
	char *skh = BN_bn2hex(sk_bn);

	//output information of miners
	EnterCriticalSection(&Critical);
	printf("\nPK:%s\n", pkh);
	printf("SK:%s\n", skh);
	printf("number of block:%d\n", num);
	LeaveCriticalSection(&Critical);

	OPENSSL_free(pkh);
	OPENSSL_free(skh);
	return 0;
}
int main(int argc, char **argv)
{
	//init
	vector<HANDLE>miner(MINER_NUM);//set vector of miner thread
	clock_t start_t, end_t;//time
	unsigned char str0[33];//hpb and pk of genesis block pointer
	memset(str0, 0, sizeof(str0));
	InitializeCriticalSection(&Critical);//init critical area
	fp = fopen("bitcoin.bin", "wb+");//open binary block file
	front0 = pow(2, 8 - (dif % 8)) - 1;//compute front0
	//input information which will be add to block

	printf("please input information\n");
	memset(inf, 0, sizeof(inf));
	fgets((char*)inf, 43, stdin);
	printf("please input target\n");
	scanf("%d", &dif);
	start_t = clock();//start to time

	//init genesis block pointer
	bh0 = (BH*)malloc(sizeof(BH));
	bnow = bh0;
	b_init(bh0, str0, str0, inf, version, dif);
	for (int i = 0; i < MINER_NUM; i++)
	{
		miner[i] = CreateThread(NULL, 0, mine, NULL, 0, 0);//creat miner thread
	}

	for (int i = 0; i < MINER_NUM; i++)
	{
		WaitForSingleObject(miner[i], INFINITE);//wait threads to exit
	}
	fclose(fp);

	end_t = clock();//stop timing
	printf("time cost %f\n", (double)(end_t - start_t) / CLOCKS_PER_SEC);//output time
	FILE *f;
	f = fopen("time.txt", "a+");
	fprintf(f, "%d : %f\n", dif, (double)(end_t - start_t) / CLOCKS_PER_SEC);//output time
	fclose(f);

	system("pause");
	return 0;
}
