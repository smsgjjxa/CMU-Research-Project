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
using namespace std;
//block size is 128byte
typedef struct block_head//block structure
{
	unsigned int v;//version(a useless constant)
	unsigned int dif;//target:difficulty of mining(the number of front 0)
	unsigned int n;//nonce
	time_t t;//timestamp
	unsigned char hpb[32];//hash value of previous block
	unsigned char pk[33];//public key
	unsigned char inf[43];//information miners want to write in block
	struct block_head *next, *pre;//pointer of next and previous block
}BH;
int sq(int a, int b)//square for int
{
	int c=1;
	for (int i = 0; i < b; i++)
	{
		c *= a;
	}
	return c;
}
//compute twice sha256
void hashb(BH *b, unsigned char *str)//compute hash value of block
{
	SHA256_CTX c;
	memset(str, 0, sizeof(str));
	//sha256 once
	SHA256_Init(&c);
	SHA256_Update(&c, b, 85);
	SHA256_Final(str, &c);
	//sha256 twice
	SHA256_Init(&c);
	SHA256_Update(&c, str, 32);
	SHA256_Update(&c, b->inf, 43);
	SHA256_Final(str, &c);
	return;
}
void b_init(BH *b, const unsigned char *hpb, const unsigned char *pk, const unsigned char *inf, const unsigned int version, const unsigned int dif)//init block
{
	memset(b, 0, sizeof(b));
	memcpy(b->hpb, hpb, 32);
	memset(b->inf, 0, sizeof(b->inf));
	memcpy(b->inf, inf, 43);
	memcpy(b->pk, pk, 33);
	b->n = 0;
	b->v = version;
	b->dif = dif;
	b->pre = NULL;
	b->next = NULL;
	return;
}
void b_print(BH *b)//output information of block
{
	printf("version:%u\ntarget:%u\nnonce:%u\ntime:%lld\n", b->v, b->dif, b->n, b->t);
	BIGNUM *hpb = BN_new();
	BIGNUM *pk = BN_new();
	//transform uchar array into big number
	BN_bin2bn(b->hpb, 32, hpb);
	BN_bin2bn(b->pk, 33, pk);
	//transform big number into string
	char *str1 = BN_bn2hex(hpb);
	char *str2 = BN_bn2hex(pk);
	printf("hpb:");
	int len = strlen(str1);
	for (int i = 0; i < 64-len; i++)//fill up the front 0
	{
		printf("0");
	}
	printf("%s\n", str1);
	printf("pk:%s\n", str2);
	printf("information:%s\n", b->inf);
	OPENSSL_free(str1);
	OPENSSL_free(str2);
	return;
}
void b_fprint(BH *b, FILE *fp)//output information of block into binary file
{
	fwrite(&b->v, 4, 1, fp);
	fwrite(&b->dif, 4, 1, fp);
	fwrite(&b->n, 4, 1, fp);
	fwrite(&b->t, 8, 1, fp);
	fwrite(b->hpb, 1, 32, fp);
	fwrite(b->pk, 1, 33, fp);
	fwrite(b->inf, 1, 43, fp);
	return;
}
bool b_finput(BH *bnow, FILE *fp)//input block information from binary file
{
	unsigned int v;
	unsigned int dif;
	unsigned int n;
	long long int t;
	unsigned char inf[43];
	unsigned char hpb[32];
	unsigned char pk[33];

	if (fread(&v, 4, 1, fp) == 0)//if file is end
	{
		return 1;
	}
	fread(&dif, 4, 1, fp);
	fread(&n, 4, 1, fp);
	fread(&t, 8, 1, fp);
	memset(hpb, 0, sizeof(hpb));
	fread(hpb, 1, 32, fp);
	memset(pk, 0, sizeof(pk));
	fread(pk, 1, 33, fp);
	memset(inf, 0, sizeof(inf));
	fread(inf, 1, 43, fp);

	b_init(bnow, hpb, pk, inf, v, dif);//init block
	bnow->t = t;
	bnow->n = n;
	return 0;
}
bool b_cmp(BH *bnow)//verify block
{
	unsigned char str[32];
	memset(str, 0, sizeof(str));
	hashb(bnow, str);//compute hash value of current block
	//compare with next block
	if (!memcmp(str, bnow->next->hpb, 32))//correct
		return TRUE;
	else//error
	{
		return FALSE;
	}
}
bool b_check(unsigned char *str, unsigned int dif, int front0)//check if new block is correct(meet the need of front 0)
{
	int num = dif / 8;
	for (int i = 0; i < num; i++)//check if bytes in front are all 0
	{
		if (str[i] != 0)
		{
			return 0;
			break;
		}
	}
	if (str[num] > front0)//check if the last byte is correct(meet the need of front 0)
	{
		return 0;
	}
	return 1;
}
