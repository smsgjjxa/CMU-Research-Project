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
typedef struct block_head//区块结构
{
	unsigned int v;//版本（没啥卵用的常数）
	unsigned int dif;//挖矿难度
	unsigned int n;//挖矿中用到的随机向量nonce
	time_t t;//时间戳timestamp
	unsigned char hpb[32];//前一个块的哈希值
	unsigned char pk[32];//挖矿者的公钥
	unsigned char inf[44];//挖矿者想输入的信息
	struct block_head *next, *pre;//连接前后区块的指针
}BH;
bool cpuc(const unsigned char *a, const unsigned char *b)//比较两个哈希值是否相同
{
	for (int i = 0; i < 32; i++)
	{
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}
void hashb(BH *b, unsigned char *str)//对区块的哈希操作
{
	SHA256_CTX c;
	memset(str, 0, sizeof(str));
	//第一次sha256哈希操作
	SHA256_Init(&c);
	SHA256_Update(&c, b, 84);
	SHA256_Final(str, &c);
	//第二次sha256哈希操作
	SHA256_Init(&c);
	SHA256_Update(&c, str, 32);
	SHA256_Update(&c, b->inf, 44);
	SHA256_Final(str, &c);
	return;
}
void b_init(BH *b, const unsigned char *hpb, const unsigned char *pk, const unsigned char *inf, const unsigned int version, const unsigned int dif)//区块初始化
{
	memset(b, 0, sizeof(b));
	memcpy(b->hpb, hpb, 32);
	memset(b->inf, 0, sizeof(b->inf));
	memcpy(b->inf, inf, 44);
	memcpy(b->pk, pk, 32);
	b->n = 0;
	b->v = version;
	b->dif = dif;
	b->pre = NULL;
	b->next = NULL;
	return;
}
void b_print(BH *b)//输出区块的信息
{
	printf("version:%u\ntarget:%u\nnonce:%u\ntime:%lld\n", b->v, b->dif, b->n, b->t);
	printf("information:%s\n", b->inf);
	BIGNUM *hpb = BN_new();
	BIGNUM *pk = BN_new();
	BN_bin2bn(b->hpb, 32, hpb);//将unsigned char数组转换为大整数
	BN_bin2bn(b->pk, 32, pk);
	char *str1 = BN_bn2hex(hpb);//将大整数转换为字符串
	char *str2 = BN_bn2hex(pk);
	printf("hpb:%s\n", str1);
	printf("pk:%s\n", str2);
	OPENSSL_free(str1);
	OPENSSL_free(str2);
	return;
}
void b_fprint(BH *b, FILE *fp)//输出区块的信息到二进制文件
{
	fwrite(&b->v, 4, 1, fp);
	fwrite(&b->dif, 4, 1, fp);
	fwrite(&b->n, 4, 1, fp);
	fwrite(&b->t, 8, 1, fp);
	fwrite(b->inf, 1, 44, fp);
	fwrite(b->hpb, 1, 32, fp);
	fwrite(b->pk, 1, 32, fp);
	return;
}
bool b_finput(BH *bnow, FILE *fp)//从二进制文件读取区块信息
{
	unsigned int v;
	unsigned int dif;
	unsigned int n;
	long long int t;
	unsigned char inf[44];
	unsigned char hpb[32];
	unsigned char pk[32];

	if (fread(&v, 4, 1, fp) == 0)//如果读到了文件尾
	{
		return 1;
	}
	fread(&dif, 4, 1, fp);
	fread(&n, 4, 1, fp);
	fread(&t, 8, 1, fp);
	memset(inf, 0, sizeof(inf));
	fread(inf, 1, 44, fp);
	memset(hpb, 0, sizeof(hpb));
	fread(hpb, 1, 32, fp);
	memset(pk, 0, sizeof(pk));
	fread(pk, 1, 32, fp);

	b_init(bnow, hpb, pk, inf, v, dif);//用读到的信息初始化区块
	bnow->t = t;
	bnow->n = n;
	return 0;
}
bool b_cmp(BH *bnow)//验证区块正确性
{
	unsigned char str[32];
	memset(str, 0, sizeof(str));
	hashb(bnow, str);//对当前区块做哈希
	//与下一个区块存储的hpb值做对比
	if (cpuc(str, bnow->next->hpb))//验证成功
		return TRUE;
	else//验证失败
	{
		return FALSE;
	}
}
