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
typedef struct block_head//����ṹ
{
	unsigned int v;//�汾��ûɶ���õĳ�����
	unsigned int dif;//�ڿ��Ѷ�
	unsigned int n;//�ڿ����õ����������nonce
	time_t t;//ʱ���timestamp
	unsigned char hpb[32];//ǰһ����Ĺ�ϣֵ
	unsigned char pk[32];//�ڿ��ߵĹ�Կ
	unsigned char inf[44];//�ڿ������������Ϣ
	struct block_head *next, *pre;//����ǰ�������ָ��
}BH;
bool cpuc(const unsigned char *a, const unsigned char *b)//�Ƚ�������ϣֵ�Ƿ���ͬ
{
	for (int i = 0; i < 32; i++)
	{
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}
void hashb(BH *b, unsigned char *str)//������Ĺ�ϣ����
{
	SHA256_CTX c;
	memset(str, 0, sizeof(str));
	//��һ��sha256��ϣ����
	SHA256_Init(&c);
	SHA256_Update(&c, b, 84);
	SHA256_Final(str, &c);
	//�ڶ���sha256��ϣ����
	SHA256_Init(&c);
	SHA256_Update(&c, str, 32);
	SHA256_Update(&c, b->inf, 44);
	SHA256_Final(str, &c);
	return;
}
void b_init(BH *b, const unsigned char *hpb, const unsigned char *pk, const unsigned char *inf, const unsigned int version, const unsigned int dif)//�����ʼ��
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
void b_print(BH *b)//����������Ϣ
{
	printf("version:%u\ntarget:%u\nnonce:%u\ntime:%lld\n", b->v, b->dif, b->n, b->t);
	printf("information:%s\n", b->inf);
	BIGNUM *hpb = BN_new();
	BIGNUM *pk = BN_new();
	BN_bin2bn(b->hpb, 32, hpb);//��unsigned char����ת��Ϊ������
	BN_bin2bn(b->pk, 32, pk);
	char *str1 = BN_bn2hex(hpb);//��������ת��Ϊ�ַ���
	char *str2 = BN_bn2hex(pk);
	printf("hpb:%s\n", str1);
	printf("pk:%s\n", str2);
	OPENSSL_free(str1);
	OPENSSL_free(str2);
	return;
}
void b_fprint(BH *b, FILE *fp)//����������Ϣ���������ļ�
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
bool b_finput(BH *bnow, FILE *fp)//�Ӷ������ļ���ȡ������Ϣ
{
	unsigned int v;
	unsigned int dif;
	unsigned int n;
	long long int t;
	unsigned char inf[44];
	unsigned char hpb[32];
	unsigned char pk[32];

	if (fread(&v, 4, 1, fp) == 0)//����������ļ�β
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

	b_init(bnow, hpb, pk, inf, v, dif);//�ö�������Ϣ��ʼ������
	bnow->t = t;
	bnow->n = n;
	return 0;
}
bool b_cmp(BH *bnow)//��֤������ȷ��
{
	unsigned char str[32];
	memset(str, 0, sizeof(str));
	hashb(bnow, str);//�Ե�ǰ��������ϣ
	//����һ������洢��hpbֵ���Ա�
	if (cpuc(str, bnow->next->hpb))//��֤�ɹ�
		return TRUE;
	else//��֤ʧ��
	{
		return FALSE;
	}
}
