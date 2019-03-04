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

FILE *fp;//�����ļ�ָ��
BH *bh0;//��������ָ��
BH *bnow;//��ǰ����ָ��
unsigned int version = 1;//�汾��ûɶ���õĳ�����
unsigned int dif = 2;//�ڿ��Ѷȣ�ǰ��0��������
unsigned char inf[44];//�ڿ������������Ϣ��Ϊ�˼�����Ϊһ���ַ�����
int order = 0;//��������
CRITICAL_SECTION Critical;//�ٽ���

DWORD WINAPI mine(LPVOID lpParamter)//�ڿ��̺߳���
{
	int flag = 0;//�Ƿ��ڵ������ʶ
	int sq;//��ǰ����������
	int num = 0;//�ڵ�������������
	unsigned char sk[32];//����Ǯ��˽Կ
	unsigned char pk0[33];//33λ����Ǯ����Կ
	unsigned char pk[32];//32λ����Ǯ����Կ
	unsigned char str[32];//��ϣֵ������
	BH *bnext;//�ڵ���������ָ��

	memset(pk, 0, sizeof(pk));
	memset(pk0, 0, sizeof(pk0));

	RAND_screen();//������Ļ�����趨���������
	while (1)
	{
		memset(sk, 0, sizeof(sk));
		RAND_bytes(sk, 32);//��ȡ�����32Ϊunsigned char����
		if (ECKey_Check(sk))//���sk�Ƿ����Ҫ��
			break;
		else
			continue;
	}
	EC_KEY *pkey = EC_KEY_new_by_curve_name(NID_secp256k1);//������Բ�����㷨�Ľṹ
	ECKey_GenKeypair(pkey, sk);//����sk������Կ
	ECKey_GetPubkey(pkey, pk0, 2);//����Կת��Ϊunsigned char����ṹ������ѹ����ʽ�����33λ���飩
	memcpy(pk, &pk0[1], 32);//��33λ��Կת��Ϊ32λ��Ŀ��Ϊ�򻯣����ڿ��޸ģ�

	while (1)
	{
		//�����ٽ�������ֹȫ�ֱ���order�ܵ������̵߳��޸ģ�
		EnterCriticalSection(&Critical);
		sq = order;
		LeaveCriticalSection(&Critical);

		printf("mining...\n");
		//�����µ�����ṹ

		bnext = NULL;
		bnext = (BH*)malloc(sizeof(BH));
		memset(str, 0, sizeof(str));
		hashb(bnow, str);//�Ե�ǰ��������ϣ
		b_init(bnext, str, pk, inf, version, dif);//��ʼ������


		while (1)
		{
			EnterCriticalSection(&Critical);
			if (order != sq)//���������������ڵ�ǰ�߳�����������������ǰ�����ѱ������߳��ڵ���
			{
				LeaveCriticalSection(&Critical);
				break;
			}
			LeaveCriticalSection(&Critical);

			flag = 0;
			bnext->t = time(0);//��ȡʱ���

			memset(str, 0, sizeof(str));
			hashb(bnext, str);//������������ϣ

			for (int i = 0; i < dif; i++)//����Ƿ��ڵ����飨�Ƿ�����ڿ��Ѷȹ涨��ǰ��0��������
			{
				if (str[i] != 0)
				{
					flag = 1;
					break;
				}
			}

			if (flag)//û�ڵ�
			{
				bnext->n++;//nonce����
				continue;
			}
			else//�ڵ���
			{
				EnterCriticalSection(&Critical);
				if (order != sq)//����Ƿ��ѱ������̣߳��ڿ��ߣ��ڵ�
				{
					LeaveCriticalSection(&Critical);
					break;
				}
				order++;//��������������
				num++;//��ǰ�����ڵ���������������
				//���������Ϣ
				printf("block %d has been mined\n", order);
				b_print(bnext);
				b_fprint(bnext, fp);//���������Ϣ���������ļ�
				//������ǰ����ָ��
				bnow->next = bnext;
				bnext->pre = bnow;
				bnow = bnow->next;
				bnext = bnext->next;
				if (order == 100 || order == 0)//����Ƿ��ڵ��˵�2016������
					order = 0;
				LeaveCriticalSection(&Critical);
				break;
			}
		}
		if (order == 0)//����Ƿ��ڵ��˵�2016������
			break;
	}
	//�ڿ����

	BIGNUM *pk_bn = BN_new();
	BN_bin2bn(pk, 32, pk_bn);
	char *pkh = BN_bn2hex(pk_bn);
	BIGNUM *sk_bn = BN_new();
	BN_bin2bn(sk, 32, sk_bn);
	char *skh = BN_bn2hex(sk_bn);

	//����ڿ��ߵ���Ϣ���ڵ���������ȣ�
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
	vector<HANDLE>miner(10);//�趨10���ڿ��߳̾��
	clock_t start_t, end_t;//ʱ���
	unsigned char str0[32];//���������hpb��pk��Ϣ
	memset(inf, 0, sizeof(inf));
	memset(str0, 0, sizeof(str0));
	strcpy((char*)inf, "I CAN FLY");
	strcpy((char*)str0, "0");
	InitializeCriticalSection(&Critical);//��ʼ���ٽ���
	start_t = clock();//��ʼ��ʱ
	fp = fopen("bitcoin.bin", "wb+");

	//��ʼ����������ָ��
	bh0 = (BH*)malloc(sizeof(BH));
	bnow = bh0;
	b_init(bh0, str0, str0, inf, version, dif);
	for (int i = 0; i < 10; i++)
	{
		miner[i] = CreateThread(NULL, 0, mine, NULL, 0, 0);//��������ʼ�ڿ��߳�
	}

	for (int i = 0; i < 10; i++)
	{
		WaitForSingleObject(miner[i], INFINITE);//�ȴ��ڿ��߳��˳�
	}

	end_t = clock();//ֹͣ��ʱ
	printf("time cost %f\n", (double)(end_t - start_t) / CLOCKS_PER_SEC);//����ܺ�ʱ
	fclose(fp);

	//����Ϊ��֤�����ڵ������飬����ע�͵�
	BH *bh1;//��������ָ��
	fp = fopen("bitcoin.bin", "rb");//�򿪶����������ļ�

	bnow = NULL;
	bnow = (BH*)malloc(sizeof(BH));
	b_finput(bnow, fp);//���ļ�����������
	bh1 = bnow;
	while (1)
	{
		b_print(bnow);
		bnow->next = (BH*)malloc(sizeof(BH));
		//���ļ�������
		if (b_finput(bnow->next, fp))//����������ļ�β
		{
			free(bnow->next);
			bnow->next = NULL;
			break;
		}
		bnow->next->pre = bnow;
		bnow = bnow->next;
	}
	fclose(fp);//�ر������ļ�

	bnow = bh1;
	while (1)
	{
		if (bnow->next == NULL)//�Ƿ񵽴�������ĩβ
			break;
		if (b_cmp(bnow))//��֤�ɹ�
			printf("correct\n");
		else//��֤ʧ��
		{
			printf("error\n");
		}
		bnow = bnow->next;
	}
	system("pause");
	return 0;
}