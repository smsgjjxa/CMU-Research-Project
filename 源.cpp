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
	FILE *fp;//�����ļ�ָ��
	BH *bnow;//��ǰ����ָ��
	BH *bh1;//��������ָ��
	fp = fopen("bitcoin.bin", "rb");//�򿪶����������ļ�

	bnow = NULL;
	bnow = (BH*)malloc(sizeof(BH));
	b_finput(bnow, fp);//���ļ�������ͷ
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