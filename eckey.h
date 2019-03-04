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
bool ECKey_Check(const unsigned char vch[32])//������ɵ�˽Կ�Ƿ��������
{
	static const unsigned char Need[32] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE, 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B, 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40 };
	BIGNUM *bn = BN_new(); // ˽Կ 
	BIGNUM *bnNeed = BN_new(); // G��Fp�µ����order  
	BN_bin2bn(vch, 32, bn); //������������ת��Ϊһ�������� 
	BN_bin2bn(Need, 32, bnNeed); //** 0 < [˽Կ] < order 
	if (BN_is_zero(bn))
		return 0; // ˽Կ����Ϊ0 
	if (BN_cmp(bn, bnNeed) > 0)
		return 0; //˽Կ����С��order
	return 1;
}

void ECKey_GenKeypair(EC_KEY * pkey, unsigned char vch[32])//��������ɵ�˽Կ������Կ�����ñ��ر��õ�����Բ�����㷨��
{
	int key_size = 32;
	const EC_GROUP * group;
	BIGNUM *privkey = BN_new();
	BN_CTX *ctx = NULL;
	EC_POINT *pubkey = NULL;
	if (NULL == pkey)
		return;
	group = EC_KEY_get0_group(pkey); // group�ṹ���д洢��Gֵ��������� 
	pubkey = EC_POINT_new(group); // ��pubkey�����ڴ棬pubkeyΪ�����ϵ�һ���� 
	ctx = BN_CTX_new();
	if (BN_bin2bn(vch, 32, privkey)) // ��˽Կ����������ʽ��ת��Ϊһ�������� 
	{
		if (EC_POINT_mul(group, pubkey, privkey, NULL, NULL, ctx)) // ����pubkey =privkey*G 
		{ // ����Կ�洢��EC_KEY�ṹ���У����ڵ���Ϊ����ĸ�ʽ
			EC_KEY_set_private_key(pkey, privkey);
			EC_KEY_set_public_key(pkey, pubkey);
		}
	}
	BN_clear_free(privkey);
	EC_POINT_free(pubkey);
	BN_CTX_free(ctx);
	return;

}
int ECKey_GetPubkey(EC_KEY * pkey, unsigned char * pubkey, int fCompressed)//����Կת��Ϊunsigned char������ʽ
{
	uint32_t cb;
	EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);//ѡ��Կ���������ʽ
	cb = i2o_ECPublicKey(pkey, NULL);//������Ҫ���ֽ���
	if (0 == cb || cb > 65)
		return 0;
	if (NULL == pubkey)
		return cb;
	cb = i2o_ECPublicKey(pkey, &pubkey);//ת��Ϊunsigned char����
	return cb;
}