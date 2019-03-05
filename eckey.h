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
bool eckey_check(const unsigned char sk[32])//check if sk meet the need
{
	//the max value of sk
	static const unsigned char need[32] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE, 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B, 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40 };
	BIGNUM *bn = BN_new();
	BIGNUM *bnneed = BN_new();
	//transform sk uchar array into big number
	BN_bin2bn(sk, 32, bn);
	BN_bin2bn(need, 32, bnneed);
	if (BN_is_zero(bn))//sk can't be all 0
		return 0;
	if (BN_cmp(bn, bnneed) > 0)//sk must less than need
		return 0;
	return 1;
}

void eckey_pk(EC_KEY *pkey, unsigned char sk[32])//produce pkey from sk(use ecc)
{
	const EC_GROUP *group;//ec group
	BIGNUM *bnsk = BN_new();
	BN_CTX *ctx = NULL;
	EC_POINT *kpoint = NULL;//a point on ec
	if (NULL == pkey)
		return;
	group = EC_KEY_get0_group(pkey);
	kpoint = EC_POINT_new(group);
	ctx = BN_CTX_new();
	if (BN_bin2bn(sk, 32, bnsk))//transform sk uchar array into big number
	{
		if (EC_POINT_mul(group, kpoint, bnsk, NULL, NULL, ctx))//compute kpoint from bnsk
		{ 
			//set sk and pk in pkey
			EC_KEY_set_private_key(pkey, bnsk);
			EC_KEY_set_public_key(pkey, kpoint);
		}
	}
	//free
	BN_clear_free(bnsk);
	EC_POINT_free(kpoint);
	BN_CTX_free(ctx);
	return;

}
int eckey_getpk(EC_KEY * pkey, unsigned char *pk, point_conversion_form_t type)//transform pk into uchar array
{
	EC_KEY_set_conv_form(pkey, type);//select compressed 
	return i2o_ECPublicKey(pkey, &pk);//transform pk into uchar array
}