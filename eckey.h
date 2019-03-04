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
bool ECKey_Check(const unsigned char vch[32])//检测生成的私钥是否符合需求
{
	static const unsigned char Need[32] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE, 0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B, 0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40 };
	BIGNUM *bn = BN_new(); // 私钥 
	BIGNUM *bnNeed = BN_new(); // G在Fp下的序号order  
	BN_bin2bn(vch, 32, bn); //将二进制序列转化为一个大整数 
	BN_bin2bn(Need, 32, bnNeed); //** 0 < [私钥] < order 
	if (BN_is_zero(bn))
		return 0; // 私钥不能为0 
	if (BN_cmp(bn, bnNeed) > 0)
		return 0; //私钥必须小于order
	return 1;
}

void ECKey_GenKeypair(EC_KEY * pkey, unsigned char vch[32])//由随机生成的私钥导出公钥（利用比特币用到的椭圆曲线算法）
{
	int key_size = 32;
	const EC_GROUP * group;
	BIGNUM *privkey = BN_new();
	BN_CTX *ctx = NULL;
	EC_POINT *pubkey = NULL;
	if (NULL == pkey)
		return;
	group = EC_KEY_get0_group(pkey); // group结构体中存储了G值和运算规则 
	pubkey = EC_POINT_new(group); // 给pubkey分配内存，pubkey为曲线上的一个点 
	ctx = BN_CTX_new();
	if (BN_bin2bn(vch, 32, privkey)) // 将私钥（二进制形式）转化为一个大整数 
	{
		if (EC_POINT_mul(group, pubkey, privkey, NULL, NULL, ctx)) // 机算pubkey =privkey*G 
		{ // 将密钥存储于EC_KEY结构体中，便于导出为所需的格式
			EC_KEY_set_private_key(pkey, privkey);
			EC_KEY_set_public_key(pkey, pubkey);
		}
	}
	BN_clear_free(privkey);
	EC_POINT_free(pubkey);
	BN_CTX_free(ctx);
	return;

}
int ECKey_GetPubkey(EC_KEY * pkey, unsigned char * pubkey, int fCompressed)//将公钥转换为unsigned char数组形式
{
	uint32_t cb;
	EC_KEY_set_conv_form(pkey, fCompressed ? POINT_CONVERSION_COMPRESSED : POINT_CONVERSION_UNCOMPRESSED);//选择公钥采用输出格式
	cb = i2o_ECPublicKey(pkey, NULL);//返回需要的字节数
	if (0 == cb || cb > 65)
		return 0;
	if (NULL == pubkey)
		return cb;
	cb = i2o_ECPublicKey(pkey, &pubkey);//转换为unsigned char数组
	return cb;
}