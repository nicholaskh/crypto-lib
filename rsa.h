#include <node.h>
#include <v8.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <assert.h>

using namespace v8;
using namespace std;

#define OUT_ENCRYPT_PATH "out.enc"
#define OUT_DECRYPT_PATH "out.dec"

#define PADDING RSA_PKCS1_PADDING
#define SEC_BYTES 245
#define RES_BYTES 344

//#define PADDING RSA_PKCS1_OAEP_PADDING
//#define SEC_BYTES 87
//#define RES_BYTES 116

#define RSAPublicKeyFile "rsa_public_key.pem"
#define RSAPrivateKeyFile "rsa_private_key.pem"

#define TYPE_PRIVATE 0
#define TYPE_PUBLIC 1

#define min(a,b) ( a < b ? a : b )

string rsaEncrypt(string str, RSA *p_rsa, Isolate *isolate, int alg);
string rsaDecrypt(string str, RSA *p_rsa, Isolate *isolate, int alg);

RSA *importRSAKeyWithType(char *type);
int getBlockSizeWithRSA_PADDING_TYPE(RSA *rsa, int padding_type);
string encryptByRsa(RSA *rsa, string content, int keyType);
string decryptByRsa(RSA *rsa, string content, int keyType);
string encryptByRsaToData(RSA *rsa, string content, int keyType);

string encryptByRsaWith(RSA *rsa, string str, int keyType);
string decryptByRsaWith(RSA *rsa, string str, int keyType);

string base64_encode(string bindata);
string base64_decode(string base64);

int ceil(int a, int b);
