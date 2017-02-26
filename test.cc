#include <node.h>
#include <assert.h>
#include <v8.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace v8;

#define OUT_ENCRYPT_PATH "out.enc"
#define OUT_DECRYPT_PATH "out.dec"

//#define PADDING RSA_PKCS1_OAEP_PADDING
//#define SEC_BYTES 87
//#define RES_BYTES 116
#define PADDING RSA_PKCS1_PADDING
#define SEC_BYTES 117
#define RES_BYTES 172
#define RSAPublicKeyFile "rsa_public_key.pem"
#define RSAPrivateKeyFile "rsa_private_key.pem"

#define TYPE_PRIVATE    0
#define TYPE_PUBLIC 1

#define min(a,b) ( a < b ? a : b )

char *rsaEncrypt(char *str, RSA *p_rsa, Isolate *isolate);
char *rsaDecrypt(char *str, RSA *p_rsa, Isolate *isolate);

RSA *importRSAKeyWithType(char *type);
int getBlockSizeWithRSA_PADDING_TYPE(RSA *rsa, int padding_type);
char *encryptByRsa(RSA *rsa, char *content, int keyType);
char *decryptByRsa(RSA *rsa, char *content, int keyType);
char *encryptByRsaToData(RSA *rsa, char *content, int keyType);

char *encryptByRsaWith(RSA *rsa, char *str, int keyType);
char *decryptByRsaWith(RSA *rsa, char *str, int keyType);

char *base64_encode(const unsigned char *bindata, char *base64, int binlength);
int base64_decode(const char *base64, unsigned char *bindata);

int ceil(int a, int b);
void join(char *a, char *b);
void mid(char *dst, char *src, int n, int m);

/*
   char *encrypt(    // 加密函数，nodejs 的 C语言 扩展函数
   int     alg,         // 算法种类，0：RSA(RSA), 其他：未定义，返回错误码 -1
   char    *secret,        // 密钥，pem格式字符串或私钥文件路径
   int     secretType,       // 数据类型，0:hex string，非0：file
   int     dataType,       // 数据类型，0:hex string，非0：file
   char    *in,    // 如数据类型为0则为源文的hex string, 否则为源文件的路径与名称
   ）
   返回值：结果或结果文件
 */
void encrypt(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    int alg = args[0]->IntegerValue();
    String::Utf8Value secretStr(args[1]->ToString());
    char *secret = *secretStr;
    int secretType = args[2]->IntegerValue();
    int dataType = args[3]->IntegerValue();
    String::Utf8Value str(args[4]->ToString());
    char *in = *str;
    //String::Utf8Value a(args[3].As<Array>());


    char *out;
    if (alg == 0) {
        RSA *p_rsa;
        if (secretType == 0) {
            BIO *bio_private = BIO_new_mem_buf(secret, strlen(secret));
            if (bio_private == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Failed to create private key BIO")));
                return;
            }
            if ((p_rsa = PEM_read_bio_RSAPrivateKey(bio_private, NULL, NULL, NULL)) == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read private key bio error")));
                BIO_free(bio_private);
                return;
            }
            BIO_free(bio_private);
        } else {
            FILE *file;
            if ((file = fopen(secret, "r")) == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open private key file error")));
                return;
            }
            if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read private key file error")));
                fclose(file);
                return;
            }
            fclose(file);
        }
        out = rsaEncrypt(in, p_rsa, isolate);
        RSA_free(p_rsa);
    } else {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Illegal alg input")));
        return;
    }
    if (dataType == 0) {
        args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, out));
    } else {
        FILE *fp = fopen(OUT_ENCRYPT_PATH, "w");
        if (fp == 0) {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open output file error")));
            return;
        }
        fwrite(out, strlen(out), 1, fp);
        fclose(fp);
        args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, OUT_ENCRYPT_PATH));
    }
    return;
}


/*
   char *decrypt(    // 解密函数，nodejs 的 C语言 扩展函数
   int     alg,         // 算法种类，0：RSA(RSA), 其他：未定义，返回错误码 -1
   char    *secret,        // 密钥，pem格式字符串或公钥文件路径
   int     secretType,       // 数据类型，0:hex string，非0：file
   int     dataType,       // 数据类型，0:hex string，非0：file
   char    *in,    // 如数据类型为0则为源文的hex string, 否则为源文件的路径与名称
   )
   返回值：结果或结果文件
 */
void decrypt(const v8::FunctionCallbackInfo<v8::Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    int alg = args[0]->IntegerValue();
    String::Utf8Value secretStr(args[1]->ToString());
    char *secret = *secretStr;
    int secretType = args[2]->IntegerValue();
    int dataType = args[3]->IntegerValue();
    String::Utf8Value str(args[4]->ToString());
    char *in = *str;

    char *out;
    if (alg == 0) {
        RSA *p_rsa;
        if (secretType == 0) {
            BIO *bio_public = BIO_new_mem_buf(secret, strlen(secret));
            if (bio_public == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Failed to create public key BIO")));
                return;
            }
            if ((p_rsa = PEM_read_bio_RSAPublicKey(bio_public, NULL, NULL, NULL)) == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read public key bio error")));
                BIO_free(bio_public);
                return;
            }
            BIO_free(bio_public);
        } else {
            FILE *file;
            if ((file = fopen(secret, "r")) == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open public key file error")));
                return;
            }
            if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read public key file error")));
                fclose(file);
                ERR_print_errors_fp(stdout);
                return;
            }
            fclose(file);
        }
        out = rsaDecrypt(in, p_rsa, isolate);
        RSA_free(p_rsa);
    } else {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Illegal alg input")));
        return;
    }
    if (dataType == 0) {
        args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, out));
    } else {
        FILE *fp = fopen(OUT_DECRYPT_PATH, "w");
        if (fp == 0) {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open output file error")));
            return;
        }
        fwrite(out, strlen(out), 1, fp);
        fclose(fp);
        args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, OUT_DECRYPT_PATH));
    }
    return;
}

//字节流转换为十六进制字符串    
void ByteToHexStr(const unsigned char* source, char* dest, int sourceLen) {
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i++) {
        highByte = source[i] >> 4;
        lowByte = source[i] & 0x0f;

        highByte += 0x30;

        if (highByte > 0x39)
            dest[i * 2] = highByte + 0x07;
        else
            dest[i * 2] = highByte;

        lowByte += 0x30;
        if (lowByte > 0x39)
            dest[i * 2 + 1] = lowByte + 0x07;
        else
            dest[i * 2 + 1] = lowByte;
    }
    return;
}

void HexStrToByte(const char* source, unsigned char* dest, int sourceLen) {
    short i;
    unsigned char highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2) {
        highByte = toupper(source[i]);
        lowByte = toupper(source[i + 1]);

        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;

        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return;
}

char *rsaEncrypt(char *in, RSA *p_rsa, Isolate *isolate) {
    char *out = encryptByRsaWith(p_rsa, in, TYPE_PRIVATE);
    return out;
}

char *rsaDecrypt(char *in, RSA *p_rsa, Isolate *isolate) {
    char *out = decryptByRsaWith(p_rsa, in, TYPE_PUBLIC);
    return out;
}

RSA *importRSAKeyWithType(int type) {
    char *keyPath;
    if (type == TYPE_PUBLIC) {
        keyPath = (char*)RSAPublicKeyFile;
    } else {
        keyPath = (char*)RSAPrivateKeyFile;
    }

    FILE *file = fopen(keyPath, "r");

    RSA *rsa;
    if (file != NULL) {
        if (type == TYPE_PUBLIC) {
            rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
            assert(rsa != NULL);
        } else {
            rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
            assert(rsa != NULL);
        }

        fclose(file);
    } else {
        return NULL;
    }

    return rsa;
}

char *encryptByRsa(RSA *rsa, char *content, int keyType) {
    char *data = encryptByRsaToData(rsa, content, keyType);
    int len = RES_BYTES;
    char *base64 = (char*)calloc(1, len + 1);
    char *ret = base64_encode((unsigned char*)data, base64, RSA_size(rsa));
    return ret;
}

char *encryptByRsaToData(RSA *rsa, char *content, int keyType) {
    int status;
    int length = strlen(content);
    char *input = (char*)calloc(1, length + 1);
    for (int i = 0; i < length; i++) {
        input[i] = content[i];
    }
    input[length] = 0;

    int flen = RSA_size(rsa);

    char *encData = (char*)calloc(1, flen + 1);

    switch (keyType) {
        case TYPE_PUBLIC:
            status = RSA_public_encrypt(length, (unsigned char*)input, (unsigned char*)encData, rsa, PADDING);
            break;

        default:
            status = RSA_private_encrypt(length, (unsigned char*)input, (unsigned char*)encData, rsa, PADDING);
            //printf("input:\n%s\n", encData);
            break;
    }

    if (status != -1) {
        return encData;
    }

    ERR_print_errors_fp(stdout);
    free(encData);
    encData = NULL;

    return (char*)NULL;
}

char *decryptByRsa(RSA *rsa, char *content, int keyType) {
    int status;
    int len = (strlen(content) / 4 + 1) * 3;
    char *data = (char*)calloc(1, len + 1);
    base64_decode(content, (unsigned char*)data);

    int flen = getBlockSizeWithRSA_PADDING_TYPE(rsa, PADDING);
    char *decData = (char*)calloc(1, flen + 1);

    int length = RSA_size(rsa);

    switch (keyType) {
        case TYPE_PUBLIC:
            status = RSA_public_decrypt(length, (unsigned char*)data, (unsigned char*)decData, rsa, PADDING);
            //printf("output:\n%s\n%s\n", data, decData);
            break;

        default:
            status = RSA_private_decrypt(length, (unsigned char*)data, (unsigned char*)decData, rsa, PADDING);
            break;
    }

    if (status != -1) {
        return decData;
    }

    ERR_print_errors_fp(stdout);
    free(decData);
    decData = NULL;

    return (char*)NULL;
}

int getBlockSizeWithRSA_PADDING_TYPE(RSA *rsa, int padding_type) {
    int len = RSA_size(rsa);

    if (padding_type == RSA_PKCS1_PADDING) {
        len -= 11;
    } else if (padding_type == RSA_PKCS1_OAEP_PADDING) {
        len -= 41;
    }

    return len;
}

char *encryptByRsaWith(RSA *rsa, char *str, int keyType) {
    int len = (strlen(str) / SEC_BYTES + 1) * RES_BYTES;
    char *encryptStr = (char*)calloc(1, len + 1);
    char *substr = (char*)calloc(1, SEC_BYTES + 1);
    for (int i = 0; i < (int)(strlen(str) / SEC_BYTES + 1); i++) {
        mid(substr, str, i * SEC_BYTES, min(SEC_BYTES, strlen(str) - i * SEC_BYTES));
        //printf("\n\n%s\n\n", substr);
        char *ss = encryptByRsa(rsa, substr, keyType);
        join(encryptStr, ss);
    }
    return encryptStr;
}

char *decryptByRsaWith(RSA *rsa, char *str, int keyType) {
    int len = (strlen(str) / RES_BYTES) * SEC_BYTES;
    char *decryptStr = (char*)calloc(1, len + 1);
    char *substr = (char*)calloc(1, RES_BYTES + 1);
    char *s = (char*)calloc(1, SEC_BYTES + 1);
    for (int i = 0; i < ceil(strlen(str), RES_BYTES); i++) {
        mid(substr, str, i * RES_BYTES, RES_BYTES);
        char *rrr = decryptByRsa(rsa, substr, keyType);
        mid(s, rrr, 0, SEC_BYTES);
        char *sss = strlen(rrr) <= SEC_BYTES ? rrr : s;
        join(decryptStr, sss);
    }

    return decryptStr;
}

int ceil(int a, int b) {
    if (a % b == 0) {
        return a / b;
    } else {
        return a / b + 1;
    }
}

void join(char *a, char *b) {
    while (*a != '\0') {
        a++;
    }
    while (*b != '\0') {
        *a++ = *b++;
    }
}

void mid(char *dst, char *src, int m, int n) {
    char *p = src;
    char *q = dst;
    int len = strlen(src);
    if (n > len)
        n = len-m;
    if (m < 0)
        m = 0;
    if (m > len)
        return;
    p += m;
    while (n--)
        *(q++) = *(p++);
    *(q++) = '\0';
}

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char * base64_encode(const unsigned char * bindata, char * base64, int binlength)
{
    int i, j;
    unsigned char current;

    for ( i = 0, j = 0 ; i < binlength ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];

        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return base64;
}

int base64_decode(const char * base64, unsigned char * bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;

        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
                ((unsigned char)(temp[3]&0x3F));
    }
    bindata[strlen((char *)bindata)] = 0;
    return j;
}

void init(v8::Local<v8::Object> exports) {
    NODE_SET_METHOD(exports, "encrypt", encrypt);
    NODE_SET_METHOD(exports, "decrypt", decrypt);
}

NODE_MODULE(binding, init);

