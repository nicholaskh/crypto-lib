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
using namespace std;

#define OUT_ENCRYPT_PATH "out.enc"
#define OUT_DECRYPT_PATH "out.dec"

//#define PADDING RSA_PKCS1_OAEP_PADDING
//#define SEC_BYTES 87
//#define RES_BYTES 116
#define PADDING RSA_PKCS1_PADDING
#define SEC_BYTES 245
#define RES_BYTES 344
#define RSAPublicKeyFile "rsa_public_key.pem"
#define RSAPrivateKeyFile "rsa_private_key.pem"

#define TYPE_PRIVATE 0
#define TYPE_PUBLIC 1

#define min(a,b) ( a < b ? a : b )

string rsaEncrypt(string str, RSA *p_rsa, Isolate *isolate);
string rsaDecrypt(string str, RSA *p_rsa, Isolate *isolate);

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
    Uint8Array *raw = *args[4].As<Uint8Array>();
    string str = string((char*)(raw->Buffer()->GetContents().Data()), raw->ByteLength());
    string in = str.substr(raw->ByteOffset(), raw->ByteLength());
    //String::Utf8Value a(args[3].As<Array>());

    string out;
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
        args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, out.c_str()));
    } else {
        FILE *fp = fopen(OUT_ENCRYPT_PATH, "w");
        if (fp == 0) {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open output file error")));
            return;
        }
        fwrite(out.c_str(), out.size(), 1, fp);
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
    string in = string(*str, str.length());

    string out;
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
        args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, out.c_str(), NewStringType::kNormal, out.size()).ToLocalChecked());
    } else {
        FILE *fp = fopen(OUT_DECRYPT_PATH, "w");
        if (fp == 0) {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open output file error")));
            return;
        }
        fwrite(out.c_str(), out.size(), 1, fp);
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

string rsaEncrypt(string in, RSA *p_rsa, Isolate *isolate) {
    string out = encryptByRsaWith(p_rsa, in, TYPE_PRIVATE);
    return out;
}

string rsaDecrypt(string in, RSA *p_rsa, Isolate *isolate) {
    string out = decryptByRsaWith(p_rsa, in, TYPE_PUBLIC);
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

string encryptByRsa(RSA *rsa, string content, int keyType) {
    string data = encryptByRsaToData(rsa, content, keyType);
    string ret = base64_encode(data);
    return ret;
}

string encryptByRsaToData(RSA *rsa, string content, int keyType) {
    int status;
    int length = content.size();
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
            break;
    }

    if (status != -1) {
        return string(encData, flen);
    }

    ERR_print_errors_fp(stdout);
    free(encData);
    encData = NULL;

    return (char*)NULL;
}

string decryptByRsa(RSA *rsa, string content, int keyType) {
    int status;
    string data = base64_decode(content);

    int flen = getBlockSizeWithRSA_PADDING_TYPE(rsa, PADDING);
    char *decData = (char*)calloc(1, flen + 1);

    int length = RSA_size(rsa);

    switch (keyType) {
        case TYPE_PUBLIC:
            status = RSA_public_decrypt(length, (unsigned char*)data.c_str(), (unsigned char*)decData, rsa, PADDING);
            break;

        default:
            status = RSA_private_decrypt(length, (unsigned char*)data.c_str(), (unsigned char*)decData, rsa, PADDING);
            break;
    }

    if (status != -1) {
        return string(decData, status);
    }

    ERR_print_errors_fp(stdout);
    free(decData);
    decData = NULL;

    return (string)NULL;
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

string encryptByRsaWith(RSA *rsa, string str, int keyType) {
    string encryptStr;
    for (int i = 0; i < (int)(str.size() / SEC_BYTES + 1); i++) {
        string ss = encryptByRsa(rsa, str.substr(i * SEC_BYTES, min(SEC_BYTES, str.size() - i * SEC_BYTES)), keyType);
        encryptStr.append(ss);
    }
    return encryptStr;
}

string decryptByRsaWith(RSA *rsa, string str, int keyType) {
    string decryptStr;
    for (int i = 0; i < ceil(str.size(), RES_BYTES); i++) {
        string rrr = decryptByRsa(rsa, str.substr(i * RES_BYTES, RES_BYTES), keyType);
        string sss = rrr.size() <= SEC_BYTES ? rrr : rrr.substr(0, SEC_BYTES);
        decryptStr.append(sss);
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

const char * base64char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

string base64_encode(string bindata) {
    string base64;
    int i;
    unsigned char current;
    int bindatalength = bindata.size();

    for (i = 0; i < bindatalength; i += 3) {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64.append(string(1, base64char[(int)current]));

        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= bindatalength ) {
            base64.append(string(1, base64char[(int)current]));
            base64.append("=");
            base64.append("=");
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64.append(string(1, base64char[(int)current]));

        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if (i + 2 >= bindatalength) {
            base64.append(string(1, base64char[(int)current]));
            base64.append("=");
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64.append(string(1, base64char[(int)current]));

        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64.append(string(1, base64char[(int)current]));
    }
    return base64;
}

string base64_decode(string base64) {
    string bindata;
    int i;
    unsigned char k;
    unsigned char temp[4];
    string c;
    for (i = 0; base64[i] != '\0' ; i += 4) {
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

        c = string(1, ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) |
            ((unsigned char)((unsigned char)(temp[1]>>4)&0x03)));
        bindata.append(c);
        if ( base64[i+2] == '=' )
            break;

        c = string(1, ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) |
            ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F)));
        bindata.append(c);
        if ( base64[i+3] == '=' )
            break;

        c = string(1, ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) |
            ((unsigned char)(temp[3]&0x3F)));
        bindata.append(c);
    }
    return bindata;
}

void init(v8::Local<v8::Object> exports) {
    NODE_SET_METHOD(exports, "encrypt", encrypt);
    NODE_SET_METHOD(exports, "decrypt", decrypt);
}

NODE_MODULE(binding, init);

