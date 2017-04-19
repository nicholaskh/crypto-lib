#include "rsa.h"

using namespace v8;
using namespace std;

/*
   char *encrypt(    // 加密函数，nodejs 的 C语言 扩展函数
   int     alg,         // 算法种类，0:RSA private, 1:RSA public, 其他：未定义，返回错误码 -1
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
    string in;
    if (args[4]->IsString()) {
        String::Utf8Value str(args[4]->ToString());
        in = *str;
    } else {
        Uint8Array *raw = *args[4].As<Uint8Array>();
        string str = string((char*)(raw->Buffer()->GetContents().Data()), raw->Buffer()->ByteLength());
        in = str.substr(raw->ByteOffset(), raw->ByteLength());
    }
    //String::Utf8Value a(args[3].As<Array>());

    string out;
    if (alg == 0 || alg == 1) {
        RSA *p_rsa;
        if (secretType == 0) {
            BIO *bio_key = BIO_new_mem_buf(secret, strlen(secret));
            if (bio_key == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Failed to create private key BIO")));
                return;
            }
            if (alg == 0) {
                if ((p_rsa = PEM_read_bio_RSAPrivateKey(bio_key, NULL, NULL, NULL)) == NULL) {
                    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read private key bio error")));
                    BIO_free(bio_key);
                    return;
                }
            } else {
                if ((p_rsa = PEM_read_bio_RSAPublicKey(bio_key, NULL, NULL, NULL)) == NULL) {
                    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read public key bio error")));
                    BIO_free(bio_key);
                    return;
                }
            }
            BIO_free(bio_key);
        } else {
            FILE *file;
            if ((file = fopen(secret, "r")) == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open key file error")));
                return;
            }
            if (alg == 0) {
                if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {
                    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read private key file error")));
                    fclose(file);
                    return;
                }
            } else {
                if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL) {
                    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read public key file error")));
                    fclose(file);
                    return;
                }
            }
            fclose(file);
        }
        out = rsaEncrypt(in, p_rsa, isolate, alg);
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
   int     alg,         // 算法种类，0:RSA public, 1:RSA private, 其他：未定义，返回错误码 -1
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
    string filename;
    if (dataType != 0) {
        if (args[5]->IsString()) {
            String::Utf8Value str(args[5]->ToString());
            filename = string(*str, str.length());
        } else {
            filename = OUT_DECRYPT_PATH;
        }
    }

    string out;
    if (alg == 0 || alg == 1) {
        RSA *p_rsa;
        if (secretType == 0) {
            BIO *bio_key = BIO_new_mem_buf(secret, strlen(secret));
            if (bio_key == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Failed to create public key BIO")));
                return;
            }
            if (alg == 0) {
                if ((p_rsa = PEM_read_bio_RSA_PUBKEY(bio_key, NULL, NULL, NULL)) == NULL) {
                    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read public key bio error")));
                    BIO_free(bio_key);
                    return;
                }
            } else {
                if ((p_rsa = PEM_read_bio_RSAPrivateKey(bio_key, NULL, NULL, NULL)) == NULL) {
                    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read private key bio error")));
                    BIO_free(bio_key);
                    return;
                }
            }
            BIO_free(bio_key);
        } else {
            FILE *file;
            if ((file = fopen(secret, "r")) == NULL) {
                isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open key file error")));
                return;
            }
            if (alg == 0) {
                if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL) {
                    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read public key file error")));
                    fclose(file);
                    ERR_print_errors_fp(stdout);
                    return;
                }
            } else {
                if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL) {
                    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Read private key file error")));
                    fclose(file);
                    ERR_print_errors_fp(stdout);
                    return;
                }
            }
            fclose(file);
        }
        out = rsaDecrypt(in, p_rsa, isolate, alg);
        RSA_free(p_rsa);
    } else {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Illegal alg input")));
        return;
    }
    if (dataType == 0) {
        args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, out.c_str(), NewStringType::kNormal, out.size()).ToLocalChecked());
    } else {
        FILE *fp = fopen(filename.c_str(), "w");
        if (fp == 0) {
            isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Open output file error")));
            return;
        }
        fwrite(out.c_str(), out.size(), 1, fp);
        fclose(fp);
        args.GetReturnValue().Set(v8::String::NewFromUtf8(isolate, filename.c_str()));
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

void init(v8::Local<v8::Object> exports) {
    NODE_SET_METHOD(exports, "encrypt", encrypt);
    NODE_SET_METHOD(exports, "decrypt", decrypt);
}

NODE_MODULE(binding, init);

