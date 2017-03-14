#include "rsa.h"

int padding;

string rsaEncrypt(string in, RSA *p_rsa, Isolate *isolate, int alg) {
    if (alg == 0) {
        padding = RSA_PKCS1_PADDING;
    } else {
        padding = RSA_PKCS1_OAEP_PADDING;
    }
    string out = encryptByRsaWith(p_rsa, in, alg);
    return out;
}

string rsaDecrypt(string in, RSA *p_rsa, Isolate *isolate, int alg) {
    if (alg == 0) {
        padding = RSA_PKCS1_PADDING;
    } else {
        padding = RSA_PKCS1_OAEP_PADDING;
    }
    string out = decryptByRsaWith(p_rsa, in, 1 - alg);
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
            status = RSA_public_encrypt(length, (unsigned char*)input, (unsigned char*)encData, rsa, padding);
            break;

        default:
            status = RSA_private_encrypt(length, (unsigned char*)input, (unsigned char*)encData, rsa, padding);
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

    int flen = getBlockSizeWithRSA_PADDING_TYPE(rsa, padding);
    char *decData = (char*)calloc(1, flen + 1);

    int length = RSA_size(rsa);

    switch (keyType) {
        case TYPE_PUBLIC:
            status = RSA_public_decrypt(length, (unsigned char*)data.c_str(), (unsigned char*)decData, rsa, padding);
            break;

        default:
            status = RSA_private_decrypt(length, (unsigned char*)data.c_str(), (unsigned char*)decData, rsa, padding);
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
        len -= 42;
    }

    return len;
}

string encryptByRsaWith(RSA *rsa, string str, int keyType) {
    string encryptStr;
    cout<<str.size()<<endl<<SEC_BYTES(rsa, padding)<<endl;
    for (int i = 0; i < ceil(str.size(), SEC_BYTES(rsa, padding)); i++) {
        cout<<min(SEC_BYTES(rsa, padding), (int)(str.size() - i * SEC_BYTES(rsa, padding)))<<endl;
        string ss = encryptByRsa(rsa, str.substr(i * SEC_BYTES(rsa, padding), min(SEC_BYTES(rsa, padding), (int)(str.size() - i * SEC_BYTES(rsa, padding)))), keyType);
        encryptStr.append(ss);
    }
    return encryptStr;
}

string decryptByRsaWith(RSA *rsa, string str, int keyType) {
    string decryptStr;
    for (int i = 0; i < ceil(str.size(), (int)RES_BYTES(rsa)); i++) {
        string rrr = decryptByRsa(rsa, str.substr(i * RES_BYTES(rsa), (int)RES_BYTES(rsa)), keyType);
        string sss = (int)rrr.size() <= SEC_BYTES(rsa, padding) ? rrr : rrr.substr(0, SEC_BYTES(rsa, padding));
        decryptStr.append(sss);
    }

    return decryptStr;
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

int ceil(int a, int b) {
    if (a % b == 0) {
        return a / b;
    } else {
        return a / b + 1;
    }
}

