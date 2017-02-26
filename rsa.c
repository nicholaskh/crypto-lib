#include <Base64.h>
#include <assert.h>
#include <rsa.h>

#define PADDING RSA_PKCS1_PADDING
#define RSAPublicKeyFile "rsa_public_key.pem"
#define RSAPrivateKeyFile "rsa_private_key.pem"

bool importRSAKeyWithType(char *type) {
    char *keyPath;
    if (!strcmp(type, "public")) {
        keyPath = RSAPublicKeyFile;
    } else {
        keyPath = RSAPrivateKeyFile;
    }

    FILE *file = fopen(keyPath, "r");

    RSA *rsa;
    if (file != NULL) {
        if (!strcmp(type, "public")) {
            rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
            assert(rsa != NULL);
        } else {
            rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
            assert(rsa != NULL);
        }

        fclose(file);
    }

    return rsa;
}

char *encryptByRsa(RSA *rsa, char *content, char *keyType) {
    char *data = encryptByRsaToData(rsa, content, keyType);
    char *base64 = (char*)malloc((strlen(data) / 3 + 1) * 4);
    char *ret = base64_encode(data, base64, strlen(data));
    return ret;
}

char *encryptByRsaToData(RSA *rsa, char *content, char *keyType) {
    int status;
    long int length = strlen(content);
    unsigned char input[length + 1];
    bzero(input, length + 1);
    for (int i = 0; i < length; i++) {
        input[i] = content[i];
    }

    int flen = getBlockSizeWithRSA_PADDING_TYPE(rsa, PADDING);

    char *encData = (char*)malloc(flen);
    bzero(encData, flen);

    switch (keyType) {
        case "public":
            status = RSA_public_encrypt(length, (unsigned char*)input, (unsigned char*)encData, rsa, PADDING);
            break;

        default:
            status = RSA_private_encrypt(length, (unsigned char*)input, (unsigned char*)encData, rsa, PADDING);
            break;
    }

    if (status) {
        return (char*)encData;
    }

    free(encData);
    encData = NULL;

    return "";
}

char *decryptByRsa(RSA *rsa, char *content, char *keyType) {
    int status;
    char *data = (char*)malloc((strlen(content) / 4 ) * 3);
    base64_decode(content, data);
    char *data = base64DecodedData(content);
    long int length = strlen(data);

    int flen = getBlockSizeWithRSA_PADDING_TYPE(rsa, PADDING);
    char *decData = (char*)malloc(flen);
    bzero(decData, flen);

    switch (keyType) {
        case "public":
            status = RSA_public_decrypt(length, (unsigned char*)data, (unsigned char*)decData, _rsa, PADDING);
            break;

        default:
            status = RSA_private_decrypt(length, (unsigned char*)data, (unsigned char*)decData, _rsa, PADDING);
            break;
    }

    if (status) {
        return (char*)decData;
    }

    free(decData);
    decData = NULL;

    return "";
}

int getBlockSizeWithRSA_PADDING_TYPE(RSA *rsa, int padding_type) {
    int len = RSA_size(rsa);

    if (padding_type == RSA_PKCS1_PADDING) {
        len -= 11;
    }

    return len;
}

char *encryptByRsaWith(RSA *rsa, char *str, char *keyType) {
    char *encryptStr = (char*)malloc((strlen(str) / 117 + 1) * 172);
    for (int i = 0; i < strlen(str) / 117 + 1; i++) {
        char *substr;
        substr(substr, str, i * 117, min(117, strlen(length) - i * 117));
        char *ss = encryptByRsaToData(rsa, substr, keyType);
        strcat(encryptStr, ss);
    }
    return encryptStr;
}

char *decryptByRsaWith(RSA *rsa, char *str, char *keyType) {
    char *decryptStr = (char*)malloc((strlen(str) / 172 + 1) * 117);
    for (int i = 0; i < strlen(str) / 172 + 1; i++) {
        char *substr;
        substr(substr, str, i * 172, 172);
        char *rrr = decryptByRsa(rsa, substr, keyType);
        char *s;
        substr(s, rrr, 0, 117);
        char *sss = strlen(rrr) <= 117 ? rrr : s;
        strcat(decryptStr, sss);
    }

    return decryptStr;
}

char *join(char *a, char *b) {
    char *c = (char *) malloc(strlen(a) + strlen(b) + 1);
    char *head = a;
    if (c == NULL) {
        exit(1);
    }
    char *tempc = c;
    while (*a != '\0') {
        *c++ = *a++;
    }
    while ((*c++ = *b++) != '\0') {
        ;
    }
    free(head);
    head = NULL;
    return tempc;
}

char *substr(char *dst, char *src, int n, int m) {
    char *p = src;
    char *q = dst;
    int len = strlen(src);
    if (n > len)
        n = len-m;
    if (m < 0)
        m = 0;
    if (m > len)
        return NULL;
    p += m;
    while (n--)
        *(q++) = *(p++);
    *(q++) = '\0';
    return dst;
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
    return j;
}
