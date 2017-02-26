#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

RSA *importRSAKeyWithType(char *type);
int getBlockSizeWithRSA_PADDING_TYPE(int padding_type);
char *encryptByRsa(RSA *rsa, char *content, char *keyType);
char *decryptByRsa(RSA *rsa, char *content, char *keyType);
char *encryptByRsaToData(RSA *rsa, char *content, char *keyType);

char *encryptByRsaWith(RSA *rsa, char *str, char *keyType);
char *decryptByRsaWith(RSA *rsa, char *str, char *keyType);
