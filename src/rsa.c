#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

#define RSA_PADDING RSA_PKCS1_PADDING

RSA *createRSA(unsigned char *key, int public)
{
    RSA *rsa = NULL;
    BIO *keybio = NULL;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio == NULL)
    {
        return NULL;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);
    }
 
    return rsa;
}

int public_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
    RSA *rsa = createRSA(key, 1);
    int result = RSA_public_encrypt(data_len, data, encrypted, rsa, RSA_PADDING);
    return result;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
    RSA *rsa = createRSA(key, 0);
    int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, RSA_PADDING);
    return result;
}

int private_encrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key, 0);
    int result = RSA_private_encrypt(data_len, data, encrypted, rsa, RSA_PADDING);
    return result;
}

int public_decrypt(unsigned char *enc_data, int data_len, unsigned char *key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key, 1);
    int  result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, RSA_PADDING);
    return result;
}

// void printLastError(char *msg)
// {
//     char * err = malloc(130);
//     ERR_load_crypto_strings();
//     ERR_error_string(ERR_get_error(), err);
//     printf("%s ERROR: %s\n", msg, err);
//     free(err);
// }