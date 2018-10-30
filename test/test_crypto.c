#include "../src/utils.h"
#include "../src/crypto.h"

void test_ripemd160sha256_as_string()
{
    uint8_t data[RIPEMD160_DIGEST_SIZE] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};

    char digest[RIPEMD160_DIGEST_SIZE * 2 + 1] = { 0 };

    // printf("input:\n");
    // printf("  data:");
    // for(int i = 0; i < RIPEMD160_DIGEST_SIZE; i++)
    // {
    //     printf(" %02x", data[i]);
    // }
    // printf("\n");

    ripemd160sha256_as_string(data, RIPEMD160_DIGEST_SIZE, digest);

    printf("\tdigest:%s\n", digest);
}

void test_generate_bucket_key()
{
    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char *bucket_id = "0123456789ab0123456789ab";
    char *bucket_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    // char *expected_bucket_key = "06b02124888a696e1da6a739042a4e7a4fb14e44b752f879f0cb2c5491c701a7";

    generate_bucket_key(mnemonic, DETERMINISTIC_KEY_SIZE, bucket_id, &bucket_key);
    bucket_key[DETERMINISTIC_KEY_SIZE] = '\0';

    printf("\tbucket_key:%s\n", bucket_key);

    free(bucket_key);
}

void test_generate_file_key()
{
    char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    char *bucket_id = "0123456789ab0123456789ab";
    char *index = "150589c9593bbebc0e795d8c4fa97304b42c110d9f0095abfac644763beca66e";
    char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    // char *expected_file_key = "90fa3754222d837835de43d16fac901914fabd0598cedc1cb23be337b4203df7";

    generate_file_key(mnemonic, DETERMINISTIC_KEY_SIZE, bucket_id, index, &file_key);

    printf("\tfile_key:%s\n", file_key);

    free(file_key);
}

void test_sha256_of_str()
{
    /*testcase 1*/
    uint8_t digest1[SHA256_DIGEST_SIZE] = { 0 };
    uint8_t str1[20] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};

    sha256_of_str(str1, 20, digest1);

    printf("\tdigest1:");
    for(int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        printf(" %02x", digest1[i]);
    }
    printf("\n");

    /*testcase 2*/
    uint8_t digest2[SHA256_DIGEST_SIZE] = { 0 };
    char *temp = "abcde";
    uint8_t *str2 = (uint8_t *)temp;

    sha256_of_str(str2, strlen(temp), digest2);

    printf("\tdigest2:");
    for(int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        printf(" %02x", digest2[i]);
    }
    printf("\n");
}

void test_ripemd160_of_str()
{
    /*testcase 1*/
    uint8_t digest1[RIPEMD160_DIGEST_SIZE] = { 0 };
    uint8_t str1[20] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};

    ripemd160_of_str(str1, 20, digest1);

    printf("\tdigest1:");
    for(int i = 0; i < RIPEMD160_DIGEST_SIZE; i++)
    {
        printf(" %02x", digest1[i]);
    }
    printf("\n");

    /*testcase 2*/
    uint8_t digest2[RIPEMD160_DIGEST_SIZE] = { 0 };
    char *temp = "abcde";
    uint8_t *str2 = (uint8_t *)temp;

    ripemd160_of_str(str2, strlen(temp), digest2);

    printf("\tdigest2:");
    for(int i = 0; i < RIPEMD160_DIGEST_SIZE; i++)
    {
        printf(" %02x", digest2[i]);
    }
    printf("\n");
}

// void test_sha512_of_str()
// {
//     /*testcase 1*/
//     uint8_t digest1[SHA512_DIGEST_SIZE] = { 0 };
//     uint8_t str1[20] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};

//     sha512_of_str(str1, 20, digest1);

//     printf("\tdigest1:");
//     for(int i = 0; i < SHA512_DIGEST_SIZE; i++)
//     {
//         printf(" %02x", digest1[i]);
//     }
//     printf("\n");

//     /*testcase 2*/
//     uint8_t digest2[SHA512_DIGEST_SIZE] = { 0 };
//     char *temp = "abcde";
//     uint8_t *str2 = (uint8_t *)temp;

//     sha512_of_str(str2, strlen(temp), digest2);

//     printf("\tdigest2:");
//     for(int i = 0; i < SHA512_DIGEST_SIZE; i++)
//     {
//         printf(" %02x", digest2[i]);
//     }
//     printf("\n");
// }

void test_increment_ctr_aes_iv()
{
    uint8_t iv[16] = {188,14,95,229,78,112,182,107,
                        34,206,248,225,52,22,16,183};

    int ret1 = increment_ctr_aes_iv(iv, 1);
    printf("\tret1:%d\n", ret1);

    int ret2 = increment_ctr_aes_iv(iv, AES_BLOCK_SIZE);
    printf("\tret2:%d\n", ret2);

    printf("\tiv[15]:%d\n", iv[15]);

    int ret3 = increment_ctr_aes_iv(iv, AES_BLOCK_SIZE * 72);
    printf("\tret3:%d\n", ret3);
    
    printf("\tiv[15]:%d, iv[14]:%d\n", iv[15], iv[14]);
}

void test_encrypt_meta()
{
    uint8_t encrypt_key[32] = {215,99,0,133,172,219,64,35,54,53,171,23,146,160,
                               81,126,137,21,253,171,48,217,184,188,8,137,3,
                               4,83,50,30,251};
    uint8_t iv[32] = {70,219,247,135,162,7,93,193,44,123,188,234,203,115,129,
                      82,70,219,247,135,162,7,93,193,44,123,188,234,203,115,
                      129,82};

    char *buffer1 = NULL;
    char *buffer2 = NULL;

    encrypt_meta("abc", encrypt_key, iv, &buffer1);
    printf("\tbuffer1:%s\n", buffer1);

    encrypt_meta("你好aaa", encrypt_key, iv, &buffer2);
    printf("\tbuffer2:%s\n", buffer2);
}

void test_decrypt_meta()
{
    uint8_t encrypt_key[32] = {215,99,0,133,172,219,64,35,54,53,171,23,146,160,
                               81,126,137,21,253,171,48,217,184,188,8,137,3,
                               4,83,50,30,251};

    char *filemeta1 = NULL;
    char *filemeta2 = NULL;

    decrypt_meta("pMvaFgO+FsMzG5D1z6Goi0bb94eiB13BLHu86stzgVJG2/eHogddwSx7vOrLc4FSvwPg", encrypt_key, &filemeta1);
    printf("\tfilemeta1:%s\n", filemeta1);

    decrypt_meta("+sXD0Ot+MZ+ENJXvIy5uuEbb94eiB13BLHu86stzgVJG2/eHogddwSx7vOrLc4FSOtwjPYuTqnL/", encrypt_key, &filemeta2);
    printf("\tfilemeta2:%s\n", filemeta2);
}

int test_meta_encryption_name(char *filename)
{
    uint8_t encrypt_key[32] = {215,99,0,133,172,219,64,35,54,53,171,23,146,160,
                               81,126,137,21,253,171,48,217,184,188,8,137,3,
                               4,83,50,30,251};
    uint8_t iv[32] = {70,219,247,135,162,7,93,193,44,123,188,234,203,115,129,
                      82,70,219,247,135,162,7,93,193,44,123,188,234,203,115,
                      129,82};

    char *buffer = NULL;
    encrypt_meta(filename, encrypt_key, iv, &buffer);

    char *buffer2 = NULL;
    int status = decrypt_meta(buffer, encrypt_key, &buffer2);
    if (status != 0) {
        return 1;
    }

    if (strcmp(filename, buffer2) != 0) {
        return 1;
    }

    free(buffer);
    free(buffer2);

    return 0;
}

int test_meta_encryption()
{
    for (int i = 1; i < 24; i++) {
        char *filename = calloc(i + 1, sizeof(char));
        memset(filename, 'a', i);
        if (test_meta_encryption_name(filename)) {
            printf("Failed with filename: %s\n", filename);
            return 1;
        }
        free(filename);
    }
    printf("\tSuccess!\n");
    return 0;
}

int main()
{
    printf("\n----BEGIN TEST ripemd160sha256_as_string----\n");
    test_ripemd160sha256_as_string();
    printf("----END TEST ripemd160sha256_as_string----\n");

    printf("\n----BEGIN TEST generate_bucket_key----\n");
    test_generate_bucket_key();
    printf("----END TEST generate_bucket_key----\n");

    printf("\n----BEGIN TEST generate_file_key----\n");
    test_generate_file_key();
    printf("----END TEST generate_file_key----\n");

    printf("\n----BEGIN TEST sha256_of_str----\n");
    test_sha256_of_str();
    printf("----END TEST sha256_of_str----\n");

    printf("\n----BEGIN TEST ripemd160_of_str----\n");
    test_ripemd160_of_str();
    printf("----END TEST ripemd160_of_str----\n");
    
    // printf("\n----BEGIN TEST sha256_of_str----\n");
    // test_sha512_of_str();
    // printf("----END TEST sha256_of_str----\n");

    printf("\n----BEGIN TEST increment_ctr_aes_iv----\n");
    test_increment_ctr_aes_iv();
    printf("----END TEST increment_ctr_aes_iv----\n");

    printf("\n----BEGIN TEST encrypt_meta----\n");
    test_encrypt_meta();
    printf("----END TEST encrypt_meta----\n");

    printf("\n----BEGIN TEST decrypt_meta----\n");
    test_decrypt_meta();
    printf("----END TEST decrypt_meta----\n");

    printf("\n----BEGIN TEST encrypt_meta/decrypt_meta----\n");
    test_meta_encryption();
    printf("----END TEST encrypt_meta/decrypt_meta----\n");
    
    return 0;
}
