#include "crypto.h"

int ripemd160sha256_as_string(uint8_t *data, uint64_t data_size, char *digest)
{
    uint8_t *ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    if (!ripemd160_digest) {
        return 1;
    }
    ripemd160sha256(data, data_size, ripemd160_digest);

    // Convert ripemd160 hex to character array
    char *ripemd160_str = hex2str(RIPEMD160_DIGEST_SIZE, ripemd160_digest);
    if (!ripemd160_str) {
        return 1;
    }

    //Copy the result into buffer
    memcpy(digest, ripemd160_str, RIPEMD160_DIGEST_SIZE * 2);

    free(ripemd160_digest);
    free(ripemd160_str);

    return 0;
}

int ripemd160sha256(uint8_t *data, uint64_t data_size, uint8_t *digest)
{
    // Get the sha256 of the data
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    sha256_of_str(data, data_size, sha256_digest);

    // Get the ripemd160 of the sha256
    uint8_t ripemd160_digest[RIPEMD160_DIGEST_SIZE];
    ripemd160_of_str(sha256_digest, SHA256_DIGEST_SIZE, ripemd160_digest);

    //Copy the result into buffer
    memcpy(digest, ripemd160_digest, RIPEMD160_DIGEST_SIZE);

    return 0;
}

int double_ripemd160sha256(uint8_t *data, uint64_t data_size, uint8_t *digest)
{
    uint8_t *first_ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    if (!first_ripemd160_digest) {
        return 1;
    }
    ripemd160sha256(data, data_size, first_ripemd160_digest);

    uint8_t *second_ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    if (!second_ripemd160_digest) {
        return 1;
    }
    ripemd160sha256(first_ripemd160_digest, RIPEMD160_DIGEST_SIZE,
                   second_ripemd160_digest);


    //Copy the result into buffer
    memcpy(digest, second_ripemd160_digest, RIPEMD160_DIGEST_SIZE);

    free(first_ripemd160_digest);
    free(second_ripemd160_digest);

    return 0;
}

int double_ripemd160sha256_as_string(uint8_t *data, uint64_t data_size,
                                    char **digest)
{
    uint8_t *ripemd160_digest = calloc(RIPEMD160_DIGEST_SIZE, sizeof(char));
    if (!ripemd160_digest) {
        return 1;
    }
    if (double_ripemd160sha256(data, data_size, ripemd160_digest)) {
        return 1;
    }

    // Convert ripemd160 hex to character array
    char *ripemd160_str = hex2str(RIPEMD160_DIGEST_SIZE, ripemd160_digest);
    if (!ripemd160_str) {
        return 1;
    }

    //Copy the result into buffer
    memcpy(*digest, ripemd160_str, RIPEMD160_DIGEST_SIZE * 2);

    free(ripemd160_digest);

    return 0;
}

int generate_bucket_key(const char *mnemonic, const char *bucket_id,
                        char **bucket_key)
{
    int status = 0;
    char *seed = calloc(128 + 1, sizeof(char));
    if (!seed) {
        status = 1;
        goto cleanup;
    }
    mnemonic_to_seed(mnemonic, "", &seed);
    seed[128] = '\0';

    status = get_deterministic_key(seed, 128, bucket_id, bucket_key);

cleanup:

    if (seed) {
        memset_zero(seed, 128 + 1);
        free(seed);
    }

    return status;
}

int generate_file_key(const char *mnemonic, const char *bucket_id,
                      const char *index, char **file_key)
{
    int status = 0;
    char *bucket_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    if (!bucket_key) {
        status = 1;
        goto cleanup;
    }

    status = generate_bucket_key(mnemonic, bucket_id, &bucket_key);
    if (status) {
        goto cleanup;
    }
    bucket_key[DETERMINISTIC_KEY_SIZE] = '\0';

    get_deterministic_key(bucket_key, 64, index, file_key);

cleanup:

    if (bucket_key) {
        memset_zero(bucket_key, DETERMINISTIC_KEY_SIZE + 1);
        free(bucket_key);
    }

    return status;
}

int get_deterministic_key(const char *key, int key_len,
                          const char *id, char **buffer)
{
    int input_len = key_len + strlen(id);
    char *sha512input = calloc(input_len + 1, sizeof(char));
    if (!sha512input) {
        return 1;
    }

    // Combine key and id
    memcpy(sha512input, key, key_len);
    memcpy(sha512input + key_len, id, strlen(id));
    sha512input[input_len] = '\0';

    // Convert input to hexdata
    uint8_t *sha512input_as_hex = str2hex(input_len, sha512input);
    if (!sha512input_as_hex) {
        return 2;
    }

    // Sha512 of hexdata
    uint8_t sha512_digest[SHA512_DIGEST_SIZE];
    sha512_of_str(sha512input_as_hex, input_len / 2, sha512_digest);

    // Convert Sha512 hex to character array
    char *sha512_str = hex2str(SHA512_DIGEST_SIZE, sha512_digest);
    if (!sha512_str) {
        return 2;
    }

    //First 64 bytes of sha512
    memcpy(*buffer, sha512_str, DETERMINISTIC_KEY_SIZE);

    memset_zero(sha512_str, SHA512_DIGEST_SIZE * 2 + 1);
    memset_zero(sha512_digest, SHA512_DIGEST_SIZE);
    memset_zero(sha512input_as_hex, input_len / 2 + 1);
    memset_zero(sha512input, input_len + 1);

    free(sha512input);
    free(sha512input_as_hex);
    free(sha512_str);

    return 0;
}

int sha256_of_str(const uint8_t *str, int str_len, uint8_t *digest)
{
    struct sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, str_len, str);
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

    return 0;
}

int ripemd160_of_str(const uint8_t *str, int str_len, uint8_t *digest)
{
    struct ripemd160_ctx ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, str_len, str);
    ripemd160_digest(&ctx, RIPEMD160_DIGEST_SIZE, digest);

    return 0;
}

int sha512_of_str(const uint8_t *str, int str_len, uint8_t *digest)
{
    struct sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, str_len, str);
    sha512_digest(&ctx, SHA512_DIGEST_SIZE, digest);

    return 0;
}

void pbkdf2_hmac_sha512 (
    unsigned key_length,
    const uint8_t *key,
    unsigned iterations,
    unsigned salt_length, const uint8_t *salt,
    unsigned length, uint8_t *dst)
{
    struct hmac_sha512_ctx sha512ctx;

    hmac_sha512_set_key (&sha512ctx, key_length, key);
    PBKDF2 (&sha512ctx, hmac_sha512_update, hmac_sha512_digest,
    SHA512_DIGEST_SIZE, iterations, salt_length, salt, length, dst);
}

int increment_ctr_aes_iv(uint8_t *iv, uint64_t bytes_position)
{
    if (bytes_position % AES_BLOCK_SIZE != 0) {
        return 1;
    }

    uint64_t times = bytes_position / AES_BLOCK_SIZE;

    while (times) {
        unsigned int i = AES_BLOCK_SIZE - 1;
        if (++(iv)[i] == 0) {
            while (i > 0 && ++(iv)[--i] == 0);
        }
        times--;
    }

    return 0;
}

uint8_t *key_from_passphrase(const char *passphrase, const char *salt)
{
    uint8_t passphrase_len = strlen(passphrase);
    uint8_t salt_len = strlen(salt);
    uint8_t *key = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
    if (!key) {
        return NULL;
    }
    int rounds = 200000;
    pbkdf2_hmac_sha256(passphrase_len, (uint8_t *)passphrase, rounds, salt_len,
                       (uint8_t *)salt, SHA256_DIGEST_SIZE, key);

    return key;
}

int decrypt_data(const char *passphrase, const char *salt, const char *data,
                 char **result)
{

    uint8_t *key = key_from_passphrase(passphrase, salt);
    if (!key) {
        return 1;
    }

    // Convert from hex string
    int len = strlen(data);
    if (len / 2 < GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE + 1) {
        free(key);
        return 1;
    }
    int enc_len = len / 2;
    int data_size = enc_len - GCM_DIGEST_SIZE - SHA256_DIGEST_SIZE;
    uint8_t *enc = str2hex(len, (char *)data);
    if (!enc) {
        free(key);
        return 1;
    }

    // Get the expected digest and iv
    uint8_t digest[GCM_DIGEST_SIZE];
    uint8_t data_iv[SHA256_DIGEST_SIZE];
    uint8_t cipher_text[data_size];
    memcpy(&digest, enc, GCM_DIGEST_SIZE);
    memcpy(&data_iv, enc + GCM_DIGEST_SIZE, SHA256_DIGEST_SIZE);
    memcpy(&cipher_text, enc + GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE, data_size);

    free(enc);

    struct gcm_aes256_ctx gcm_ctx;
    gcm_aes256_set_key(&gcm_ctx, key);
    gcm_aes256_set_iv(&gcm_ctx, SHA256_DIGEST_SIZE, data_iv);
    free(key);

    // Decrypt the data
    *result = calloc(data_size + 1, sizeof(char));
    int pos = 0;
    size_t remain = data_size;
    while (pos < data_size) {
        int len = AES_BLOCK_SIZE;
        if (remain < AES_BLOCK_SIZE) {
            len = remain;
        }
        gcm_aes256_decrypt(&gcm_ctx, len, (uint8_t *)*result + pos,
                           cipher_text + pos);
        pos += AES_BLOCK_SIZE;
        remain -= AES_BLOCK_SIZE;
    }

    uint8_t actual_digest[GCM_DIGEST_SIZE];
    gcm_aes256_digest(&gcm_ctx, GCM_DIGEST_SIZE, actual_digest);

    int digest_match = memcmp(actual_digest, digest, GCM_DIGEST_SIZE);
    if (digest_match != 0) {
        return 1;
    }

    return 0;
}

int encrypt_data(const char *passphrase, const char *salt, const char *data,
                 char **result)
{
    uint8_t *key = key_from_passphrase(passphrase, salt);
    if (!key) {
        return 1;
    }

    uint8_t data_size = strlen(data);
    if (data_size <= 0) {
        return 1;
    }

    // Generate synthetic iv with first half of sha512 hmac of data
    struct hmac_sha512_ctx hmac_ctx;
    hmac_sha512_set_key(&hmac_ctx, SHA256_DIGEST_SIZE, key);
    hmac_sha512_update(&hmac_ctx, data_size, (uint8_t *)data);
    uint8_t data_iv[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&hmac_ctx, SHA256_DIGEST_SIZE, data_iv);

    // Encrypt the data
    struct gcm_aes256_ctx gcm_ctx;
    gcm_aes256_set_key(&gcm_ctx, key);
    gcm_aes256_set_iv(&gcm_ctx, SHA256_DIGEST_SIZE, data_iv);
    free(key);

    int pos = 0;
    size_t remain = data_size;
    uint8_t cipher_text[data_size];
    while (pos < data_size) {
        int len = AES_BLOCK_SIZE;
        if (remain < AES_BLOCK_SIZE) {
            len = remain;
        }
        gcm_aes256_encrypt(&gcm_ctx, len, cipher_text + pos,
                           (uint8_t *)data + pos);
        pos += AES_BLOCK_SIZE;
        remain -= AES_BLOCK_SIZE;
    }

    // Get the digest
    uint8_t digest[GCM_DIGEST_SIZE];
    gcm_aes256_digest(&gcm_ctx, GCM_DIGEST_SIZE, digest);


    // Copy the digest, iv and cipher text to a buffer
    int buffer_size = GCM_DIGEST_SIZE + (SHA512_DIGEST_SIZE / 2) + data_size;
    uint8_t *buffer = calloc(buffer_size, sizeof(char));
    if (!buffer) {
        return 1;
    }
    memcpy(buffer, digest, GCM_DIGEST_SIZE);
    memcpy(buffer + GCM_DIGEST_SIZE, data_iv, SHA256_DIGEST_SIZE);
    memcpy(buffer + GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE,
           &cipher_text, data_size);

    // Convert to hex string
    *result = hex2str(buffer_size, buffer);
    if (!*result) {
        return 1;
    }

    free(buffer);


    return 0;
}

int encrypt_meta(const char *filemeta,
                 uint8_t *encrypt_key,
                 uint8_t *encrypt_iv,
                 char **buffer_base64)
{
    struct gcm_aes256_ctx ctx2;
    gcm_aes256_set_key(&ctx2, encrypt_key);
    gcm_aes256_set_iv(&ctx2, SHA256_DIGEST_SIZE, encrypt_iv);

    int pos = 0;
    size_t length = strlen(filemeta);
    size_t remain = length;
    uint8_t cipher_text[length];
    while (pos < length) {
        int len = AES_BLOCK_SIZE;
        if (remain < AES_BLOCK_SIZE) {
            len = remain;
        }
        gcm_aes256_encrypt(&ctx2, len, cipher_text + pos,
                           (uint8_t *)filemeta + pos);
        pos += AES_BLOCK_SIZE;
        remain -= AES_BLOCK_SIZE;
    }

    uint8_t digest[GCM_DIGEST_SIZE];
    gcm_aes256_digest(&ctx2, GCM_DIGEST_SIZE, digest);

    uint32_t buf_len = GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE + length;
    uint8_t buf[buf_len];
    memcpy(buf, digest, GCM_DIGEST_SIZE);
    memcpy(buf + GCM_DIGEST_SIZE, encrypt_iv, SHA256_DIGEST_SIZE);
    memcpy(buf + GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE, &cipher_text, length);

    size_t base64_len = BASE64_ENCODE_LENGTH(buf_len);
    *buffer_base64 = calloc(base64_len + 3, sizeof(uint8_t));
    if (!*buffer_base64) {
        //STORJ_MEMORY_ERROR
        return 1;
    }

    struct base64_encode_ctx ctx3;
    base64_encode_init(&ctx3);
    size_t out_len = base64_encode_update(&ctx3, (uint8_t *)*buffer_base64,
                                          buf_len, buf);
    out_len += base64_encode_final(&ctx3, (uint8_t *)*buffer_base64 + out_len);

    return 0;
}

int decrypt_meta(const char *buffer_base64,
                 uint8_t *decrypt_key,
                 char **filemeta)
{
    uint32_t buffer_len = BASE64_DECODE_LENGTH(strlen(buffer_base64));
    uint8_t *buffer = calloc(buffer_len, sizeof(uint8_t));
    if (!buffer) {
        //STORJ_MEMORY_ERROR
        return 1;
    }

    size_t decode_len = 0;
    struct base64_decode_ctx ctx3;
    base64_decode_init(&ctx3);
    if (!base64_decode_update(&ctx3, &decode_len, buffer,
                              strlen(buffer_base64), (uint8_t *)buffer_base64)) {
        free(buffer);
        return 1;
    }

    if (!base64_decode_final(&ctx3)) {
        free(buffer);
        return 1;
    }

    if (GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE + 1 > decode_len) {
        free(buffer);
        //STORJ_META_DECRYPTION_ERROR
        return 1;
    }

    size_t length = decode_len - GCM_DIGEST_SIZE - SHA256_DIGEST_SIZE;

    uint8_t digest[GCM_DIGEST_SIZE];
    uint8_t iv[SHA256_DIGEST_SIZE];
    uint8_t cipher_text[length];
    uint8_t clear_text[length];

    memcpy(&digest, buffer, GCM_DIGEST_SIZE);
    memcpy(&iv, buffer + GCM_DIGEST_SIZE, SHA256_DIGEST_SIZE);
    memcpy(&cipher_text, buffer + GCM_DIGEST_SIZE + SHA256_DIGEST_SIZE, length);

    free(buffer);

    struct gcm_aes256_ctx ctx2;
    gcm_aes256_set_key(&ctx2, decrypt_key);
    gcm_aes256_set_iv(&ctx2, SHA256_DIGEST_SIZE, iv);

    int pos = 0;
    size_t remain = length;
    while (pos < length) {
        int len = AES_BLOCK_SIZE;
        if (remain < AES_BLOCK_SIZE) {
            len = remain;
        }
        gcm_aes256_decrypt(&ctx2, len, clear_text + pos, cipher_text + pos);
        pos += AES_BLOCK_SIZE;
        remain -= AES_BLOCK_SIZE;
    }

    uint8_t actual_digest[GCM_DIGEST_SIZE];
    gcm_aes256_digest(&ctx2, GCM_DIGEST_SIZE, actual_digest);

    int digest_match = memcmp(actual_digest, digest, GCM_DIGEST_SIZE);
    if (digest_match != 0) {
        //STORJ_META_DECRYPTION_ERROR
        return 1;
    }

    *filemeta = calloc(length + 1, sizeof(char));
    if (!*filemeta) {
        //STORJ_MEMORY_ERROR
        return 1;
    }
    memcpy(*filemeta, &clear_text, length);

    return 0;
}
