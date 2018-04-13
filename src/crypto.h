/**
 * @file crypto.h
 * @brief Storj crypto utilities.
 *
 * Helper crypto utilities
 */
#ifndef STORJ_CRYPTO_H
#define STORJ_CRYPTO_H

#include <nettle/aes.h>
#include <nettle/ripemd160.h>
#include <nettle/hmac.h>
#include <nettle/pbkdf2.h>
#include <nettle/sha.h>
#include <nettle/ctr.h>
#include <nettle/gcm.h>
#include <nettle/base64.h>

#include "bip39.h"
#include "utils.h"

#define DETERMINISTIC_KEY_SIZE 64
#define DETERMINISTIC_KEY_HEX_SIZE 32
#define BUCKET_NAME_MAGIC "398734aab3c4c30c9f22590e83a95f7e43556a45fc2b3060e0c39fde31f50272"

static const uint8_t BUCKET_META_MAGIC[32] = {66,150,71,16,50,114,88,160,163,35,154,65,162,213,226,215,70,138,57,61,52,19,210,170,38,164,162,200,86,201,2,81};

int sha256_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int sha512_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int ripemd160_of_str(const uint8_t *str, int str_len, uint8_t *digest);

int ripemd160sha256(uint8_t *data, uint64_t data_size, uint8_t *digest);

int ripemd160sha256_as_string(uint8_t *data, uint64_t data_size, char *digest);

int double_ripemd160sha256(uint8_t *data, uint64_t data_size, uint8_t *digest);

int double_ripemd160sha256_as_string(uint8_t *data, uint64_t data_size,
                                    char **digest);

void pbkdf2_hmac_sha512(unsigned key_length,
                        const uint8_t *key,
                        unsigned iterations,
                        unsigned salt_length, const uint8_t *salt,
                        unsigned length, uint8_t *dst);

/**
 * @brief Generate a bucket's key
 *
 * @param[in] Character array of the mnemonic
 * @param[in] bucket_id Character array of bucket id
 * @param[out] bucket_key 64 byte character array that is the bucket's key
 * @return A non-zero error value on failure and 0 on success.
 */
int generate_bucket_key(const char *mnemonic, const char *bucket_id,
                        char **bucket_key);

/**
 * @brief Generate a file's key
 *
 * @param[in] Character array of the mnemonic
 * @param[in] bucket_id Character array of bucket id
 * @param[in] index Character array of index
 * @param[out] file_key 64 byte character array that is the bucket's key
 * @return A non-zero error value on failure and 0 on success.
 */
int generate_file_key(const char *mnemonic,
                      const char *bucket_id,
                      const char *index,
                      char **file_key);

/**
 * @brief Calculate deterministic key by getting sha512 of key + id
 *
 * @param[in] Character array of the key
 * @param[in] key_len Integer value of length of key
 * @param[in] id Character array id
 * @param[out] buffer 64 byte character array of the deterministic key
 * @return A non-zero error value on failure and 0 on success.
 */
int get_deterministic_key(const char *key, int key_len,
                          const char *id, char **buffer);

/**
 * @brief Increment the iv for ctr decryption/encryption
 *
 * This function will modify iv and increment the counter based
 * on the bytes position and the AES block size, useful for decrypting
 * shards asynchronously.
 *
 * The iv must be 16 bytes, the AES block size, and the bytes_position
 * must a multiple of 16.
 *
 * @param[out] iv The ctr/iv to be incremented
 * @return A non-zero value on failure
 */
int increment_ctr_aes_iv(uint8_t *iv, uint64_t bytes_position);

/**
 * @brief Will derive an encryption key from passhrase
 *
 * Will use PBKDF2 to generate an encryption key from the passphrase.
 *
 * @param[in] passphrase - The passhrase
 * @param[in] salt - The salt used in the key derivation function
 * @return A key or NULL on failure.
 */
uint8_t *key_from_passphrase(const char *passphrase, const char *salt);

/**
 * @brief Will encrypt data with passphrase
 *
 * Data is encrypted using AES-256-CTR with a key generated from a key
 * derivation function with the passphrase.
 *
 * @param[in] passphrase - The passhrase used to encrypt the data
 * @param[in] salt - The salt used in the key derivation function
 * @param[in] data - The data to be encrypted
 * @param[out] result - The encrypted data encoded as hex string
 * @return A non-zero error value on failure and 0 on success.
 */
int encrypt_data(const char *passphrase,
                 const char *salt,
                 const char *data,
                 char **result);

/**
 * @brief Will decrypt data with passphrase
 *
 * Data is decrypted using AES-256-CTR with a key generated from a key
 * derivation function with the passphrase.
 *
 * @param[in] passphrase - The passhrase used to encrypt the data
 * @param[in] salt - The salt used in the key derivation function
 * @param[in] data - The hex string of encoded data
 * @param[out] result - The decrypted data
 */
int decrypt_data(const char *passphrase,
                 const char *salt,
                 const char *data,
                 char **result);

/**
 * @brief Will encrypt file meta
 *
 * This will encrypt file meta information using AES-256-GCM. The
 * resulting buffer will concat digest, iv and cipher text as base54
 * null terminated string.
 *
 * @param[in] filemeta - The null terminated filename
 * @param[in] encrypt_key - The key used to encrypt the file meta (32 bytes)
 * @param[in] encrypt_iv - The iv to use for encryption (32 bytes)
 * @param[out] buffer_base64 - The base64 encoded encrypted data including
 * digest, iv and cipher text
 * @return A non-zero value on error, zero on success.
 */
int encrypt_meta(const char *filemeta,
                 uint8_t *encrypt_key,
                 uint8_t *encrypt_iv,
                 char **buffer_base64);

/**
 * @brief Will decrypt file meta
 *
 * This will decrypt file meta information.
 *
 * @param[in] buffer_base64 - The base64 encrypted data
 * @param[in] decrypt_key - The key used to decrypt the file (32 bytes)
 * @param[out] filemeta - The null terminated filename
 * @return A non-zero value on error, zero on success.
 */
int decrypt_meta(const char *buffer_base64,
                 uint8_t *decrypt_key,
                 char **filemeta);

#endif /* STORJ_CRYPTO_H */
