/**
 * key file parser
 */
#ifndef KEY_FILE_H
#define KEY_FILE_H

#include "genaro.h"

#define KEY_FILE_ERR_NUM (-1)
#define KEY_FILE_ERR_POINTER NULL
#define KEY_FILE_SUCCESS (0)
#define KEY_FILE_ERR_FORMAT (-1)
#define KEY_FILE_ERR_DATA (-2)
#define KEY_FILE_ERR_VALID (-3)
#define KEY_FILE_ERR_UNKNOWN (-4)

typedef struct {
    int64_t dklen;
    int64_t n;
    int64_t p;
    int64_t r;
    char *salt;
} kdfparams_obj_t;

typedef struct {
    char *iv;
} cipherparams_obj_t;

typedef struct {
    char *cipher;
    char *ciphertext;
    cipherparams_obj_t *cipherparams;

    char *kdf;
    kdfparams_obj_t *kdfparams;

    char *mac;
} crypto_obj_t;

typedef struct {
    int64_t version;
    char *id;
    char *address;
    crypto_obj_t *crypto;
} key_file_obj_t;
void key_file_obj_put(key_file_obj_t *key_obj);

void key_result_put(key_result_t *key_result);

/**
 * @brief get json object from file
 * @param path
 * @return
 */
// file -> json_object
json_object *parse_key_file(char *path);
// json_object -> key_file_obj_t
key_file_obj_t *get_key_obj(json_object *key_json_obj);
// passphrase -> key_file_obj_t -> key_result_t
int extract_key_file_obj(const char *passphrase, key_file_obj_t *key_obj, key_result_t **key_result);

#endif
