/**
 * key file parser
 */

#include "genaro.h"

#define KEY_FILE_ERR_NUM (-1)
#define KEY_FILE_ERR_POINTER NULL
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
} key_obj_t;

typedef struct {
    json_object *json_obj;
    key_obj_t *key_obj;
} key_file_result_t;

key_obj_t *get_key_obj(json_object *key_json_obj);

/**
 * @brief whether key file is valid
 * @param path
 * @return 1: err, 0: valid
 */
key_file_result_t *parse_key_file(char *path);

void key_file_result_put(key_file_result_t *key_file_result);
int extract_key(char *passphrase, key_obj_t *key_obj, char **buf);
