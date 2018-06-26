#include "key_file.h"
#include "libscrypt.h"
#include "crypto.h"
#include "utils.h"

/*
 * free memory of key_obj_t
 * ***********************************************************
 */

void kdfparams_obj_put(kdfparams_obj_t *kdfparams_obj) {
    if (kdfparams_obj == NULL) return;

    // do not free char * fields, because it's managed by json_object.
    free(kdfparams_obj);
}

void cipherparams_obj_put(cipherparams_obj_t *cipherparams_obj) {
    if (cipherparams_obj == NULL) return;

    free(cipherparams_obj);
}

void crypto_obj_put(crypto_obj_t *crypto_obj) {
    if (crypto_obj == NULL) return;

    cipherparams_obj_put(crypto_obj->cipherparams);
    kdfparams_obj_put(crypto_obj->kdfparams);

    free(crypto_obj);
}

// free memory of key_obj
void key_file_obj_put(key_file_obj_t *key_file_obj) {
    if (key_file_obj == NULL) return;

    crypto_obj_put(key_file_obj->crypto);

    free(key_file_obj);
}

void key_result_put(key_result_t *key_result) {
    if (key_result == NULL) return;

    if (key_result->dec_key) {
        free(key_result->dec_key);
    }
    if (key_result->priv_key) {
        free(key_result->priv_key);
    }
    free(key_result);
}

/*
 * get value from json_object
 * ***********************************************************
 */

json_object *get_json_object_value(json_object *json_obj, const char *key) {
    json_object *value_obj;
    if (json_object_object_get_ex(json_obj, key, &value_obj)) {
        return value_obj;
    }
    return KEY_FILE_ERR_POINTER;
}

char *get_json_string_value(json_object *json_obj, const char *key) {
    json_object *value_obj;
    if ((value_obj = get_json_object_value(json_obj, key)) == KEY_FILE_ERR_POINTER) {
        return KEY_FILE_ERR_POINTER;
    }

    char *string;
    string = (char *) json_object_get_string(value_obj);
    return string;
}

int64_t get_json_num_value(json_object *json_obj, const char *key) {
    json_object *value_obj;
    int64_t num;
    if ((value_obj = get_json_object_value(json_obj, key)) == KEY_FILE_ERR_POINTER) {
        return KEY_FILE_ERR_NUM;
    }

    num = json_object_get_int64(value_obj);
    return num;
}

/*
 * parse json_object to key_obj_t
 * ***********************************************************
 */


kdfparams_obj_t *get_cipher_kdfparams(json_object *kdfparams_json_obj) {
    kdfparams_obj_t *kdfparams_obj = calloc(sizeof(kdfparams_obj_t), 1);

    if ((kdfparams_obj->dklen = get_json_num_value(kdfparams_json_obj, "dklen")) != KEY_FILE_ERR_NUM &&
        (kdfparams_obj->n = get_json_num_value(kdfparams_json_obj, "n")) != KEY_FILE_ERR_NUM &&
        (kdfparams_obj->p = get_json_num_value(kdfparams_json_obj, "p")) != KEY_FILE_ERR_NUM &&
        (kdfparams_obj->r = get_json_num_value(kdfparams_json_obj, "r")) != KEY_FILE_ERR_NUM &&
        (kdfparams_obj->salt = get_json_string_value(kdfparams_json_obj, "salt")) != KEY_FILE_ERR_POINTER) {

        return kdfparams_obj;
    }
    kdfparams_obj_put(kdfparams_obj);
    return KEY_FILE_ERR_POINTER;
}

cipherparams_obj_t *get_cipher_cipherparams(json_object *cipherparams_json_obj) {
    cipherparams_obj_t *cipherparams_obj = calloc(sizeof(cipherparams_obj_t), 1);

    if ((cipherparams_obj->iv = get_json_string_value(cipherparams_json_obj, "iv")) == KEY_FILE_ERR_POINTER) {

        cipherparams_obj_put(cipherparams_obj);
        return KEY_FILE_ERR_POINTER;
    }

    return cipherparams_obj;
}

char *get_crypto_mac(json_object *crypto_json_obj) {
    return get_json_string_value(crypto_json_obj, "mac");
}

char *get_crypto_kdf(json_object *crypto_json_obj) {
    return get_json_string_value(crypto_json_obj, "kdf");
}

char *get_crypto_ciphertext(json_object *crypto_json_obj) {
    return get_json_string_value(crypto_json_obj, "ciphertext");
}

char *get_crypto_cipher(json_object *crypto_json_obj) {
    return get_json_string_value(crypto_json_obj, "cipher");
}

crypto_obj_t *get_crypto_obj(json_object *crypto_json_obj) {
    crypto_obj_t *crypto_obj = calloc(sizeof(crypto_obj_t), 1);

    json_object *tmp_json_obj;
    if ((crypto_obj->cipher = get_crypto_cipher(crypto_json_obj)) != KEY_FILE_ERR_POINTER &&
        (crypto_obj->ciphertext = get_crypto_ciphertext(crypto_json_obj)) != KEY_FILE_ERR_POINTER &&
        (crypto_obj->kdf = get_crypto_kdf(crypto_json_obj)) != KEY_FILE_ERR_POINTER &&
        (crypto_obj->mac = get_crypto_mac(crypto_json_obj)) != KEY_FILE_ERR_POINTER &&

        (tmp_json_obj = get_json_object_value(crypto_json_obj, "cipherparams")) != KEY_FILE_ERR_POINTER &&
        (crypto_obj->cipherparams = get_cipher_cipherparams(tmp_json_obj)) != KEY_FILE_ERR_POINTER &&

        (tmp_json_obj = get_json_object_value(crypto_json_obj, "kdfparams")) != KEY_FILE_ERR_POINTER &&
        (crypto_obj->kdfparams = get_cipher_kdfparams(tmp_json_obj)) != KEY_FILE_ERR_POINTER) {

        return crypto_obj;
    }
    crypto_obj_put(crypto_obj);
    return KEY_FILE_ERR_POINTER;
}

char *get_key_address(json_object *key_json_obj) {
    return get_json_string_value(key_json_obj, "address");
}
/**
 * @brief get id
 * @param key_json_obj
 * @return[out] id
 */
char *get_key_id(json_object *key_json_obj) {
    return get_json_string_value(key_json_obj, "id");
}

int64_t get_key_version(json_object *key_json_obj) {
    int64_t ver = get_json_num_value(key_json_obj, "version");
    if (ver != 3) {
        return KEY_FILE_ERR_NUM;
    }
    return ver;
}

key_file_obj_t *get_key_obj(json_object *key_json_obj) {
    key_file_obj_t *key_obj = calloc(sizeof(key_file_obj_t), 1);

    json_object *crypto_json_obj;
    if ((key_obj->version = get_key_version(key_json_obj)) != KEY_FILE_ERR_NUM &&
        (key_obj->id = get_key_id(key_json_obj)) != KEY_FILE_ERR_POINTER &&
        (key_obj->address = get_key_address(key_json_obj)) != KEY_FILE_ERR_POINTER &&

        (crypto_json_obj = get_json_object_value(key_json_obj, "crypto")) != KEY_FILE_ERR_POINTER &&
        (key_obj->crypto = get_crypto_obj(crypto_json_obj)) != KEY_FILE_ERR_POINTER) {

        return key_obj;
    }
    key_file_obj_put(key_obj);
    return KEY_FILE_ERR_POINTER;
}

/*
 * others
 * ***********************************************************
 */

int extract_key_file_obj(const char *passphrase, key_file_obj_t *key_file_obj, key_result_t **ptr_key_result) {
    int status = KEY_FILE_SUCCESS;
    uint8_t *buf_mac = NULL;
    uint8_t *buf_mac_sha3 = NULL;
    uint8_t *ciphertext_raw = NULL;
    uint8_t *salt_hex;
    key_result_t *key_result = *ptr_key_result = calloc(sizeof(key_result_t), 1);

    crypto_obj_t *crypto_obj = key_file_obj->crypto;

    // check params range
    kdfparams_obj_t *kdfparams_obj = crypto_obj->kdfparams;
    size_t max = 1 << 30;
    if (kdfparams_obj->r * kdfparams_obj->p >= max) {
        status = KEY_FILE_ERR_DATA;
        goto clean_variable;
    }

    // key derivation
    size_t dec_key_len = (size_t) kdfparams_obj->dklen;
    key_result->dec_key = malloc(dec_key_len);
    char *salt = kdfparams_obj->salt;
    salt_hex = str2hex(strlen(salt), salt);
    int err = libscrypt_scrypt((uint8_t *) passphrase, strlen(passphrase),
                               salt_hex, strlen(salt)/2,
                               (uint64_t) kdfparams_obj->n,
                               (uint32_t) kdfparams_obj->r,
                               (uint32_t) kdfparams_obj->p,
                               key_result->dec_key,
                               dec_key_len
    );
    if (err != 0) {
        status = KEY_FILE_ERR_UNKNOWN;
        goto clean_variable;
    }

    // check derived key
    char *ciphertext_str = crypto_obj->ciphertext;
    size_t ciphertext_len = strlen(ciphertext_str);

    ciphertext_raw = str2hex(ciphertext_len, ciphertext_str);
    size_t buf_ciphertext_len = ciphertext_len / 2;

    size_t left_len = dec_key_len / 2;
    size_t buf_mac_len = left_len  + buf_ciphertext_len;
    buf_mac = malloc(buf_mac_len);

    memcpy(buf_mac, key_result->dec_key + left_len, left_len);
    memcpy(buf_mac + left_len, ciphertext_raw, buf_ciphertext_len);

    buf_mac_sha3 = malloc(CRYPTO_SHA3_DIGEST_SIZE);
    sha3_256_of_str(buf_mac, (int) buf_mac_len, buf_mac_sha3);

    char *str_mac_sha3 = hex2str(CRYPTO_SHA3_DIGEST_SIZE, buf_mac_sha3);
    if (strcmp(str_mac_sha3, crypto_obj->mac) != 0) {
        status = KEY_FILE_ERR_VALID;
        goto clean_variable;
    }

    // get private key
    key_result->priv_key = malloc(dec_key_len);

    char *iv_str = crypto_obj->cipherparams->iv;
    // TODO: must be AES_BLOCK_SIZE=16 bytes
    uint8_t *iv_raw = str2hex(strlen(iv_str), iv_str);

    struct CTR_CTX(struct aes128_ctx, AES_BLOCK_SIZE) ctx;
    CTR_SET_COUNTER(&ctx, iv_raw);
    aes128_set_encrypt_key(&ctx.ctx, key_result->dec_key);
    CTR_CRYPT(&ctx, aes128_encrypt, dec_key_len, key_result->priv_key, ciphertext_raw);
    key_result->key_len = dec_key_len;

clean_variable:
    if (buf_mac) {
        free(buf_mac);
    }
    if (buf_mac_sha3) {
        free(buf_mac_sha3);
    }
    if (ciphertext_raw) {
        free(ciphertext_raw);
    }
    if (status != KEY_FILE_SUCCESS) {
        key_result_put(key_result);
        *ptr_key_result = NULL;
    }
    return status;
}

json_object *parse_key_file(char *path) {
    FILE *fp = NULL;
    char *buff = NULL;
    key_file_obj_t *key_file_obj = NULL;

    // check in case of over-sized
    fp = fopen(path, "r");
    fseek(fp, 0, SEEK_END);
    size_t len = (size_t) ftell(fp);
    if (len > 1024) {
        goto clean_variable;
    }

    // read from file
    fseek(fp, 0, SEEK_SET);
    buff = malloc(len);
    if (fread(buff, 1, len, fp) != len) {
        goto clean_variable;
    }

    // parse data as json
    json_object *key_json_obj = json_tokener_parse(buff);
    if (key_json_obj == NULL) {
        goto clean_variable;
    }

    // parse json as struct
    if ((key_file_obj = get_key_obj(key_json_obj)) == NULL) {
        goto clean_variable;
    }

    return key_json_obj;

clean_variable:
    if (fp) {
        fclose(fp);
    }
    if (buff) {
        free(buff);
    }
    if (key_json_obj) {
        json_object_put(key_json_obj);
    }
    key_file_obj_put(key_file_obj);
    return KEY_FILE_ERR_POINTER;
}
