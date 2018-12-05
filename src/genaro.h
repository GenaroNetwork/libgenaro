/**
 * @file genaro.h
 * @brief Genaro library.
 *
 * Implements functionality to upload and download files from the Genaro
 * distributed network.
 */

#ifndef GENARO_H
#define GENARO_H

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(GENARODLL)
  #if defined(DLL_EXPORT)
    #define GENARO_API __declspec(dllexport)
  #else
    #define GENARO_API __declspec(dllimport)
  #endif
#else
  #define GENARO_API
#endif

#include <assert.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <uv.h>
#include <curl/curl.h>
#include <secp256k1.h>
#include <nettle/sha.h>

#include <inttypes.h>

#ifdef _WIN32
#include <time.h>
#endif

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>

#endif

// File transfer success
#define GENARO_TRANSFER_OK 0
#define GENARO_TRANSFER_CANCELED 1

// Bridge related errors 1000 to 1999
#define GENARO_BRIDGE_REQUEST_ERROR 1000
#define GENARO_BRIDGE_AUTH_ERROR 1001
#define GENARO_BRIDGE_TOKEN_ERROR 1002
#define GENARO_BRIDGE_TIMEOUT_ERROR 1003
#define GENARO_BRIDGE_INTERNAL_ERROR 1004
#define GENARO_BRIDGE_RATE_ERROR 1005
#define GENARO_BRIDGE_BUCKET_NOTFOUND_ERROR 1006
#define GENARO_BRIDGE_FILE_NOTFOUND_ERROR 1007
#define GENARO_BRIDGE_JSON_ERROR 1008
#define GENARO_BRIDGE_FRAME_ERROR 1009
#define GENARO_BRIDGE_POINTER_ERROR 1010
#define GENARO_BRIDGE_REPOINTER_ERROR 1011
#define GENARO_BRIDGE_FILEINFO_ERROR 1012
#define GENARO_BRIDGE_BUCKET_FILE_EXISTS 1013
#define GENARO_BRIDGE_OFFER_ERROR 1014
#define GENARO_BRIDGE_DECRYPTION_KEY_ERROR 1015

// Farmer related errors 2000 to 2999
#define GENARO_FARMER_REQUEST_ERROR 2000
#define GENARO_FARMER_TIMEOUT_ERROR 2001
#define GENARO_FARMER_AUTH_ERROR 2002
#define GENARO_FARMER_EXHAUSTED_ERROR 2003
#define GENARO_FARMER_INTEGRITY_ERROR 2004

// File related errors 3000 to 3999
#define GENARO_FILE_INTEGRITY_ERROR 3000
#define GENARO_FILE_WRITE_ERROR 3001
#define GENARO_FILE_ENCRYPTION_ERROR 3002
#define GENARO_FILE_SIZE_ERROR 3003
#define GENARO_FILE_DECRYPTION_ERROR 3004
#define GENARO_FILE_GENERATE_HMAC_ERROR 3005
#define GENARO_FILE_READ_ERROR 3006
#define GENARO_FILE_SHARD_MISSING_ERROR 3007
#define GENARO_FILE_RECOVER_ERROR 3008
#define GENARO_FILE_RESIZE_ERROR 3009
#define GENARO_FILE_UNSUPPORTED_ERASURE 3010
#define GENARO_FILE_PARITY_ERROR 3011

// Memory related errors
#define GENARO_MEMORY_ERROR 4000
#define GENARO_MAPPING_ERROR 4001
#define GENARO_UNMAPPING_ERROR 4002

// Queue related errors
#define GENARO_QUEUE_ERROR 5000

// Meta related errors 6000 to 6999
#define GENARO_META_ENCRYPTION_ERROR 6000
#define GENARO_META_DECRYPTION_ERROR 6001

// Miscellaneous errors
#define GENARO_HEX_DECODE_ERROR 7000

// Exchange report codes
#define GENARO_REPORT_SUCCESS 1000
#define GENARO_REPORT_FAILURE 1100

// Exchange report messages
#define GENARO_REPORT_FAILED_INTEGRITY "FAILED_INTEGRITY"
#define GENARO_REPORT_SHARD_DOWNLOADED "SHARD_DOWNLOADED"
#define GENARO_REPORT_SHARD_UPLOADED "SHARD_UPLOADED"
#define GENARO_REPORT_DOWNLOAD_ERROR "DOWNLOAD_ERROR"
#define GENARO_REPORT_UPLOAD_ERROR "TRANSFER_FAILED"

#define GENARO_SHARD_CHALLENGES 4
#define GENARO_LOW_SPEED_LIMIT 30720L
#define GENARO_LOW_SPEED_TIME 20L
#define GENARO_HTTP_TIMEOUT 60L

typedef struct {
    uint8_t *key;
    uint8_t *ctr;
} genaro_key_ctr_t;

typedef struct {
    const char *key_as_str;
    const char *ctr_as_str;
} genaro_key_ctr_as_str_t;

typedef struct {
    genaro_key_ctr_as_str_t *key_ctr_as_str;
    char *index;
} genaro_encryption_info_t;

typedef struct {
    uint8_t *encryption_ctr;
    struct aes256_ctx *ctx;
} genaro_encryption_ctx_t;

typedef enum {
    GENARO_REPORT_NOT_PREPARED = 0,
    GENARO_REPORT_AWAITING_SEND = 1,
    GENARO_REPORT_SENDING = 2,
    GENARO_REPORT_SENT = 3
} exchange_report_status_t;

/** @brief Bridge configuration options
 *
 * Proto can be "http" or "https", and the user/pass are used for
 * basic authentication to a Genaro bridge.
 */
typedef struct {
    const char *proto;
    const char *host;
    int port;
} genaro_bridge_options_t;

/** @brief File encryption options
 *
 * The mnemonic is a BIP39 secret code used for generating keys for file
 * encryption and decryption.
 */
typedef struct genaro_encrypt_options {
    uint8_t *priv_key;
    size_t key_len;
} genaro_encrypt_options_t;

/** @brief HTTP configuration options
 *
 * Settings for making HTTP requests
 */
typedef struct genaro_http_options {
    const char *user_agent;
    const char *proxy_url;
    const char *cainfo_path;
    uint64_t low_speed_limit;
    uint64_t low_speed_time;
    uint64_t timeout;
} genaro_http_options_t;

/** @brief A function signature for logging
 */
typedef void (*genaro_logger_fn)(const char *message, int level, void *handle);

/** @brief Logging configuration options
 *
 * Settings for logging
 */
typedef struct genaro_log_options {
    genaro_logger_fn logger;
    int level;
} genaro_log_options_t;

/** @brief A function signature for logging
 */
typedef void (*genaro_logger_format_fn)(genaro_log_options_t *options,
                                       void *handle,
                                       const char *format, ...);

/** @brief Functions for all logging levels
 */
typedef struct genaro_log_levels {
    genaro_logger_format_fn debug;
    genaro_logger_format_fn info;
    genaro_logger_format_fn warn;
    genaro_logger_format_fn error;
} genaro_log_levels_t;

/** @brief A structure for a Genaro user environment.
 *
 * This is the highest level structure and holds many commonly used options
 * and the event loop for queuing work.
 */
typedef struct genaro_env {
    genaro_bridge_options_t *bridge_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_http_options_t *http_options;
    genaro_log_options_t *log_options;
    bool is_support_share;
    const char *tmp_path;
    uv_loop_t *loop;
    genaro_log_levels_t *log;
} genaro_env_t;

/** @brief A structure for queueing json request work
 */
typedef struct {
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *options;
    char *method;
    char *path;
    bool auth;
    struct json_object *body;
    struct json_object *response;
    int error_code;
    int status_code;
    void *handle;
} json_request_t;

/** @brief A structure for that describes a bucket
 */
typedef struct {
    const char *created;
    const char *name;
    const char *id;
    const char *bucketId;
    int32_t type;
    bool decrypted;
    uint64_t limitStorage;
    uint64_t usedStorage;
    uint64_t timeStart;
    uint64_t timeEnd;
} genaro_bucket_meta_t;

/** @brief A structure for queueing create bucket request work
 */
typedef struct {
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *bridge_options;
    const char *bucket_name;
    const char *encrypted_bucket_name;
    struct json_object *response;
    genaro_bucket_meta_t *bucket;
    int error_code;
    int status_code;
    void *handle;
} create_bucket_request_t;

/** @brief A structure for queueing list buckets request work
 */
typedef struct {
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *options;
    char *method;
    char *path;
    bool auth;
    struct json_object *body;
    struct json_object *response;
    genaro_bucket_meta_t *buckets;
    uint32_t total_buckets;
    int error_code;
    int status_code;
    void *handle;
} get_buckets_request_t;

/** @brief A structure for queueing get bucket request work
 */
typedef struct {
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *options;
    char *method;
    char *path;
    bool auth;
    struct json_object *body;
    struct json_object *response;
    genaro_bucket_meta_t *bucket;
    int error_code;
    int status_code;
    void *handle;
} get_bucket_request_t;

/** @brief A structure for queueing rename bucket request work
 */
typedef struct {
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *options;
    const char *bucket_name;
    const char *encrypted_bucket_name;
    char *method;
    char *path;
    bool auth;
    struct json_object *body;
    struct json_object *response;
    int error_code;
    int status_code;
    void *handle;
} rename_bucket_request_t;

/** @brief A structure for queueing store decrypt key request work
 */
typedef struct {
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *options;
    const char *bucket_id;
    const char *file_id;
    const char *index;
    char *method;
    char *path;
    bool auth;
    struct json_object *body;
    struct json_object *response;
    int error_code;
    int status_code;
    char *decrypt_key;
    void *handle;
} share_file_request_t;

/** @brief A structure for that describes a bucket entry/file
 */
typedef struct {
    bool isShareFile;
    const char *created;
    const char *filename;
    const char *mimetype;
    const char *erasure;
    uint64_t size;
    const char *hmac;
    const char *id;
    bool decrypted;
    const char *index;
    const char *rsaKey;
    const char *rsaCtr;
} genaro_file_meta_t;

/** @brief A structure for queueing list files request work
 */
typedef struct {
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *options;
    bool is_support_share;
    const char *bucket_id;
    char *method;
    char *path;
    bool auth;
    struct json_object *body;
    struct json_object *response;
    genaro_file_meta_t *files;
    uint32_t total_files;
    int error_code;
    int status_code;
    void *handle;
} list_files_request_t;

typedef enum {
    BUCKET_PUSH,
    BUCKET_PULL
} genaro_bucket_op_t;

/** @brief A data structure that represents an exchange report
 *
 * These are sent at the end of an exchange with a farmer to report the
 * performance and reliability of farmers.
 */
typedef struct {
    char *data_hash;
    char *reporter_id;
    char *farmer_id;
    char *client_id;
    uint64_t start;
    uint64_t end;
    unsigned int code;
    char *message;
    unsigned int send_status;
    unsigned int send_count;
    uint32_t pointer_index;
} genaro_exchange_report_t;

/** @brief A function signature for download/upload progress callback
 */
/*typedef void (*genaro_progress_cb)(double progress,
                                  uint64_t bytes,
                                  uint64_t total_bytes,
                                  void *handle);
*/

typedef void (*genaro_progress_upload_cb)(double progress,
                                          uint64_t file_bytes,
                                          void *handle);

/*typedef void (*genaro_progress_download_cb)(double progress,
                                  uint64_t bytes,
                                  uint64_t total_bytes,
                                  void *handle);*/

typedef void (*genaro_progress_download_cb)(double progress,
                                            uint64_t file_bytes,
                                            void *handle);

/** @brief A function signature for a download complete callback
 */
typedef void (*genaro_finished_download_cb)(int status,
                                            const char *file_name,
                                            const char *temp_file_name,
                                            FILE *fd,
                                            uint64_t file_bytes,
                                            char *sha256,
                                            void *handle);

/** @brief A function signature for an upload complete callback
 */
typedef void (*genaro_finished_upload_cb)(const char *bucket_id,
                                          const char *file_name,
                                          int error_status,
                                          char *file_id,
                                          uint64_t file_bytes,
                                          char *sha256_of_encrypted,  // The sha256 value of the encrypted file(not including the parity shards)
                                          void *handle);

/** @brief A structure that represents a pointer to a shard
 *
 * A shard is an encrypted piece of a file, a pointer holds all necessary
 * information to retrieve a shard from a farmer, including the IP address
 * and port of the farmer, as well as a token indicating a transfer has been
 * authorized. Other necessary information such as the expected hash of the
 * data, and the index position in the file is also included.
 *
 * The data can be replaced with new farmer contact, in case of failure, and the
 * total number of replacements can be tracked.
 */
typedef struct {
    unsigned int replace_count;
    char *token;
    char *shard_hash;
    uint32_t index;
    int status;
    uint64_t size;
    bool parity;
    uint64_t downloaded_size;
    char *farmer_id;
    char *farmer_address;
    int farmer_port;
    genaro_exchange_report_t *report;
    uv_work_t *work;
} genaro_pointer_t;

/** @brief A structure for file upload options
 */
typedef struct {
    int prepare_frame_limit;
    int push_frame_limit;
    int push_shard_limit;
    bool rs;
    const char *bucket_id;
    const char *file_name;
    FILE *fd;
} genaro_upload_opts_t;

/** @brief A structure that keeps state between multiple worker threads,
 * and for referencing a download to apply actions to an in-progress download.
 *
 * After work has been completed in a thread, its after work callback will
 * update and modify the state and then queue the next set of work based on the
 * changes, and added to the event loop. The state is all managed within one
 * thread, the event loop thread, and any work that is performed in another
 * thread should not modify this structure directly, but should pass a
 * reference to it, so that once the work is complete the state can be updated.
 */
typedef struct genaro_download_state {
    genaro_file_meta_t *info;
    bool requesting_info;
    uint32_t info_fail_count;
    genaro_env_t *env;
    const char *file_id;
    const char *bucket_id;
    const char *file_name;
    const char *temp_file_name;
    FILE *destination;
    genaro_progress_download_cb progress_cb;
    genaro_finished_download_cb finished_cb;
    bool finished;
    bool canceled;
    uint64_t shard_size;
    uint32_t total_shards;
    int download_max_concurrency;
    uint32_t completed_shards;
    uint32_t resolving_shards;
    genaro_pointer_t *pointers;
    char *excluded_farmer_ids;
    uint32_t total_pointers;
    uint32_t total_parity_pointers;
    bool rs;
    bool recovering_shards;
    bool truncated;
    bool pointers_completed;
    uint32_t pointer_fail_count;
    bool requesting_pointers;
    int error_status;
    char *error_from_bridge;
    bool writing;
    genaro_key_ctr_t *key_ctr;
    const char *hmac;
    uint32_t pending_work_count;
    genaro_log_levels_t *log;
    bool decrypt;
    void *handle;

    uint64_t file_size;

    // sha256 of the downloaded file
    char *sha256;
} genaro_download_state_t;

typedef struct {
    char *hash;
    uint8_t challenges[GENARO_SHARD_CHALLENGES][32];
    char challenges_as_str[GENARO_SHARD_CHALLENGES][64 + 1];
    // Merkle Tree leaves. Each leaf is size of RIPEMD160 hash
    char tree[GENARO_SHARD_CHALLENGES][20 * 2 + 1];
    int index;
    bool is_parity;
    uint64_t size;
} shard_meta_t;

typedef struct {
    char *token;
    char *farmer_user_agent;
    char *farmer_protocol;
    char *farmer_address;
    char *farmer_port;
    char *farmer_node_id;
} farmer_pointer_t;

typedef struct {
    int progress;
    int push_frame_request_count;
    int push_shard_request_count;
    int index;
    farmer_pointer_t *pointer;
    shard_meta_t *meta;
    genaro_exchange_report_t *report;
    uint64_t uploaded_size;
    uv_work_t *work;
} shard_tracker_t;

typedef struct genaro_upload_state {
    genaro_env_t *env;
    uint32_t shard_concurrency;
    const char *index;
    const char *file_name;
    char *file_id;
    const char *encrypted_file_name;
    FILE *original_file;
    uint64_t file_size;
    const char *bucket_id;
    char *bucket_key;
    uint32_t completed_shards;
    uint32_t total_shards;
    uint32_t total_data_shards;
    uint32_t total_parity_shards;
    uint64_t shard_size;
    uint64_t total_bytes;
    uint64_t uploaded_bytes;
    char *exclude;
    char *frame_id;
    char *hmac_id;
    genaro_key_ctr_t *key_ctr;
    genaro_key_ctr_as_str_t *rsa_key_ctr_as_str;

    // TODO: change this to opts or env
    bool rs;
    bool awaiting_parity_shards;
    char *parity_file_path;
    FILE *parity_file;
    char *encrypted_file_path;
    FILE *encrypted_file;
    bool creating_encrypted_file;

    bool requesting_frame;
    bool completed_upload;
    bool creating_bucket_entry;
    bool received_all_pointers;
    bool final_callback_called;
    bool canceled;
    bool bucket_verified;
    bool file_verified;

    bool progress_finished;

    int push_shard_limit;
    int push_frame_limit;
    int prepare_frame_limit;

    int frame_request_count;
    int add_bucket_entry_count;
    int bucket_verify_count;
    int file_verify_count;
    int create_encrypted_file_count;

    genaro_progress_upload_cb progress_cb;
    genaro_finished_upload_cb finished_cb;
    int error_status;
    char *error_from_bridge;
    genaro_log_levels_t *log;
    void *handle;
    shard_tracker_t *shard;
    int pending_work_count;

    // used to calculate the sha256 of the encrypted file(not including the parity shards)
    struct sha256_ctx sha256_of_encrypted_ctx;
    char *sha256_of_encrypted;
} genaro_upload_state_t;

typedef struct {
    uint8_t *dec_key;
    uint8_t *priv_key;
    size_t key_len;
} key_result_t;

GENARO_API key_result_t *genaro_parse_key_file(json_object *key_json_obj, const char *passphrase);
GENARO_API void genaro_key_result_to_encrypt_options(key_result_t *key_result, genaro_encrypt_options_t *encrypt_options);

/**
 * @brief Initialize a Genaro environment
 *
 * This will setup an event loop for queueing further actions, as well
 * as define necessary configuration options for communicating with Genaro
 * bridge, and for encrypting/decrypting files.
 *
 * @param[in] options - Genaro Bridge API options
 * @param[in] encrypt_options - File encryption options
 * @param[in] http_options - HTTP settings
 * @param[in] log_options - Logging settings
 * @param[in] is_support_share - Whether the feature of file share is support.
 * @return A null value on error, otherwise a genaro_env pointer.
 */
GENARO_API genaro_env_t *genaro_init_env(genaro_bridge_options_t *options,
                                         genaro_encrypt_options_t *encrypt_options,
                                         genaro_http_options_t *http_options,
                                         genaro_log_options_t *log_options,
                                         bool is_support_share);


/**
 * @brief Destroy a Genaro environment
 *
 * This will free all memory for the Genaro environment and zero out any memory
 * with sensitive information, such as passwords and encryption keys.
 *
 * The event loop must be closed before this method should be used.
 *
 * @param [in] env
 */
GENARO_API int genaro_destroy_env(genaro_env_t *env);

GENARO_API int genaro_write_auth(const char *filepath, json_object *key_json_obj);
GENARO_API int genaro_read_auth(const char *filepath, json_object **key_json_obj);

/**
 * @brief Will get the current unix timestamp in milliseconds
 *
 * @return A unix timestamp
 */
GENARO_API uint64_t genaro_util_timestamp();

/**
 * @brief Get the error message for an error code
 *
 * This function will return a error message associated with a genaro
 * error code.
 *
 * @param[in] error_code The genaro error code integer
 * @return A char pointer with error message
 */
GENARO_API char *genaro_strerror(int error_code);

/**
 * @brief Get Genaro bridge API information.
 *
 * This function will get general information about the genaro bridge api.
 * The network i/o is performed in a thread pool with a libuv loop, and the
 * response is available in the first argument to the callback function.
 *
 * @param[in] env The genaro environment struct
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_get_info(genaro_env_t *env,
                                      void *handle,
                                      uv_after_work_cb cb);

/**
 * @brief List available buckets for a user.
 *
 * @param[in] env The genaro environment struct
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_get_buckets(genaro_env_t *env,
                                         void *handle,
                                         uv_after_work_cb cb);

/**
 * @brief Will free all structs for get buckets request
 *
 * @param[in] req - The work request from genaro_bridge_get_buckets callback
 */
GENARO_API void genaro_free_get_buckets_request(get_buckets_request_t *req);

/**
 * @brief Create a bucket.
 *
 * @param[in] env The genaro environment struct
 * @param[in] name The name of the bucket
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_create_bucket(genaro_env_t *env,
                                           const char *name,
                                           void *handle,
                                           uv_after_work_cb cb);

/**
 * @brief Delete a bucket.
 *
 * @param[in] env The genaro environment struct
 * @param[in] id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_delete_bucket(genaro_env_t *env,
                                           const char *id,
                                           void *handle,
                                           uv_after_work_cb cb);

/**
 * @brief Rename a bucket.
 *
 * @param[in] env The genaro environment struct
 * @param[in] id The bucket id
 * @param[in] name The new name of bucket
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_rename_bucket(genaro_env_t *env,
                                           const char *id,
                                           const char *name,
                                           void *handle,
                                           uv_after_work_cb cb);

/**
 * @brief Get a info of specific bucket.
 *
 * @param[in] env The genaro environment struct
 * @param[in] id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_get_bucket(genaro_env_t *env,
                                        const char *id,
                                        void *handle,
                                        uv_after_work_cb cb);

/**
 * @brief Will free all structs for get bucket request
 *
 * @param[in] req - The work request from genaro_bridge_get_bucket callback
 */
GENARO_API void genaro_free_get_bucket_request(get_bucket_request_t *req);

/**
 * @brief Get a list of all files in a bucket.
 *
 * @param[in] env The genaro environment struct
 * @param[in] id The bucket id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_list_files(genaro_env_t *env,
                                        const char *id,
                                        void *handle,
                                        uv_after_work_cb cb);

/**
 * @brief Will free all structs for list files request
 *
 * @param[in] req - The work request from genaro_bridge_list_files callback
 */
GENARO_API void genaro_free_list_files_request(list_files_request_t *req);

/**
 * @brief Create a PUSH or PULL bucket token.
 *
 * @param[in] env The genaro environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] operation The type of operation PUSH or PULL
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_create_bucket_token(genaro_env_t *env,
                                                 const char *bucket_id,
                                                 genaro_bucket_op_t operation,
                                                 void *handle,
                                                 uv_after_work_cb cb);

/**
 * @brief Get pointers with locations to file shards.
 *
 * @param[in] env The genaro environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] file_id The file id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_get_file_pointers(genaro_env_t *env,
                                               const char *bucket_id,
                                               const char *file_id,
                                               void *handle,
                                               uv_after_work_cb cb);

/**
 * @brief Delete a file in a bucket.
 *
 * @param[in] env The genaro environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] file_id The file id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_delete_file(genaro_env_t *env,
                                         const char *bucket_id,
                                         const char *file_id,
                                         void *handle,
                                         uv_after_work_cb cb);

/**
 * @brief Create a file frame
 *
 * @param[in] env The genaro environment struct
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_create_frame(genaro_env_t *env,
                                          void *handle,
                                          uv_after_work_cb cb);

/**
 * @brief List available file frames
 *
 * @param[in] env The genaro environment struct
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_get_frames(genaro_env_t *env,
                                        void *handle,
                                        uv_after_work_cb cb);

/**
 * @brief Get information for a file frame
 *
 * @param[in] env The genaro environment struct
 * @param[in] frame_id The frame id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
 GENARO_API int genaro_bridge_get_frame(genaro_env_t *env,
                                        const char *frame_id,
                                        void *handle,
                                        uv_after_work_cb cb);

/**
 * @brief Delete a file frame
 *
 * @param[in] env The genaro environment struct
 * @param[in] frame_id The frame id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_delete_frame(genaro_env_t *env,
                                          const char *frame_id,
                                          void *handle,
                                          uv_after_work_cb cb);

/**
 * @brief Get metadata for a file
 *
 * @param[in] env The genaro environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] file_id The file id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_get_file_info(genaro_env_t *env,
                                           const char *bucket_id,
                                           const char *file_id,
                                           void *handle,
                                           uv_after_work_cb cb);

/**
 * @brief Get mirror data for a file
 *
 * @param[in] env The genaro environment struct
 * @param[in] bucket_id The bucket id
 * @param[in] file_id The file id
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] cb A function called with response when complete
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_list_mirrors(genaro_env_t *env,
                                          const char *bucket_id,
                                          const char *file_id,
                                          void *handle,
                                          uv_after_work_cb cb);


/**
 * @brief Generate the encryption key and ctr of AES256 CTR, and also the index that can regenerate them.
 * 
 * @param[in] env A pointer to environment
 * @param[in] index The salt of AES
 * @param[in] bucket_id The bucket id
 * @return A pointer to the encryption info.
 */
GENARO_API genaro_encryption_info_t *genaro_generate_encryption_info(genaro_env_t *env,
                                                                     const char *index,
                                                                     const char *bucket_id);

/**
 * @brief Will cancel an upload
 *
 * @param[in] state A pointer to the upload state
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_store_file_cancel(genaro_upload_state_t *state);

/**
 * @brief Upload a file
 *
 * @param[in] env A pointer to environment
 * @param[in] opts The options for the upload
 * @param[in] index The index that has generated key_ctr.
 * @param[in] key_ctr_as_str The key and ctr for file encryption
 * @param[in] rsa_key_ctr_as_str The RSA encrypted key and ctr
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] progress_cb Function called with progress updates
 * @param[in] finished_cb Function called when download finished
 * @return A pointer to the upload state.
 */
GENARO_API genaro_upload_state_t *genaro_bridge_store_file(genaro_env_t *env,
                                                           genaro_upload_opts_t *opts,
                                                           const char *index,
                                                           genaro_key_ctr_as_str_t *key_ctr_as_str,
                                                           genaro_key_ctr_as_str_t *rsa_key_ctr_as_str,
                                                           void *handle,
                                                           genaro_progress_upload_cb progress_cb,
                                                           genaro_finished_upload_cb finished_cb);

/**
 * @brief Will cancel a download
 *
 * @param[in] state A pointer to the download state
 * @return A non-zero error value on failure and 0 on success.
 */
GENARO_API int genaro_bridge_resolve_file_cancel(genaro_download_state_t *state);

/**
 * @brief Download a file
 *
 * @param[in] env A pointer to environment
 * @param[in] bucket_id Character array of bucket id
 * @param[in] file_id Character array of file id
 * @param[in] key_ctr_as_str The file encryption/decryption key and ctr
 * @param[in] file_name The file name include path
 * @param[in] temp_file_name The temp file name include path
 * @param[in] destination File descriptor of the destination
 * @param[in] decrypt Wheather to decrypt the file after download
 * @param[in] handle A pointer that will be available in the callback
 * @param[in] progress_cb Function called with progress updates
 * @param[in] finished_cb Function called when download finished
 * @return A pointer to the download state.
 */
GENARO_API genaro_download_state_t *genaro_bridge_resolve_file(genaro_env_t *env,
                                                               const char *bucket_id,
                                                               const char *file_id,
                                                               genaro_key_ctr_as_str_t *key_ctr_as_str,
                                                               const char *file_name,
                                                               const char *temp_file_name,
                                                               FILE *destination,
                                                               bool decrypt,
                                                               void *handle,
                                                               genaro_progress_download_cb progress_cb,
                                                               genaro_finished_download_cb finished_cb);

/**
 * @brief Encrypt meta information using AES-256-GCM and HMAC-SHA256
 *
 * @param[in] env A pointer to environment
 * @param[in] meta A pointer to the meta
 * @return NULL on failure and the encrypted meta on success.
 */
GENARO_API char *genaro_encrypt_meta(genaro_env_t *env, 
                                     const char *meta);

/**
 * @brief Decrypt an encrypted meta
 *
 * @param[in] env A pointer to environment
 * @param[in] encrypted_meta A pointer to the encrypted meta
 * @return NULL on failure and the decrypted meta on success.
 */
GENARO_API char *genaro_decrypt_meta(genaro_env_t *env, 
                                     const char *encrypted_meta);

/**
 * @brief Decrypt a file that hasn't been decrypted
 *
 * @param[in] env A pointer to environment
 * @param[in] file_path The path of the undecrypted file
 * @param[in] key_ctr_as_str The file encryption/decryption key and ctr 
 * @return NULL on failure and the decrypted meta on success.
 */
GENARO_API char *genaro_decrypt_file(genaro_env_t *env, 
                                     const char *file_path,
                                     genaro_key_ctr_as_str_t *key_ctr_as_str);

/*Curl debug function*/
int curl_debug(CURL *pcurl, curl_infotype itype, char * pData, size_t size, void *userptr);

extern int genaro_debug;
extern char *curl_out_dir;

extern secp256k1_context *g_secp256k1_ctx;

static inline char separator()
{
#ifdef _WIN32
    return '\\';
#else
    return '/';
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* GENARO_H */
