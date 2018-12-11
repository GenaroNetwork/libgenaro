/**
 * @file uploader.h
 * @brief Genaro upload methods and definitions.
 *
 * Structures and functions useful for uploading files.
 */
#ifndef GENARO_UPLOADER_H
#define GENARO_UPLOADER_H
#include "genaro.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"
#include "rs.h"

#define GENARO_NULL -1
#define GENARO_MAX_REPORT_TRIES 2
#define GENARO_MAX_PUSH_FRAME_COUNT 3
#define GENARO_MAX_ADD_BUCKET_ENTRY 3
#define GENARO_MAX_PUSH_SHARD 3
#define GENARO_MAX_CREATE_ENCRYPTED_FILE 3
#define GENARO_MAX_REQUEST_FRAME_ID 3
#define GENARO_MAX_VERIFY_BUCKET_ID 3

typedef enum {
    CANCELED = 0,
    AWAITING_PREPARE_FRAME = 1,
    PREPARING_FRAME = 2,
    AWAITING_PUSH_FRAME = 3,
    PUSHING_FRAME = 4,
    AWAITING_PUSH_SHARD = 5,
    PUSHING_SHARD = 6,
    COMPLETED_PUSH_SHARD = 7
} genaro_state_progress_t;

typedef enum {
    PREPARE_FRAME_LIMIT = 1,
    PUSH_FRAME_LIMIT = 32,
    PUSH_SHARD_LIMIT = 32
} genaro_state_progress_limits_t;

typedef struct {
    /* state should not be modified in worker threads */
    genaro_upload_state_t *upload_state;
    int status_code;
    int error_status;
    shard_meta_t *shard_meta;
    // Position in shard meta array
    int shard_meta_index;
    // Either parity file pointer or original file
    FILE *shard_file;
    genaro_log_levels_t *log;
} frame_builder_t;

typedef struct {
    int error_status;
    /* state should not be modified in worker threads */
    genaro_upload_state_t *upload_state;
} parity_shard_req_t;

typedef struct {
    int error_status;
    /* state should not be modified in worker threads */
    genaro_upload_state_t *upload_state;
} encrypt_file_req_t;

typedef struct {
    genaro_http_options_t *http_options;
    genaro_bridge_options_t *options;
    int status_code;
    int error_status;
    genaro_log_levels_t *log;
    int shard_index;
    int shard_meta_index;
    FILE *shard_file;
    uv_async_t progress_handle;
    uint64_t start;
    uint64_t end;

    /* state should not be modified in worker threads */
    genaro_upload_state_t *upload_state;
    bool *canceled;
} push_shard_request_t;

typedef struct {
    genaro_http_options_t *http_options;
    genaro_bridge_options_t *options;
    char *token;
    const char *bucket_id;
    char *bucket_op;
    /* state should not be modified in worker threads */
    genaro_upload_state_t *upload_state;
    int status_code;
    int error_status;
    genaro_log_levels_t *log;
} request_token_t;

typedef struct {
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *options;
    /* state should not be modified in worker threads */
    genaro_upload_state_t *upload_state;
    char *frame_id;
    int status_code;
    int error_status;
    struct json_object *response;

    // Add shard to frame
    int shard_meta_index;
    farmer_pointer_t *farmer_pointer;

    genaro_log_levels_t *log;
} frame_request_t;

typedef struct {
  genaro_http_options_t *http_options;
  genaro_encrypt_options_t *encrypt_options;
  genaro_bridge_options_t *options;
  /* state should not be modified in worker threads */
  genaro_upload_state_t *upload_state;
  int status_code;
  int error_status;
  struct json_object *response;
  genaro_log_levels_t *log;
} post_to_bucket_request_t;

typedef struct {
    uint32_t pointer_index;
    genaro_http_options_t *http_options;
    genaro_encrypt_options_t *encrypt_options;
    genaro_bridge_options_t *options;
    int status_code;
    genaro_exchange_report_t *report;
    /* state should not be modified in worker threads */
    genaro_upload_state_t *state;
} shard_send_report_t;

static farmer_pointer_t *farmer_pointer_new();
static shard_meta_t *shard_meta_new();
static uv_work_t *shard_meta_work_new(int index, genaro_upload_state_t *state);
static uv_work_t *frame_work_new(int *index, genaro_upload_state_t *state);
static uv_work_t *uv_work_new();

static int check_in_progress(genaro_upload_state_t *state, int status);
char *create_tmp_name(genaro_upload_state_t *state, char *extension);

static void shard_meta_cleanup(shard_meta_t *shard_meta);
static void pointer_cleanup(farmer_pointer_t *farmer_pointer);
static void cleanup_state(genaro_upload_state_t *state);
genaro_encryption_ctx_t *prepare_encryption_ctx(uint8_t *ctr, uint8_t *pass);
void free_encryption_ctx(genaro_encryption_ctx_t *ctx);

static void queue_next_work(genaro_upload_state_t *state);

static void queue_request_frame_id(genaro_upload_state_t *state);
static void queue_prepare_frame(genaro_upload_state_t *state, int index);
static void queue_push_frame(genaro_upload_state_t *state, int index);
static void queue_push_shard(genaro_upload_state_t *state, int index);
static void queue_create_bucket_entry(genaro_upload_state_t *state);
static void queue_send_exchange_report(genaro_upload_state_t *state, int index);
static void queue_create_encrypted_file(genaro_upload_state_t *state);

static void request_frame_id(uv_work_t *work);
static void prepare_frame(uv_work_t *work);
static void push_frame(uv_work_t *work);
static void push_shard(uv_work_t *work);
static void create_bucket_entry(uv_work_t *work);
static void send_exchange_report(uv_work_t *work);
static void create_encrypted_file(uv_work_t *work);

static void after_request_frame_id(uv_work_t *work, int status);
static void after_prepare_frame(uv_work_t *work, int status);
static void after_push_frame(uv_work_t *work, int status);
static void after_push_shard(uv_work_t *work, int status);
static void after_create_bucket_entry(uv_work_t *work, int status);
static void after_send_exchange_report(uv_work_t *work, int status);
static void after_create_encrypted_file(uv_work_t *work, int status);

static void queue_verify_bucket_id(genaro_upload_state_t *state);
static void verify_bucket_id_callback(uv_work_t *work_req, int status);

#endif /* GENARO_UPLOADER_H */
