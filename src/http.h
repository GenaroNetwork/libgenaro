/**
 * @file http.h
 * @brief Storj HTTP utilities.
 *
 * Helper methods and utilities for http requests.
 */
#ifndef STORJ_HTTP_H
#define STORJ_HTTP_H

#include <curl/curl.h>
#include <nettle/sha.h>
#include <nettle/ripemd160.h>

#ifdef _WIN32
#include <signal.h>
#endif

#include "storj.h"
#include "utils.h"
#include "crypto.h"

#define SHARD_PROGRESS_INTERVAL BUFSIZ * 8

/** @brief A structure for sharing download progress state between threads.
 *
 * This structure is used to send async updates from a worker thread
 * back to the event loop thread, to report the bytes that have been
 * received for a shard.
 */
typedef struct {
    uint32_t pointer_index;
    uint64_t bytes;
    /* state should not be modified in worker threads */
    void *state;
} shard_download_progress_t;

/** @brief A structure for sharing upload progress state between threads.
 *
 * This structure is used to send async updates from a worker thread
 * back to the event loop thread, to report the bytes that have been
 * received for a shard.
 */
typedef struct {
    uint32_t pointer_index;
    uint64_t bytes;
    /* state should not be modified in worker threads */
    void *state;
} shard_upload_progress_t;

typedef struct {
    FILE *fd;
    storj_encryption_ctx_t *ctx;
    uint64_t offset;
    uint64_t length;
    uint64_t remain;
    uint64_t total_sent;
    uint64_t bytes_since_progress;
    uv_async_t *progress_handle;
    int error_code;
    bool *canceled;
} shard_body_send_t;

typedef struct {
    uint8_t *tail;
    size_t tail_position;
    size_t tail_length;
    uint8_t *data;
    size_t length;
    size_t bytes_since_progress;
    uint64_t shard_total_bytes;
    uv_async_t *progress_handle;
    bool *canceled;
    struct sha256_ctx *sha256_ctx;
    FILE *destination;
    uint64_t file_position;
    int error_code;
} shard_body_receive_t;

typedef struct {
    uint8_t *data;
    size_t length;
} http_body_receive_t;

typedef struct {
    void *pnt;
    uint64_t remain;
} http_body_send_t;

/**
 * @brief Send a shard to a farmer via an HTTP request
 *
 * @param[in] http_options The HTTP options including proxy
 * @param[in] farmer_id The farmer id
 * @param[in] proto The protocol "http" or "https"
 * @param[in] host The farmer host address
 * @param[in] port The farmer port
 * @param[in] shard_hash The hash of the shard to send
 * @param[in] shard_total_bytes The total bytes of the shard
 * @param[in] shard_data The actual bytes
 * @param[in] token The farmer token for uploading
 * @param[in] status_code The HTTP response status code
 * @param[in] progress_handle The async handle for progress updates
 * @param[in] canceled Pointer for canceling uploads
 * @return A non-zero error value on failure and 0 on success.
 */
int put_shard(storj_http_options_t *http_options,
              char *farmer_id,
              char *proto,
              char *host,
              int port,
              char *shard_hash,
              uint64_t shard_total_bytes,
              FILE *original_file,
              uint64_t file_position,
              storj_encryption_ctx_t *ctx,
              char *token,
              int *status_code,
              int *read_code,
              uv_async_t *progress_handle,
              bool *canceled);

/**
 * @brief Make a HTTP request for a shard
 *
 * @param[in] http_options The HTTP options including proxy
 * @param[in] farmer_id The farmer id
 * @param[in] proto The protocol "http" or "https"
 * @param[in] host The farmer host address
 * @param[in] port The farmer port
 * @param[in] shard_hash The hash of the shard to fetch
 * @param[in] shard_total_bytes The total bytes of the shard
 * @param[in] shard_data The actual bytes
 * @param[in] token The farmer token for downloading
 * @param[in] status_code The HTTP response status code
 * @param[in] progress_handle The async handle for progress updates
 * @param[in] canceled Pointer for canceling downloads
 * @return A non-zero error value on failure and 0 on success.
 */
int fetch_shard(storj_http_options_t *http_options,
                char *farmer_id,
                char *proto,
                char *host,
                int port,
                char *shard_hash,
                uint64_t shard_total_bytes,
                char *token,
                FILE *destination,
                uint64_t file_position,
                int *status_code,
                int *write_code,
                uv_async_t *progress_handle,
                bool *canceled);

/**
 * @brief Make a JSON HTTP request
 *
 * @param[in] options The storj bridge options
 * @param[in] method The HTTP method
 * @param[in] path The path of the resource
 * @param[in] request_body A json object of the request body
 * @param[in] auth Boolean to include authentication
 * @param[out] status_code The resulting status code from the request
 * @return A non-zero error value on failure and 0 on success.
 */
int fetch_json(storj_http_options_t *http_options,
               storj_bridge_options_t *options,
               char *method,
               char *path,
               struct json_object *request_body,
               bool auth,
               struct json_object **response,
               int *status_code);


#endif /* STORJ_HTTP_H */
