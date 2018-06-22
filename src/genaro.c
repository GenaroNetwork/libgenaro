#include "genaro.h"
#include "http.h"
#include "utils.h"
#include "crypto.h"
#include "key_file.h"

static inline void noop() {};

static void json_request_worker(uv_work_t *work)
{
    json_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options, req->encrypt_options,
                                 req->options, req->method, req->path, NULL, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;
}

static void create_bucket_request_worker(uv_work_t *work)
{
    create_bucket_request_t *req = work->data;
    int status_code = 0;

    // Derive a key based on the master seed and bucket name magic number
    char *bucket_key_as_str = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    generate_bucket_key(req->encrypt_options->priv_key,
                        req->encrypt_options->key_len,
                        BUCKET_NAME_MAGIC,
                        &bucket_key_as_str);

    uint8_t *bucket_key = str2hex(strlen(bucket_key_as_str), bucket_key_as_str);
    if (!bucket_key) {
        req->error_code = GENARO_MEMORY_ERROR;
        return;
    }

    free(bucket_key_as_str);

    // Get bucket name encryption key with first half of hmac w/ magic
    struct hmac_sha512_ctx ctx1;
    hmac_sha512_set_key(&ctx1, SHA256_DIGEST_SIZE, bucket_key);
    hmac_sha512_update(&ctx1, SHA256_DIGEST_SIZE, BUCKET_META_MAGIC);
    uint8_t key[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&ctx1, SHA256_DIGEST_SIZE, key);

    // Generate the synthetic iv with first half of hmac w/ name
    struct hmac_sha512_ctx ctx2;
    hmac_sha512_set_key(&ctx2, SHA256_DIGEST_SIZE, bucket_key);
    hmac_sha512_update(&ctx2, strlen(req->bucket_name),
                       (uint8_t *)req->bucket_name);
    uint8_t bucketname_iv[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&ctx2, SHA256_DIGEST_SIZE, bucketname_iv);

    free(bucket_key);

    // Encrypt the bucket name
    char *encrypted_bucket_name;
    encrypt_meta(req->bucket_name, key, bucketname_iv, &encrypted_bucket_name);
    req->encrypted_bucket_name = encrypted_bucket_name;

    struct json_object *body = json_object_new_object();
    json_object *name = json_object_new_string(req->encrypted_bucket_name);
    json_object_object_add(body, "name", name);

    req->error_code = fetch_json(req->http_options, req->encrypt_options,
                                 req->bridge_options, "POST", "/buckets", NULL, body,
                                 true, &req->response, &status_code);

    json_object_put(body);

    if (req->response != NULL) {
        req->bucket = malloc(sizeof(genaro_bucket_meta_t));

        struct json_object *id;
        json_object_object_get_ex(req->response, "id", &id);

        req->bucket->id = json_object_get_string(id);
        req->bucket->name = req->bucket_name;
        req->bucket->decrypted = true;
    }

    req->status_code = status_code;
}

static void get_buckets_request_worker(uv_work_t *work)
{
    get_buckets_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options, req->encrypt_options,
                                 req->options, req->method, req->path, NULL, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;

    int num_buckets = 0;
    if (req->response != NULL &&
        json_object_is_type(req->response, json_type_array)) {
        num_buckets = json_object_array_length(req->response);
    }

    if (num_buckets > 0) {
        req->buckets = malloc(sizeof(genaro_bucket_meta_t) * num_buckets);
        req->total_buckets = num_buckets;
    }

    // Derive a key based on the master seed
    char *bucket_key_as_str = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    generate_bucket_key(req->encrypt_options->priv_key,
                        req->encrypt_options->key_len,
                        BUCKET_NAME_MAGIC,
                        &bucket_key_as_str);

    uint8_t *bucket_key = str2hex(strlen(bucket_key_as_str), bucket_key_as_str);
    if (!bucket_key) {
        req->error_code = GENARO_MEMORY_ERROR;
        return;
    }

    free(bucket_key_as_str);

    // Get bucket name encryption key with first half of hmac w/ magic
    struct hmac_sha512_ctx ctx1;
    hmac_sha512_set_key(&ctx1, SHA256_DIGEST_SIZE, bucket_key);
    hmac_sha512_update(&ctx1, SHA256_DIGEST_SIZE, BUCKET_META_MAGIC);
    uint8_t key[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&ctx1, SHA256_DIGEST_SIZE, key);

    free(bucket_key);

    struct json_object *bucket_item;
    struct json_object *name;
    struct json_object *created;
    struct json_object *id;

    for (int i = 0; i < num_buckets; i++) {
        bucket_item = json_object_array_get_idx(req->response, i);

        json_object_object_get_ex(bucket_item, "id", &id);
        json_object_object_get_ex(bucket_item, "name", &name);
        json_object_object_get_ex(bucket_item, "created", &created);

        genaro_bucket_meta_t *bucket = &req->buckets[i];
        bucket->id = json_object_get_string(id);
        bucket->decrypted = false;
        bucket->created = json_object_get_string(created);
        bucket->name = NULL;

        // Attempt to decrypt the name, otherwise
        // we will default the name to the encrypted text.
        // The decrypted flag will be set to indicate the status
        // of decryption for alternative display.
        const char *encrypted_name = json_object_get_string(name);
        if (!encrypted_name) {
            continue;
        }
        char *decrypted_name;
        int error_status = decrypt_meta(encrypted_name, key,
                                        &decrypted_name);
        if (!error_status) {
            bucket->decrypted = true;
            bucket->name = decrypted_name;
        } else {
            bucket->decrypted = false;
            bucket->name = strdup(encrypted_name);
        }
    }
}

static void get_bucket_request_worker(uv_work_t *work)
{
    get_bucket_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options, req->encrypt_options,
                                 req->options, req->method, req->path, NULL, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;

    if (!req->response) {
        req->bucket = NULL;
        return;
    }

    // Derive a key based on the master seed
    char *bucket_key_as_str = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    generate_bucket_key(req->encrypt_options->priv_key,
                        req->encrypt_options->key_len,
                        BUCKET_NAME_MAGIC,
                        &bucket_key_as_str);

    uint8_t *bucket_key = str2hex(strlen(bucket_key_as_str), bucket_key_as_str);
    if (!bucket_key) {
        req->error_code = GENARO_MEMORY_ERROR;
        return;
    }

    free(bucket_key_as_str);

    // Get bucket name encryption key with first half of hmac w/ magic
    struct hmac_sha512_ctx ctx1;
    hmac_sha512_set_key(&ctx1, SHA256_DIGEST_SIZE, bucket_key);
    hmac_sha512_update(&ctx1, SHA256_DIGEST_SIZE, BUCKET_META_MAGIC);
    uint8_t key[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&ctx1, SHA256_DIGEST_SIZE, key);

    free(bucket_key);

    struct json_object *name;
    struct json_object *created;
    struct json_object *id;

    json_object_object_get_ex(req->response, "id", &id);
    json_object_object_get_ex(req->response, "name", &name);
    json_object_object_get_ex(req->response, "created", &created);

    req->bucket = malloc(sizeof(genaro_bucket_meta_t));
    req->bucket->id = json_object_get_string(id);
    req->bucket->decrypted = false;
    req->bucket->created = json_object_get_string(created);
    req->bucket->name = NULL;

    // Attempt to decrypt the name, otherwise
    // we will default the name to the encrypted text.
    // The decrypted flag will be set to indicate the status
    // of decryption for alternative display.
    const char *encrypted_name = json_object_get_string(name);
    if (encrypted_name) {
        char *decrypted_name;
        int error_status = decrypt_meta(encrypted_name, key,
                                        &decrypted_name);
        if (!error_status) {
            req->bucket->decrypted = true;
            req->bucket->name = decrypted_name;
        } else {
            req->bucket->decrypted = false;
            req->bucket->name = strdup(encrypted_name);
        }
    }
}

static void list_files_request_worker(uv_work_t *work)
{
    list_files_request_t *req = work->data;
    int status_code = 0;

    req->error_code = fetch_json(req->http_options, req->encrypt_options,
                                 req->options, req->method, req->path, NULL, req->body,
                                 req->auth, &req->response, &status_code);

    req->status_code = status_code;

    int num_files = 0;
    if (req->response != NULL &&
        json_object_is_type(req->response, json_type_array)) {
        num_files = json_object_array_length(req->response);
    }

    if (num_files > 0) {
        req->files = malloc(sizeof(genaro_file_meta_t) * num_files);
        req->total_files = num_files;
    }

    // Get the bucket key to encrypt the filename from bucket id
    char *bucket_key_as_str = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    generate_bucket_key(req->encrypt_options->priv_key,
                        req->encrypt_options->key_len,
                        req->bucket_id,
                        &bucket_key_as_str);

    uint8_t *bucket_key = str2hex(strlen(bucket_key_as_str), bucket_key_as_str);
    if (!bucket_key) {
        req->error_code = GENARO_MEMORY_ERROR;
        return;
    }

    free(bucket_key_as_str);

    // Get file name encryption key with first half of hmac w/ magic
    struct hmac_sha512_ctx ctx1;
    hmac_sha512_set_key(&ctx1, SHA256_DIGEST_SIZE, bucket_key);
    hmac_sha512_update(&ctx1, SHA256_DIGEST_SIZE, BUCKET_META_MAGIC);
    uint8_t key[SHA256_DIGEST_SIZE];
    hmac_sha512_digest(&ctx1, SHA256_DIGEST_SIZE, key);

    free(bucket_key);

    struct json_object *file;
    struct json_object *filename;
    struct json_object *mimetype;
    struct json_object *size;
    struct json_object *id;
    struct json_object *created;

    for (int i = 0; i < num_files; i++) {
        file = json_object_array_get_idx(req->response, i);

        json_object_object_get_ex(file, "filename", &filename);
        json_object_object_get_ex(file, "mimetype", &mimetype);
        json_object_object_get_ex(file, "size", &size);
        json_object_object_get_ex(file, "id", &id);
        json_object_object_get_ex(file, "created", &created);

        genaro_file_meta_t *file = &req->files[i];

        file->created = json_object_get_string(created);
        file->mimetype = json_object_get_string(mimetype);
        file->size = json_object_get_int64(size);
        file->erasure = NULL;
        file->index = NULL;
        file->hmac = NULL; // TODO though this value is not needed here
        file->id = json_object_get_string(id);
        file->decrypted = false;
        file->filename = NULL;

        // Attempt to decrypt the filename, otherwise
        // we will default the filename to the encrypted text.
        // The decrypted flag will be set to indicate the status
        // of decryption for alternative display.
        const char *encrypted_file_name = json_object_get_string(filename);
        if (!encrypted_file_name) {
            continue;
        }
        char *decrypted_file_name;
        int error_status = decrypt_meta(encrypted_file_name, key,
                                        &decrypted_file_name);
        if (!error_status) {
            file->decrypted = true;
            file->filename = decrypted_file_name;
        } else {
            file->decrypted = false;
            file->filename = strdup(encrypted_file_name);
        }
    }
}

static uv_work_t *uv_work_new()
{
    uv_work_t *work = malloc(sizeof(uv_work_t));
    return work;
}

static json_request_t *json_request_new(
    genaro_http_options_t *http_options,
    genaro_encrypt_options_t *encrypt_options,
    genaro_bridge_options_t *options,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{

    json_request_t *req = malloc(sizeof(json_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->encrypt_options = encrypt_options;
    req->options = options;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static list_files_request_t *list_files_request_new(
    genaro_http_options_t *http_options,
    genaro_bridge_options_t *options,
    genaro_encrypt_options_t *encrypt_options,
    const char *bucket_id,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{
    list_files_request_t *req = malloc(sizeof(list_files_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->bucket_id = bucket_id;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->files = NULL;
    req->total_files = 0;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static create_bucket_request_t *create_bucket_request_new(
    genaro_http_options_t *http_options,
    genaro_bridge_options_t *bridge_options,
    genaro_encrypt_options_t *encrypt_options,
    const char *bucket_name,
    void *handle)
{
    create_bucket_request_t *req = malloc(sizeof(create_bucket_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->encrypt_options = encrypt_options;
    req->bridge_options = bridge_options;
    req->bucket_name = bucket_name;
    req->encrypted_bucket_name = NULL;
    req->response = NULL;
    req->bucket = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_buckets_request_t *get_buckets_request_new(
    genaro_http_options_t *http_options,
    genaro_bridge_options_t *options,
    genaro_encrypt_options_t *encrypt_options,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{
    get_buckets_request_t *req = malloc(sizeof(get_buckets_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->buckets = NULL;
    req->total_buckets = 0;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static get_bucket_request_t *get_bucket_request_new(
        genaro_http_options_t *http_options,
        genaro_bridge_options_t *options,
        genaro_encrypt_options_t *encrypt_options,
        char *method,
        char *path,
        struct json_object *request_body,
        bool auth,
        void *handle)
{
    get_bucket_request_t *req = malloc(sizeof(get_bucket_request_t));
    if (!req) {
        return NULL;
    }

    req->http_options = http_options;
    req->options = options;
    req->encrypt_options = encrypt_options;
    req->method = method;
    req->path = path;
    req->auth = auth;
    req->body = request_body;
    req->response = NULL;
    req->bucket = NULL;
    req->error_code = 0;
    req->status_code = 0;
    req->handle = handle;

    return req;
}

static uv_work_t *json_request_work_new(
    genaro_env_t *env,
    char *method,
    char *path,
    struct json_object *request_body,
    bool auth,
    void *handle)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return NULL;
    }
    work->data = json_request_new(env->http_options, env->encrypt_options,
                                  env->bridge_options, method, path,
                                  request_body, auth, handle);

    if (!work->data) {
        return NULL;
    }

    return work;
}

static void default_logger(const char *message,
                           int level,
                           void *handle)
{
    puts(message);
}

static void log_formatter(genaro_log_options_t *options,
                          void *handle,
                          int level,
                          const char *format,
                          va_list args)
{
    va_list args_cpy;
    va_copy(args_cpy, args);
    int length = vsnprintf(0, 0, format, args_cpy);
    va_end(args_cpy);

    if (length > 0) {
        char message[length + 1];
        if (vsnprintf(message, length + 1, format, args)) {
            options->logger(message, level, handle);
        }
    }
}

static void log_formatter_debug(genaro_log_options_t *options, void *handle,
                                const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_formatter(options, handle, 4, format, args);
    va_end(args);
}

static void log_formatter_info(genaro_log_options_t *options, void *handle,
                               const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_formatter(options, handle, 3, format, args);
    va_end(args);
}

static void log_formatter_warn(genaro_log_options_t *options, void *handle,
                               const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_formatter(options, handle, 2, format, args);
    va_end(args);
}

static void log_formatter_error(genaro_log_options_t *options, void *handle,
                                const char *format, ...)
{
    va_list args;
    va_start(args, format);
    log_formatter(options, handle, 1, format, args);
    va_end(args);
}

GENARO_API struct genaro_env *genaro_init_env(genaro_bridge_options_t *options,
                                 genaro_encrypt_options_t *encrypt_options,
                                 genaro_http_options_t *http_options,
                                 genaro_log_options_t *log_options)
{
    curl_global_init(CURL_GLOBAL_ALL);

    uv_loop_t *loop = uv_default_loop();
    if (!loop) {
        return NULL;
    }

    genaro_env_t *env = malloc(sizeof(genaro_env_t));
    if (!env) {
        return NULL;
    }

    // setup the uv event loop
    env->loop = loop;

    // deep copy bridge options
    genaro_bridge_options_t *bo = malloc(sizeof(genaro_bridge_options_t));
    if (!bo) {
        return NULL;
    }

    bo->proto = strdup(options->proto);
    bo->host = strdup(options->host);
    bo->port = options->port;

#ifdef _POSIX_MEMLOCK
    size_t page_size = sysconf(_SC_PAGESIZE);
#elif _WIN32
    SYSTEM_INFO si;
    GetSystemInfo (&si);
    uintptr_t page_size = si.dwPageSize;
#endif

    env->bridge_options = bo;

    // deep copy encryption options
    genaro_encrypt_options_t *eo = malloc(sizeof(genaro_encrypt_options_t));
    if (!eo) {
        return NULL;
    }

    if (encrypt_options && encrypt_options->priv_key) {

        // prevent private key from being swapped unencrypted to disk
#ifdef _POSIX_MEMLOCK
        if (encrypt_options->key_len >= page_size) {
            return NULL;
        }

#ifdef HAVE_ALIGNED_ALLOC
        eo->priv_key = aligned_alloc(page_size, page_size);
#elif HAVE_POSIX_MEMALIGN
        eo->priv_key = NULL;
        if (posix_memalign((void *)&eo->mnemonic, page_size, page_size)) {
            return NULL;
        }
#else
        eo->priv_key = malloc(page_size);
#endif

        if (eo->priv_key == NULL) {
            return NULL;
        }

        memset((char *)eo->priv_key, 0, page_size);
        memcpy((char *)eo->priv_key, encrypt_options->priv_key, encrypt_options->key_len);
        eo->key_len = encrypt_options->key_len;
        if (mlock(eo->priv_key, eo->key_len)) {
            return NULL;
        }
#elif _WIN32
        eo->priv_key = VirtualAlloc(NULL, page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (eo->priv_key == NULL) {
            return NULL;
        }
        memset((char *)eo->priv_key, 0, page_size);
        memcpy((char *)eo->priv_key, encrypt_options->priv_key, encrypt_options->key_len);
        eo->key_len = encrypt_options->key_len;
        if (!VirtualLock((char *)eo->priv_key, eo->key_len)) {
            return NULL;
        }
#else
        memcpy((char *)eo->priv_key, encrypt_options->priv_key, encrypt_options->key_len);
        eo->key_len = encrypt_options->key_len;
#endif
    } else {
        eo->priv_key = NULL;
    }

    env->encrypt_options = eo;

    // Set tmp_path
    struct stat sb;
    env->tmp_path = NULL;
    if (env->tmp_path &&
        stat(env->tmp_path, &sb) == 0 &&
        S_ISDIR(sb.st_mode)) {
        env->tmp_path = strdup(env->tmp_path);
    } else if (getenv("GENARO_TEMP") &&
               stat(getenv("GENARO_TEMP"), &sb) == 0 &&
               S_ISDIR(sb.st_mode)) {
        env->tmp_path = strdup(getenv("GENARO_TEMP"));
#ifdef _WIN32
    } else if (getenv("TEMP") &&
               stat(getenv("TEMP"), &sb) == 0 &&
               S_ISDIR(sb.st_mode)) {
        env->tmp_path = strdup(getenv("TEMP"));
#else
    } else if ("/tmp" && stat("/tmp", &sb) == 0 && S_ISDIR(sb.st_mode)) {
        env->tmp_path = strdup("/tmp");
#endif
    } else {
        env->tmp_path = NULL;
    }

    // deep copy the http options
    genaro_http_options_t *ho = malloc(sizeof(genaro_http_options_t));
    if (!ho) {
        return NULL;
    }
    ho->user_agent = strdup(http_options->user_agent);
    if (http_options->proxy_url) {
        ho->proxy_url = strdup(http_options->proxy_url);
    } else {
        ho->proxy_url = NULL;
    }
    if (http_options->cainfo_path) {
        ho->cainfo_path = strdup(http_options->cainfo_path);
    } else {
        ho->cainfo_path = NULL;
    }
    ho->low_speed_limit = http_options->low_speed_limit;
    ho->low_speed_time = http_options->low_speed_time;
    if (http_options->timeout == 0 ||
        http_options->timeout >= GENARO_HTTP_TIMEOUT) {
        ho->timeout = http_options->timeout;
    } else {
        ho->timeout = GENARO_HTTP_TIMEOUT;
    }

    env->http_options = ho;

    // setup the log options
    env->log_options = log_options;
    if (!env->log_options->logger) {
        env->log_options->logger = default_logger;
    }

    genaro_log_levels_t *log = malloc(sizeof(genaro_log_levels_t));
    if (!log) {
        return NULL;
    }

    log->debug = (genaro_logger_format_fn)noop;
    log->info = (genaro_logger_format_fn)noop;
    log->warn = (genaro_logger_format_fn)noop;
    log->error = (genaro_logger_format_fn)noop;

    switch(log_options->level) {
        case 4:
            log->debug = log_formatter_debug;
        case 3:
            log->info = log_formatter_info;
        case 2:
            log->warn = log_formatter_warn;
        case 1:
            log->error = log_formatter_error;
        case 0:
            break;
    }

    env->log = log;

    return env;
}

GENARO_API int genaro_destroy_env(genaro_env_t *env)
{
    int status = 0;

    // free and destroy all bridge options
    free((char *)env->bridge_options->proto);
    free((char *)env->bridge_options->host);

    free(env->bridge_options);

    // free and destroy all encryption options
    if (env->encrypt_options && env->encrypt_options->priv_key) {
        size_t key_len = env->encrypt_options->key_len;
        // zero out file encryption mnemonic before freeing
        if (key_len > 0) {
            memset_zero((char *)env->encrypt_options->priv_key, key_len);
        }
#ifdef _POSIX_MEMLOCK
        status = munlock(env->encrypt_options->priv_key, key_len);
#elif _WIN32
        if (!VirtualUnlock((char *)env->encrypt_options->priv_key, key_len)) {
            status = 1;
        }
#endif

#ifdef _WIN32
        VirtualFree((char *)env->bridge_options, key_len, MEM_RELEASE);
#else
        free((char *)env->encrypt_options->priv_key);
#endif
    }

    if (env->tmp_path) {
        free((char *)env->tmp_path);
    }

    free(env->encrypt_options);

    // free all http options
    free((char *)env->http_options->user_agent);
    if (env->http_options->proxy_url) {
        free((char *)env->http_options->proxy_url);
    }
    if (env->http_options->cainfo_path) {
        free((char *)env->http_options->cainfo_path);
    }
    free(env->http_options);

    // free the log levels
    free(env->log);

    // free the environment
    free(env);

    curl_global_cleanup();

    return status;
}

GENARO_API int genaro_encrypt_auth(const char *passphrase,
                       const char *salt,
                       const char *text,
                       char **buffer)
{
    char *encrypted = NULL;

    if (encrypt_data(passphrase, salt, text, &encrypted)) {
        if (encrypted) {
            free(encrypted);
        }
        return 1;
    }

    *buffer = encrypted;
    return 0;
}

GENARO_API int genaro_encrypt_write_auth(const char *filepath, char *passphrase, json_object *key_json_obj)
{
    FILE *fp;
    fp = fopen(filepath, "w");
    if (fp == NULL) {
        return 1;
    }

    char *buffer = NULL;
    const char *key_json_str = json_object_to_json_string(key_json_obj);
    if (genaro_encrypt_auth(passphrase, passphrase, key_json_str, &buffer)) {
        fclose(fp);
        return 1;
    }

    fwrite(buffer, strlen(buffer), sizeof(char), fp);
    fwrite("\n", 1, sizeof(char), fp);

    free(buffer);
    fclose(fp);

    return 0;
}

GENARO_API int genaro_decrypt_auth(const char *buffer,
                       const char *passphrase,
                       json_object **key_json_obj)
{
    int status = 0;
    char *decrypted = NULL;

    // TODO: "salt" is temporary
    if (decrypt_data(passphrase, passphrase, buffer, &decrypted)) {
        status = 1;
        goto clean;
    }

    *key_json_obj = json_tokener_parse(decrypted);
    if (*key_json_obj == NULL) {
        status = 1;
        goto clean;
    }
clean:
    if (decrypted) {
        free(decrypted);
    }
    return status;
}

/**
 *
 * @param filepath
 * @param passphrase
 * @param key_json_obj
 * @return 0: success, 1: fail
 */
GENARO_API int genaro_decrypt_read_auth(const char *filepath,
                                        const char *passphrase,
                                        json_object **key_json_obj)
{
    FILE *fp;
    fp = fopen(filepath, "r");
    if (fp == NULL) {
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    size_t fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = calloc(fsize + 1, sizeof(char));
    if (buffer == NULL) {
        return 1;
    }

    size_t read_blocks = 0;
    while ((!feof(fp)) && (!ferror(fp))) {
        read_blocks = fread(buffer + read_blocks, 1, fsize, fp);
        if (read_blocks <= 0) {
            break;
        }
    }

    int error = ferror(fp);
    fclose(fp);

    if (error) {
        return error;
    }

    int status = genaro_decrypt_auth(buffer, passphrase, key_json_obj);

    free(buffer);

    return status;

}

GENARO_API uint64_t genaro_util_timestamp()
{
    return get_time_milliseconds();
}

GENARO_API int genaro_mnemonic_generate(int strength, char **buffer)
{
    return mnemonic_generate(strength, buffer);
}

GENARO_API bool genaro_mnemonic_check(const char *mnemonic)
{
    return mnemonic_check(mnemonic);
}

GENARO_API char *genaro_strerror(int error_code)
{
    switch(error_code) {
        case GENARO_BRIDGE_REQUEST_ERROR:
            return "Bridge request error";
        case GENARO_BRIDGE_AUTH_ERROR:
            return "Bridge request authorization error";
        case GENARO_BRIDGE_TOKEN_ERROR:
            return "Bridge request token error";
        case GENARO_BRIDGE_POINTER_ERROR:
            return "Bridge request pointer error";
        case GENARO_BRIDGE_REPOINTER_ERROR:
            return "Bridge request replace pointer error";
        case GENARO_BRIDGE_TIMEOUT_ERROR:
            return "Bridge request timeout error";
        case GENARO_BRIDGE_INTERNAL_ERROR:
            return "Bridge request internal error";
        case GENARO_BRIDGE_RATE_ERROR:
            return "Bridge rate limit error";
        case GENARO_BRIDGE_BUCKET_NOTFOUND_ERROR:
            return "Bucket is not found";
        case GENARO_BRIDGE_FILE_NOTFOUND_ERROR:
            return "File is not found";
        case GENARO_BRIDGE_BUCKET_FILE_EXISTS:
            return "File already exists";
        case GENARO_BRIDGE_OFFER_ERROR:
            return "Unable to receive storage offer";
        case GENARO_BRIDGE_JSON_ERROR:
            return "Unexpected JSON response";
        case GENARO_BRIDGE_FILEINFO_ERROR:
            return "Bridge file info error";
        case GENARO_FARMER_REQUEST_ERROR:
            return "Farmer request error";
        case GENARO_FARMER_EXHAUSTED_ERROR:
            return "Farmer exhausted error";
        case GENARO_FARMER_TIMEOUT_ERROR:
            return "Farmer request timeout error";
        case GENARO_FARMER_AUTH_ERROR:
            return "Farmer request authorization error";
        case GENARO_FARMER_INTEGRITY_ERROR:
            return "Farmer request integrity error";
        case GENARO_FILE_INTEGRITY_ERROR:
            return "File integrity error";
        case GENARO_FILE_READ_ERROR:
            return "File read error";
        case GENARO_FILE_WRITE_ERROR:
            return "File write error";
        case GENARO_BRIDGE_FRAME_ERROR:
            return "Bridge frame request error";
        case GENARO_FILE_ENCRYPTION_ERROR:
            return "File encryption error";
        case GENARO_FILE_SIZE_ERROR:
            return "File size error";
        case GENARO_FILE_DECRYPTION_ERROR:
            return "File decryption error";
        case GENARO_FILE_GENERATE_HMAC_ERROR:
            return "File hmac generation error";
        case GENARO_FILE_SHARD_MISSING_ERROR:
            return "File missing shard error";
        case GENARO_FILE_RECOVER_ERROR:
            return "File recover error";
        case GENARO_FILE_RESIZE_ERROR:
            return "File resize error";
        case GENARO_FILE_UNSUPPORTED_ERASURE:
            return "File unsupported erasure code error";
        case GENARO_FILE_PARITY_ERROR:
            return "File create parity error";
        case GENARO_META_ENCRYPTION_ERROR:
            return "Meta encryption error";
        case GENARO_META_DECRYPTION_ERROR:
            return "Meta decryption error";
        case GENARO_TRANSFER_CANCELED:
            return "File transfer canceled";
        case GENARO_MEMORY_ERROR:
            return "Memory error";
        case GENARO_MAPPING_ERROR:
            return "Memory mapped file error";
        case GENARO_UNMAPPING_ERROR:
            return "Memory mapped file unmap error";
        case GENARO_QUEUE_ERROR:
            return "Queue error";
        case GENARO_HEX_DECODE_ERROR:
            return "Unable to decode hex string";
        case GENARO_TRANSFER_OK:
            return "No errors";
        default:
            return "Unknown error";
    }
}

GENARO_API int genaro_bridge_get_info(genaro_env_t *env, void *handle, uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env,"GET", "/", NULL,
                                            false, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_get_buckets(genaro_env_t *env, void *handle, uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }
    work->data = get_buckets_request_new(env->http_options,
                                         env->bridge_options,
                                         env->encrypt_options,
                                         "GET", "/buckets",
                                         NULL, true, handle);
    if (!work->data) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work,
                         get_buckets_request_worker, cb);
}

GENARO_API void genaro_free_get_buckets_request(get_buckets_request_t *req)
{
    json_object_put(req->response);
    if (req->buckets && req->total_buckets > 0) {
        for (int i = 0; i < req->total_buckets; i++) {
            free((char *)req->buckets[i].name);
        }
    }
    free(req->buckets);
    free(req);
}

GENARO_API int genaro_bridge_create_bucket(genaro_env_t *env,
                               const char *name,
                               void *handle,
                               uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    work->data = create_bucket_request_new(env->http_options,
                                           env->bridge_options,
                                           env->encrypt_options,
                                           name,
                                           handle);
    if (!work->data) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work,
                         create_bucket_request_worker, cb);
}

GENARO_API int genaro_bridge_delete_bucket(genaro_env_t *env,
                               const char *id,
                               void *handle,
                               uv_after_work_cb cb)
{
    char *path = str_concat_many(2, "/buckets/", id);
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "DELETE", path,
                                            NULL, true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_get_bucket(genaro_env_t *env,
                                      const char *id,
                                      void *handle,
                                      uv_after_work_cb cb)
{
    uv_work_t *work = uv_work_new();
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    char *path = str_concat_many(2, "/buckets/", id);
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    work->data = get_bucket_request_new(env->http_options,
                                        env->bridge_options,
                                        env->encrypt_options,
                                        "GET", path,
                                        NULL, true, handle);
    if (!work->data) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, get_bucket_request_worker, cb);
}

GENARO_API void genaro_free_get_bucket_request(get_bucket_request_t *req)
{
    json_object_put(req->response);
    free(req->path);
    if (req->bucket) {
        free((char *)req->bucket->name);
    }
    free(req->bucket);
    free(req);
}

GENARO_API int genaro_bridge_list_files(genaro_env_t *env,
                            const char *id,
                            void *handle,
                            uv_after_work_cb cb)
{
    char *path = str_concat_many(3, "/buckets/", id, "/files");
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = uv_work_new();
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }
    work->data = list_files_request_new(env->http_options,
                                        env->bridge_options,
                                        env->encrypt_options,
                                        id, "GET", path,
                                        NULL, true, handle);

    if (!work->data) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work,
                         list_files_request_worker, cb);
}

GENARO_API void genaro_free_list_files_request(list_files_request_t *req)
{
    json_object_put(req->response);
    free(req->path);
    if (req->files && req->total_files > 0) {
        for (int i = 0; i < req->total_files; i++) {
            free((char *)req->files[i].filename);
        }
    }
    free(req->files);
    free(req);
}

GENARO_API int genaro_bridge_create_bucket_token(genaro_env_t *env,
                                     const char *bucket_id,
                                     genaro_bucket_op_t operation,
                                     void *handle,
                                     uv_after_work_cb cb)
{
    struct json_object *body = json_object_new_object();
    json_object *op_string = json_object_new_string(BUCKET_OP[operation]);

    json_object_object_add(body, "operation", op_string);

    char *path = str_concat_many(3, "/buckets/", bucket_id, "/tokens");
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "POST", path, body,
                                            true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_get_file_pointers(genaro_env_t *env,
                                   const char *bucket_id,
                                   const char *file_id,
                                   void *handle,
                                   uv_after_work_cb cb)
{
    char *path = str_concat_many(4, "/buckets/", bucket_id, "/files/", file_id);
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_delete_file(genaro_env_t *env,
                             const char *bucket_id,
                             const char *file_id,
                             void *handle,
                             uv_after_work_cb cb)
{
    char *path = str_concat_many(4, "/buckets/", bucket_id, "/files/", file_id);
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "DELETE", path, NULL,
                                            true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_create_frame(genaro_env_t *env,
                              void *handle,
                              uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env, "POST", "/frames", NULL,
                                            true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_get_frames(genaro_env_t *env,
                            void *handle,
                            uv_after_work_cb cb)
{
    uv_work_t *work = json_request_work_new(env, "GET", "/frames", NULL,
                                            true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_get_frame(genaro_env_t *env,
                           const char *frame_id,
                           void *handle,
                           uv_after_work_cb cb)
{
    char *path = str_concat_many(2, "/frames/", frame_id);
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);

}

GENARO_API int genaro_bridge_delete_frame(genaro_env_t *env,
                              const char *frame_id,
                              void *handle,
                              uv_after_work_cb cb)
{
    char *path = str_concat_many(2, "/frames/", frame_id);
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "DELETE", path, NULL,
                                            true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_get_file_info(genaro_env_t *env,
                               const char *bucket_id,
                               const char *file_id,
                               void *handle,
                               uv_after_work_cb cb)
{
    char *path = str_concat_many(5, "/buckets/", bucket_id, "/files/",
                                 file_id, "/info");
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                            true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_list_mirrors(genaro_env_t *env,
                              const char *bucket_id,
                              const char *file_id,
                              void *handle,
                              uv_after_work_cb cb)
{
    char *path = str_concat_many(5, "/buckets/", bucket_id, "/files/",
                                 file_id, "/mirrors");
    if (!path) {
        return GENARO_MEMORY_ERROR;
    }

    uv_work_t *work = json_request_work_new(env, "GET", path, NULL,
                                           true, handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }

    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}

GENARO_API int genaro_bridge_register(genaro_env_t *env,
                          const char *email,
                          const char *password,
                          void *handle,
                          uv_after_work_cb cb)
{
    uint8_t sha256_digest[SHA256_DIGEST_SIZE];
    sha256_of_str((uint8_t *)password, strlen(password), sha256_digest);

    char *hex_str = hex2str(SHA256_DIGEST_SIZE, sha256_digest);
    if (!hex_str) {
        return GENARO_MEMORY_ERROR;
    }

    struct json_object *body = json_object_new_object();
    json_object *email_str = json_object_new_string(email);
    json_object *pass_str = json_object_new_string(hex_str);
    free(hex_str);
    json_object_object_add(body, "email", email_str);
    json_object_object_add(body, "password", pass_str);

    uv_work_t *work = json_request_work_new(env, "POST", "/users", body, true,
                                            handle);
    if (!work) {
        return GENARO_MEMORY_ERROR;
    }
    return uv_queue_work(env->loop, (uv_work_t*) work, json_request_worker, cb);
}
