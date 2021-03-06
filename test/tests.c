#include "genarotests.h"

char *folder;
int tests_ran = 0;
int test_status = 0;

// setup bridge options to point to mock server
genaro_bridge_options_t bridge_options = {
    .proto = "http",
    .host  = "localhost",
    .port  = 8091,
};

// setup bridge options to point to mock server (with incorrect auth)
genaro_bridge_options_t bridge_options_bad = {
    .proto = "http",
    .host  = "localhost",
    .port  = 8091,
};

genaro_encrypt_options_t encrypt_options = {
    .priv_key = (uint8_t *)"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    .key_len = 93
};

genaro_http_options_t http_options = {
    .user_agent = "genaro-test",
    .low_speed_limit = 0,
    .low_speed_time = 0,
    .timeout = 0
};

genaro_log_options_t log_options = {
    .level = 0
};

void fail(char *msg)
{
    printf("\t" KRED "FAIL" RESET " %s\n", msg);
    tests_ran += 1;
}

void pass(char *msg)
{
    printf("\t" KGRN "PASS" RESET " %s\n", msg);
    test_status += 1;
    tests_ran += 1;
}

void check_bridge_get_info(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);

    struct json_object* value;
    int success = json_object_object_get_ex(req->response, "info", &value);
    assert(success == 1);
    pass("genaro_bridge_get_info");

    json_object_put(req->response);
    free(req);
    free(work_req);
}

void check_get_buckets(uv_work_t *work_req, int status)
{
    assert(status == 0);
    get_buckets_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(json_object_is_type(req->response, json_type_array) == 1);

    struct json_object *bucket = json_object_array_get_idx(req->response, 0);
    struct json_object* value;
    int success = json_object_object_get_ex(bucket, "id", &value);
    assert(success == 1);
    pass("genaro_bridge_get_buckets");

    genaro_free_get_buckets_request(req);
    free(work_req);
}

void check_get_bucket(uv_work_t *work_req, int status)
{
    assert(status == 0);
    get_bucket_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->bucket);
    assert(strcmp(req->bucket->name, "test") == 0);
    assert(req->bucket->decrypted);

    pass("genaro_bridge_get_bucket");

    genaro_free_get_bucket_request(req);
    free(work_req);
}

void check_get_buckets_badauth(uv_work_t *work_req, int status)
{
    assert(status == 0);
    get_buckets_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->buckets == NULL);
    assert(req->status_code == 401);

    pass("genaro_bridge_get_buckets_badauth");

    genaro_free_get_buckets_request(req);
    free(work_req);
}

void check_create_bucket(uv_work_t *work_req, int status)
{
    assert(status == 0);
    create_bucket_request_t *req = work_req->data;
    assert(req->handle == NULL);

    struct json_object* value;
    int success = json_object_object_get_ex(req->response, "name", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* name = json_object_get_string(value);
    assert(strcmp(name, "backups") == 0);
    pass("genaro_bridge_create_bucket");

    json_object_put(req->response);
    free((void *)req->encrypted_bucket_name);
    free(req->bucket);
    free(req);
    free(work_req);
}

void check_delete_bucket(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->response == NULL);
    assert(req->status_code == 204);

    pass("genaro_bridge_delete_bucket");

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

void check_list_files(uv_work_t *work_req, int status)
{
    assert(status == 0);
    list_files_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->response != NULL);

    struct json_object *file = json_object_array_get_idx(req->response, 0);
    struct json_object *value;
    int success = json_object_object_get_ex(file, "id", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* id = json_object_get_string(value);
    assert(strcmp(id, "f18b5ca437b1ca3daa14969f") == 0);

    pass("genaro_bridge_list_files");

    genaro_free_list_files_request(req);
    free(work_req);
}

void check_list_files_badauth(uv_work_t *work_req, int status)
{
    assert(status == 0);
    list_files_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->response == NULL);
    assert(req->files == NULL);
    assert(req->status_code == 401);

    pass("genaro_bridge_list_files_badauth");

    genaro_free_list_files_request(req);
    free(work_req);
}

void check_bucket_tokens(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "token", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* token = json_object_get_string(value);

    char *t = "a264e12611ad93b1777e82065f86cfcf088967dba2f15559cea5e140d5339a0e";

    assert(strcmp(token, t) == 0);

    pass("genaro_bridge_create_bucket_token");

    json_object_put(req->body);
    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

void check_file_pointers(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->response);

    assert(json_object_is_type(req->response, json_type_array) == 1);

    struct json_object *bucket = json_object_array_get_idx(req->response, 0);
    struct json_object* value;
    int success = json_object_object_get_ex(bucket, "farmer", &value);
    assert(success == 1);

    pass("genaro_bridge_get_file_pointers");

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

void check_resolve_file_progress(double progress,
                                 uint64_t file_bytes,
                                 void *handle)
{
    assert(handle == NULL);
    if (progress == (double)1) {
        pass("genaro_bridge_resolve_file (progress finished)");
    }

    // TODO check error case
}

void check_resolve_file(int status, const char *file_name, const char *temp_file_name, FILE *fd, uint64_t total_bytes, char *sha256, void *handle)
{
    fclose(fd);
    assert(handle == NULL);
    if (status) {
        fail("genaro_bridge_resolve_file");
        printf("Download failed: %s\n", genaro_strerror(status));
    } else {
        pass("genaro_bridge_resolve_file");
    }
}

void check_resolve_file_cancel(int status, const char *file_name, const char *temp_file_name, FILE *fd, uint64_t total_bytes, char *sha256, void *handle)
{
    fclose(fd);
    assert(handle == NULL);
    if (status == GENARO_TRANSFER_CANCELED) {
        pass("genaro_bridge_resolve_file_cancel");
    } else {
        fail("genaro_bridge_resolve_file_cancel");
    }
}

void check_store_file_progress(double progress,
                               uint64_t file_bytes,
                               void *handle)
{
    assert(handle == NULL);
    if (progress == (double)1) {
        pass("genaro_bridge_store_file (progress finished)");
    }
}

void check_store_file(const char *bucket_id, const char *file_name, int status, char *file_id, uint64_t total_bytes, char *sha256, void *handle)
{
    assert(handle == NULL);
    if (status == 0) {
        if (strcmp(file_id, "85fb0ed00de1196dc22e0f6d") == 0 ) {
            pass("genaro_bridge_store_file");
        } else {
            fail("genaro_bridge_store_file(0)");
        }
    } else {
        fail("genaro_bridge_store_file(1)");
        printf("\t\tERROR:   %s\n", genaro_strerror(status));
    }

    free(file_id);
}

void check_store_file_cancel(const char *bucket_id, const char *file_name, int status, char *file_id, uint64_t total_bytes, char *sha256, void *handle)
{
    assert(handle == NULL);
    if (status == GENARO_TRANSFER_CANCELED) {
        pass("genaro_bridge_store_file_cancel");
    } else {
        fail("genaro_bridge_store_file_cancel");
        printf("\t\tERROR:   %s\n", genaro_strerror(status));
    }

    free(file_id);
}

void check_delete_file(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->response == NULL);
    assert(req->status_code == 200);

    pass("genaro_bridge_delete_file");

    free(req->path);
    free(req);
    free(work_req);
}

void check_create_frame(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "id", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* id = json_object_get_string(value);

    assert(strcmp(id, "d6367831f7f1b117ffdd0015") == 0);
    pass("genaro_bridge_create_frame");

    json_object_put(req->response);
    free(req);
    free(work_req);
}

void check_get_frames(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);

    struct json_object *file = json_object_array_get_idx(req->response, 0);
    struct json_object *value;
    int success = json_object_object_get_ex(file, "id", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* id = json_object_get_string(value);
    assert(strcmp(id, "52b8cc8dfd47bb057d8c8a17") == 0);

    pass("genaro_bridge_get_frames");

    json_object_put(req->response);
    free(req);
    free(work_req);
}

void check_get_frame(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "id", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* id = json_object_get_string(value);

    assert(strcmp(id, "192f90792f42875a7533340b") == 0);
    pass("genaro_bridge_get_frame");

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

void check_delete_frame(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->response == NULL);
    assert(req->status_code == 200);

    pass("genaro_bridge_delete_frame");

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

void check_file_info(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "mimetype", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char* mimetype = json_object_get_string(value);

    assert(strcmp(mimetype, "video/ogg") == 0);
    pass("genaro_bridge_get_file_info");

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

void check_list_mirrors(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);

    assert(json_object_is_type(req->response, json_type_array) == 1);
    struct json_object *firstShard = json_object_array_get_idx(req->response,
                                                               0);
    struct json_object *established;
    struct json_object *available;
    json_object_object_get_ex(firstShard, "established", &established);
    json_object_object_get_ex(firstShard, "available", &available);
    assert(json_object_is_type(established, json_type_array) == 1);
    assert(json_object_is_type(established, json_type_array) == 1);

    pass("genaro_bridge_list_mirrors");

    json_object_put(req->response);
    free(req->path);
    free(req);
    free(work_req);
}

void check_register(uv_work_t *work_req, int status)
{
    assert(status == 0);
    json_request_t *req = work_req->data;
    assert(req->handle == NULL);
    assert(req->status_code == 201);

    struct json_object *value;
    int success = json_object_object_get_ex(req->response, "email", &value);
    assert(success == 1);
    assert(json_object_is_type(value, json_type_string) == 1);

    const char *email = json_object_get_string(value);

    assert(strcmp(email, "test@test.com") == 0);
    pass("genaro_bridge_register");

    json_object_put(req->body);
    json_object_put(req->response);
    free(req);
    free(work_req);
}

int create_test_upload_file(char *filepath)
{
    FILE *fp;
    fp = fopen(filepath, "wb+");

    if (fp == NULL) {
        printf(KRED "Could not create upload file: %s\n" RESET, filepath);
        exit(0);
    }

    int shard_size = 16777216;
    char *bytes = "abcdefghijklmn";
    for (int i = 0; i < strlen(bytes); i++) {
        char *page = calloc(shard_size + 1, sizeof(char));
        memset(page, bytes[i], shard_size);
        fputs(page, fp);
        free(page);
    }

    fclose(fp);
    return 0;
}

int test_upload()
{
    // initialize event loop and environment
    genaro_env_t *env = genaro_init_env(&bridge_options,
                                      &encrypt_options,
                                      &http_options,
                                      &log_options,
                                      false);
    assert(env != NULL);

    char *file_name = "genaro-test-upload.data";
    int len = strlen(folder) + 1 + strlen(file_name);
    char *file = calloc(len + 1, sizeof(char));
    strcpy(file, folder);
    strcat(file, "/");
    strcat(file, file_name);
    file[len] = '\0';

    create_test_upload_file(file);

    const char *index = "d2891da46d9c3bf42ad619ceddc1b6621f83e6cb74e6b6b6bc96bdbfaefb8692";
    const char *bucket_id = "368be0816766b28fd5f43af5";

    // upload file
    genaro_upload_opts_t upload_opts = {\
        .bucket_id = bucket_id,
        .file_name = file_name,
        .fd = fopen(file, "rb"),
        .rs = true
    };

    genaro_encryption_info_t *encryption_info = genaro_generate_encryption_info(env, index, bucket_id);
    genaro_key_ctr_as_str_t *rsa_key_ctr_as_str = NULL;
    genaro_upload_state_t *state = genaro_bridge_store_file(env,
                                                          &upload_opts,
                                                          encryption_info->index,
                                                          encryption_info->key_ctr_as_str,
                                                          rsa_key_ctr_as_str,
                                                          NULL,
                                                          check_store_file_progress,
                                                          check_store_file);
    if (!state || state->error_status != 0) {
        return 1;
    }

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        return 1;
    }

    free(file);
    genaro_destroy_env(env);

    return 0;
}

int test_upload_cancel()
{

    // initialize event loop and environment
    genaro_env_t *env = genaro_init_env(&bridge_options,
                                      &encrypt_options,
                                      &http_options,
                                      &log_options,
                                      false);
    assert(env != NULL);

    char *file_name = "genaro-test-upload.data";
    int len = strlen(folder) + 1 + strlen(file_name);
    char *file = calloc(len + 1, sizeof(char));
    strcpy(file, folder);
    strcat(file, "/");
    strcat(file, file_name);
    file[len] = '\0';

    create_test_upload_file(file);

    const char *index = "d2891da46d9c3bf42ad619ceddc1b6621f83e6cb74e6b6b6bc96bdbfaefb8692";
    const char *bucket_id = "368be0816766b28fd5f43af5";
    // upload file
    genaro_upload_opts_t upload_opts = {
        .bucket_id = bucket_id,
        .file_name = file_name,
        .fd = fopen(file, "rb")
    };

    genaro_encryption_info_t *encryption_info = genaro_generate_encryption_info(env, index, bucket_id);
    genaro_key_ctr_as_str_t *rsa_key_ctr_as_str = NULL;
    genaro_upload_state_t *state = genaro_bridge_store_file(env,
                                                          &upload_opts,
                                                          encryption_info->index,
                                                          encryption_info->key_ctr_as_str,
                                                          rsa_key_ctr_as_str,
                                                          NULL,
                                                          check_store_file_progress,
                                                          check_store_file_cancel);
    if (!state || state->error_status != 0) {
        return 1;
    }

    // process the loop one at a time so that we can do other things while
    // the loop is processing, such as cancel the download
    int count = 0;
    bool more;
    int status = 0;
    do {
        more = uv_run(env->loop, UV_RUN_ONCE);
        if (more == false) {
            more = uv_loop_alive(env->loop);
            if (uv_run(env->loop, UV_RUN_NOWAIT) != 0) {
                more = true;
            }
        }

        count++;

        if (count == 100) {
            status = genaro_bridge_store_file_cancel(state);
            assert(status == 0);
        }

    } while (more == true);

    free(file);
    genaro_destroy_env(env);

    return 0;
}

int test_download()
{

    // initialize event loop and environment
    genaro_env_t *env = genaro_init_env(&bridge_options,
                                      &encrypt_options,
                                      &http_options,
                                      &log_options,
                                      false);
    assert(env != NULL);

    // resolve file
    char *download_file = calloc(strlen(folder) + 24 + 1, sizeof(char));
    strcpy(download_file, folder);
    strcat(download_file, "genaro-test-download.data");

    char *renamed_file = calloc(strlen(download_file) + 10 + 1, sizeof(char));
    strcpy(renamed_file, download_file);
    strcat(renamed_file, ".genarotmp");

    FILE *renamed_fp = fopen(renamed_file, "wb+");

    char *bucket_id = "368be0816766b28fd5f43af5";
    char *file_id = "998960317b6725a3f8080c2b";

    genaro_download_state_t *state = genaro_bridge_resolve_file(env,
                                                              bucket_id,
                                                              file_id,
                                                              NULL,
                                                              download_file,
                                                              renamed_file,
                                                              renamed_fp,
                                                              true,
                                                              NULL,
                                                              check_resolve_file_progress,
                                                              check_resolve_file);

    if (!state || state->error_status != 0) {
        return 1;
    }

    free(download_file);

    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        return 1;
    }

    genaro_destroy_env(env);

    return 0;
}

int test_download_cancel()
{
    // initialize event loop and environment
    genaro_env_t *env = genaro_init_env(&bridge_options,
                                      &encrypt_options,
                                      &http_options,
                                      &log_options,
                                      false);
    assert(env != NULL);

    // resolve file
    char *download_file = calloc(strlen(folder) + 33 + 1, sizeof(char));
    strcpy(download_file, folder);
    strcat(download_file, "genaro-test-download-canceled.data");

    char *renamed_file = calloc(strlen(download_file) + 10 + 1, sizeof(char));
    strcpy(renamed_file, download_file);
    strcat(renamed_file, ".genarotmp");

    FILE *renamed_fp = fopen(renamed_file, "wb+");

    char *bucket_id = "368be0816766b28fd5f43af5";
    char *file_id = "998960317b6725a3f8080c2b";

    genaro_download_state_t *state = genaro_bridge_resolve_file(env,
                                                              bucket_id,
                                                              file_id,
                                                              NULL,
                                                              download_file,
                                                              renamed_file,
                                                              renamed_fp,
                                                              true,
                                                              NULL,
                                                              check_resolve_file_progress,
                                                              check_resolve_file_cancel);

    if (!state || state->error_status != 0) {
        return 1;
    }

    // process the loop one at a time so that we can do other things while
    // the loop is processing, such as cancel the download
    int count = 0;
    bool more;
    int status = 0;
    do {
        more = uv_run(env->loop, UV_RUN_ONCE);
        if (more == false) {
            more = uv_loop_alive(env->loop);
            if (uv_run(env->loop, UV_RUN_NOWAIT) != 0) {
                more = true;
            }
        }

        count++;

        if (count == 100) {
            status = genaro_bridge_resolve_file_cancel(state);
            assert(status == 0);
        }

    } while (more == true);

    free(download_file);
    genaro_destroy_env(env);

    return 0;
}

int test_api_badauth()
{
    // initialize event loop and environment
    genaro_env_t *env = genaro_init_env(&bridge_options_bad,
                                      &encrypt_options,
                                      &http_options,
                                      &log_options,
                                      false);

    assert(env != NULL);

    int status = 0;

    // get buckets
    status = genaro_bridge_get_buckets(env, NULL, check_get_buckets_badauth);
    assert(status == 0);

    char *bucket_id = "368be0816766b28fd5f43af5";

    // list files in a bucket
    status = genaro_bridge_list_files(env, bucket_id, NULL,
                                     check_list_files_badauth);
    assert(status == 0);

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        return 1;
    }

    genaro_destroy_env(env);

    return 0;
}

int test_api()
{
    // initialize event loop and environment
    genaro_env_t *env = genaro_init_env(&bridge_options,
                                      &encrypt_options,
                                      &http_options,
                                      &log_options,
                                      false);

    assert(env != NULL);

    int status;

    // get general api info
    status = genaro_bridge_get_info(env, NULL, check_bridge_get_info);
    assert(status == 0);

    // get buckets
    status = genaro_bridge_get_buckets(env, NULL, check_get_buckets);
    assert(status == 0);

    char *bucket_id = "368be0816766b28fd5f43af5";

    // get bucket
    status = genaro_bridge_get_bucket(env, bucket_id, NULL, check_get_bucket);
    assert(status == 0);

    // create a new bucket with a name
    status = genaro_bridge_create_bucket(env, "backups", NULL,
                                        check_create_bucket);
    assert(status == 0);

    // delete a bucket
    // TODO check for successful status code, response has object
    status = genaro_bridge_delete_bucket(env, bucket_id, NULL,
                                        check_delete_bucket);
    assert(status == 0);

    // list files in a bucket
    status = genaro_bridge_list_files(env, bucket_id, NULL,
                                     check_list_files);
    assert(status == 0);

    // create bucket tokens
    status = genaro_bridge_create_bucket_token(env,
                                              bucket_id,
                                              BUCKET_PUSH,
                                              NULL,
                                              check_bucket_tokens);
    assert(status == 0);

    char *file_id = "998960317b6725a3f8080c2b";

    // delete a file in a bucket
    status = genaro_bridge_delete_file(env,
                                      bucket_id,
                                      file_id,
                                      NULL,
                                      check_delete_file);
    assert(status == 0);

    // create a file frame
    status = genaro_bridge_create_frame(env, NULL, check_create_frame);
    assert(status == 0);

    // get frames
    status = genaro_bridge_get_frames(env, NULL, check_get_frames);
    assert(status == 0);

    char *frame_id = "d4af71ab00e15b0c1a7b6ab2";

    // get frame
    status = genaro_bridge_get_frame(env, frame_id, NULL, check_get_frame);
    assert(status == 0);

    // delete frame
    status = genaro_bridge_delete_frame(env, frame_id, NULL, check_delete_frame);
    assert(status == 0);

    // get file information
    status = genaro_bridge_get_file_info(env, bucket_id,
                                        file_id, NULL, check_file_info);
    assert(status == 0);

    // get file pointers
    status = genaro_bridge_get_file_pointers(env, bucket_id,
                                            file_id, NULL, check_file_pointers);
    assert(status == 0);

    // get mirrors
    status = genaro_bridge_list_mirrors(env, bucket_id, file_id, NULL,
                                       check_list_mirrors);
    assert(status == 0);

    /*
    // register a user
    status = genaro_bridge_register(env, "testuser@test.com", "asdf", NULL,
                                   check_register);
    assert(status == 0);
    */

    // run all queued events
    if (uv_run(env->loop, UV_RUN_DEFAULT)) {
        return 1;
    }

    genaro_destroy_env(env);

    return 0;
}

/*
int test_mnemonic_check()
{
    static const char *vectors_ok[] = {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "legal winner thank year wave sausage worth useful legal winner thank yellow",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "jelly better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "renew stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "afford alter spike radar gate glance object seek swamp infant panel yellow",
        "indicate race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "clutch control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "turtle front uncle idea crush write shrug there lottery flower risk shell",
        "kiss carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "exile ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "board flee heavy tunnel powder denial science ski answer betray cargo cat",
        "board blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "beyond stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        0,
    };
    static const char *vectors_fail[] = {
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "above winner thank year wave sausage worth useful legal winner thank yellow",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "above abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "above winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "above advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "above zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "above better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "above stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "above pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "above alter spike radar gate glance object seek swamp infant panel yellow",
        "above race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "above control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "above front uncle idea crush write shrug there lottery flower risk shell",
        "above carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "above ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "above flee heavy tunnel powder denial science ski answer betray cargo cat",
        "above blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "above stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "winner thank year wave sausage worth useful legal winner thank yellow",
        "advice cage absurd amount doctor acoustic avoid letter advice cage above",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
        "winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
        "advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "better achieve collect unaware mountain thought cargo oxygen act hood bridge",
        "stay biology evidence goat welcome casual join adapt armor shuffle fault little machine walk stumble urge swap",
        "pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic",
        "alter spike radar gate glance object seek swamp infant panel yellow",
        "race push merry suffer human cruise dwarf pole review arch keep canvas theme poem divorce alter left",
        "control vehicle tonight unusual clog visa ice plunge glimpse recipe series open hour vintage deposit universe tip job dress radar refuse motion taste",
        "front uncle idea crush write shrug there lottery flower risk shell",
        "carry display unusual confirm curtain upgrade antique rotate hello void custom frequent obey nut hole price segment",
        "ask congress lamp submit jacket era scheme attend cousin alcohol catch course end lucky hurt sentence oven short ball bird grab wing top",
        "flee heavy tunnel powder denial science ski answer betray cargo cat",
        "blade invite damage undo sun mimic interest slam gaze truly inherit resist great inject rocket museum chief",
        "stage sleep clip because twist token leaf atom beauty genius food business side grid unable middle armed observe pair crouch tonight away coconut",
        0,
    };

    const char **m;
    int r;
    int r2;
    m = vectors_ok;
    while (*m) {
        r = mnemonic_check(*m);
        r2 = genaro_mnemonic_check(*m);
        assert(r == 1);
        assert(r2 == 1);
        m++;
    }
    m = vectors_fail;
    while (*m) {
        r = mnemonic_check(*m);
        r2 = mnemonic_check(*m);
        assert(r == 0);
        assert(r2 == 0);
        m++;
    }

    pass("mnemonic_check");

    return 0;
}

int test_genaro_mnemonic_generate_256()
{
    int status;
    int stren = 256;
    char *mnemonic = NULL;
    genaro_mnemonic_generate(stren, &mnemonic);
    status = genaro_mnemonic_check(mnemonic);

    if (status != 1) {
        fail("test_mnemonic_generate");
        printf("\t\texpected mnemonic check: %i\n", 0);
        printf("\t\tactual mnemonic check:   %i\n", status);
        free(mnemonic);
        return 1;
    }
    free(mnemonic);

    pass("test_genaro_mnemonic_check_256");

    return 0;
}

int test_genaro_mnemonic_generate()
{
    int status;
    int stren = 128;
    char *mnemonic = NULL;
    genaro_mnemonic_generate(stren, &mnemonic);
    status = genaro_mnemonic_check(mnemonic);

    if (status != 1) {
        fail("test_mnemonic_generate");
        printf("\t\texpected mnemonic check: %i\n", 0);
        printf("\t\tactual mnemonic check:   %i\n", status);
        free(mnemonic);
        return 1;
    }
    free(mnemonic);

    pass("test_genaro_mnemonic_check");

    return 0;
}*/

int test_mnemonic_generate()
{
    int status;
    int stren = 128;
    char *mnemonic = NULL;
    mnemonic_generate(stren, &mnemonic);
    status = mnemonic_check(mnemonic);

    if (status != 1) {
        fail("test_mnemonic_generate");
        printf("\t\texpected mnemonic check: %i\n", 0);
        printf("\t\tactual mnemonic check:   %i\n", status);
        free(mnemonic);
        return 1;
    }
    free(mnemonic);

    pass("test_mnemonic_generate");

    return 0;
}

int test_generate_seed()
{
    char *mnemonic = "abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde ab";
    char *seed = calloc(128 + 1, sizeof(char));
    char *expected_seed = "0e07b8f829d493a3430682a087ccb592b543434c157fbe0e2c15235a2b64169b1274acfcdcf15c366cf2769c16077060b88ca324d4cd40177870164ff16ef7a3";

    mnemonic_to_seed((uint8_t *)mnemonic, 128, "", &seed);
    seed[128] = '\0';

    int check = memcmp(seed, expected_seed, 128);
    if (check != 0) {
        fail("test_generate_seed");
        printf("\t\texpected seed: %s\n", expected_seed);
        printf("\t\tactual seed:   %s\n", seed);

        free(seed);
        return 1;
    }

    free(seed);
    pass("test_generate_seed");

    return 0;
}

int test_generate_seed_trezor()
{
    char *mnemonic = "abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde ab";
    char *seed = calloc(128 + 1, sizeof(char));
    char *expected_seed = "2a941bdadf69c0ca370ca1974b8d25ed053bae5f27144f554bcca6fe8556df77ef937c7b5892ff951ee738862f4c6aff1f9aa1472bb1ded441c03edeb7e75479";

    mnemonic_to_seed((uint8_t *)mnemonic, 128, "TREZOR", &seed);
    seed[128] = '\0';

    int check = memcmp(seed, expected_seed, 128);
    if (check != 0) {
        fail("test_generate_seed_256_trezor");
        printf("\t\texpected seed: %s\n", expected_seed);
        printf("\t\tactual seed:   %s\n", seed);

        free(seed);
        return 1;
    }

    free(seed);
    pass("test_generate_seed_256_trezor");

    return 0;
}

int test_get_deterministic_key()
{
    char *key = "1625348fba";
    char *bucket_id = "385960ffa4";
    char *buffer = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    char *expected_buffer = "296195601e0557bef8963a418c53489f4216e8fe033768b5ca2a9bfb02188296";

    get_deterministic_key(key, strlen(key), bucket_id, &buffer);

    int check = memcmp(expected_buffer, buffer, DETERMINISTIC_KEY_SIZE);
    if (check != 0) {
        fail("test_get_deterministic_key");
        printf("\t\texpected buffer: %s\n", expected_buffer);
        printf("\t\tactual buffer:   %s\n", buffer);
        return 1;
    }

    pass("test_get_deterministic_key");

    return 0;
}

int test_generate_bucket_key()
{
    char *mnemonic = "abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcd";
    char *bucket_id = "0123456789ab0123456789ab";
    char *bucket_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    char *expected_bucket_key = "b17403c5130847731abd1c233e74002aa666c71497a19c90b7c305479ccd5844";

    generate_bucket_key((uint8_t *)mnemonic, strlen(mnemonic), bucket_id, &bucket_key);
    bucket_key[DETERMINISTIC_KEY_SIZE] = '\0';

    int check = memcmp(expected_bucket_key, bucket_key, DETERMINISTIC_KEY_SIZE);
    if (check != 0) {
        fail("test_generate_bucket_key");
        printf("\t\texpected bucket_key: %s\n", expected_bucket_key);
        printf("\t\tactual bucket_key:   %s\n", bucket_key);

        free(bucket_key);
        return 1;
    }

    free(bucket_key);
    pass("test_generate_bucket_key");

    return 0;
}

int test_generate_file_key()
{
    char *mnemonic = "abcde abcde abcde abcde abcde abcde abcde abcde abcde abcde abcd";
    char *bucket_id = "0123456789ab0123456789ab";
    char *index = "150589c9593bbebc0e795d8c4fa97304b42c110d9f0095abfac644763beca66e";
    char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    char *expected_file_key = "eccd01f6a87991ff0b504718df1da40cb2bcda48099375f5124358771c9ebe2c";

    generate_file_key((uint8_t *)mnemonic, strlen(mnemonic), bucket_id, index, &file_key);

    int check = strcmp(expected_file_key, file_key);
    if (check != 0) {
        fail("test_generate_file_key");
        printf("\t\texpected file_key: %s\n", expected_file_key);
        printf("\t\tactual file_key:   %s\n", file_key);

        free(file_key);
        return 1;
    }

    free(file_key);
    pass("test_generate_file_key");

    return 0;
}

int test_str2hex()
{
    char *data = "632442ba2e5f28a3a4e68dcb0b45d1d8f097d5b47479d74e2259055aa25a08aa";

    uint8_t *buffer = str_decode_to_hex(64, data);

    uint8_t expected[32] = {99,36,66,186,46,95,40,163,164,230,141,203,11,69,
                              209,216,240,151,213,180,116,121,215,78,34,89,5,
                              90,162,90,8,170};

    int failed = 0;
    for (int i = 0; i < 32; i++) {
        if (expected[i] != buffer[i]) {
            failed = 1;
        }
    }

    if (failed) {
        fail("test_str2hex");
    } else {
        pass("test_str2hex");
    }

    free(buffer);

    return 0;
}

int test_hex_to_str()
{
    uint8_t data[32] = {99,36,66,186,46,95,40,163,164,230,141,203,11,69,
                              209,216,240,151,213,180,116,121,215,78,34,89,5,
                              90,162,90,8,170};

    char *result = hex_encode_to_str(32, data);
    if (!result) {
        fail("test_hex_to_str");
        return 0;
    }

    char *expected = "632442ba2e5f28a3a4e68dcb0b45d1d8f097d5b47479d74e2259055aa25a08aa";

    int failed = 0;
    if (strcmp(expected, result) != 0) {
        failed = 1;
    }

    if (failed) {
        fail("test_hex_to_str");
    } else {
        pass("test_hex_to_str");
    }

    free(result);

    return 0;
}

int test_get_time_milliseconds()
{
    double time = get_time_milliseconds();

    // TODO check against another source
    if (time) {
        pass("test_get_time_milliseconds");
    } else {
        fail("test_get_time_milliseconds");
    }

    return 0;
}

int test_determine_shard_size()
{
    uint64_t file_size;
    uint64_t shard_size;
    uint64_t expected_shard_size;

    // 1000 bytes should be 8Mb
    file_size = 1000;
    expected_shard_size = 2097152;
    shard_size = determine_shard_size(file_size, 0);

    if (shard_size != expected_shard_size) {
        fail("test_determine_shard_size");
        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);

        return 1;
    }

    file_size = 134217729;
    expected_shard_size = 16777216;
    shard_size = determine_shard_size(file_size, 0);

    if (shard_size != expected_shard_size) {
        fail("test_determine_shard_size");
        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);

        return 1;
    }

    file_size = 268435457;
    expected_shard_size = 33554432;
    shard_size = determine_shard_size(file_size, 0);

    if (shard_size != expected_shard_size) {
        fail("test_determine_shard_size");
        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);

        return 1;
    }

    // Make sure we stop at max file size
    file_size = 1012001737418240;
    expected_shard_size = 4294967296;
    shard_size = determine_shard_size(file_size, 0);

    if (shard_size != expected_shard_size) {
        fail("test_determine_shard_size");
        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);

        return 1;
    }

    // Test fail case
    file_size = 0;
    expected_shard_size = 0;
    shard_size = determine_shard_size(file_size, 0);

    if (shard_size != expected_shard_size) {
        fail("test_determine_shard_size");
        printf("\t\texpected shard_size: %" PRIu64 "\n", expected_shard_size);
        printf("\t\tactual shard_size:   %" PRIu64 "\n", shard_size);

        return 1;
    }

    pass("test_determine_shard_size");

    return 0;
}

int test_increment_ctr_aes_iv()
{
    uint8_t iv[16] = {188,14,95,229,78,112,182,107,
                        34,206,248,225,52,22,16,183};

    if (!increment_ctr_aes_iv(iv, 1)) {
        fail("increment_ctr_aes_iv(0)");
        return 1;
    }

    if (increment_ctr_aes_iv(iv, AES_BLOCK_SIZE)) {
        fail("increment_ctr_aes_iv(1)");
        return 1;
    }

    if (iv[15] != 184) {
        fail("increment_ctr_aes_iv(2)");
        return 1;
    }

    if (increment_ctr_aes_iv(iv, AES_BLOCK_SIZE * 72)) {
        fail("increment_ctr_aes_iv(3)");
        return 1;
    }

    if (iv[15] != 0 || iv[14] != 17) {
        fail("increment_ctr_aes_iv(4)");
        return 1;
    }

    pass("increment_ctr_aes_iv");
    return 0;
}

/*int test_read_write_encrypted_file()
{
    // it should create file passed in if it does not exist
    char test_file[1024];
    strcpy(test_file, folder);
    strcat(test_file, "genaro-test-user.json");
    if (access(test_file, F_OK) != -1) {
        unlink(test_file);
    }

    // it should successfully encrypt and decrypt a file with the provided key and salt
    char *expected_mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless";
    genaro_encrypt_write_auth(test_file, "testpass",
                             "testuser@genaro.io", "bridgepass", expected_mnemonic);

    char *bridge_user = NULL;
    char *bridge_pass = NULL;
    char *mnemonic = NULL;
    if (genaro_decrypt_read_auth(test_file, "testpass", &mnemonic)) {
        fail("test_genaro_write_read_auth(0)");
        return 1;
    }

    if (strcmp(bridge_user, "testuser@genaro.io") != 0) {
        fail("test_genaro_write_read_auth(1)");
        return 1;
    }

    if (strcmp(bridge_pass, "bridgepass") != 0) {
        fail("test_genaro_write_read_auth(2)");
        return 1;
    }

    if (strcmp(mnemonic, expected_mnemonic) != 0) {
        fail("test_genaro_write_read_auth(3)");
        return 1;
    }

    free(bridge_user);
    free(bridge_pass);
    free(mnemonic);

    // it should fail to decrypt if the wrong password
    if (!genaro_decrypt_read_auth(test_file, "wrongpass", &mnemonic)) {
        fail("test_genaro_write_read_auth(4)");
        return 1;
    }

    free(bridge_user);
    free(bridge_pass);

    pass("test_genaro_write_read_auth");

    return 0;
}*/

int test_meta_encryption_name(char *filename)
{

    // uint8_t encrypt_key[32] = {215,99,0,133,172,219,64,35,54,53,171,23,146,160,
    //                            81,126,137,21,253,171,48,217,184,188,8,137,3,
    //                            4,83,50,30,251};
    // uint8_t iv[32] = {70,219,247,135,162,7,93,193,44,123,188,234,203,115,129,
    //                   82,70,219,247,135,162,7,93,193,44,123,188,234,203,115,
    //                   129,82};

    uint8_t encrypt_key[32] = {11,22,0,133,172,219,64,35,54,53,171,23,146,160,
                               81,33,137,21,253,171,48,217,184,188,8,137,3,
                               4,83,50,33,251};
    uint8_t iv[32] = {44,219,247,135,162,7,93,193,44,123,188,234,203,115,129,
                      82,44,219,247,44,162,7,93,193,44,123,188,234,203,115,
                      12,82};

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
            fail("test_meta_encryption");
            printf("Failed with filename: %s\n", filename);
            return 1;
        }
        free(filename);
    }
    pass("test_meta_encryption");
    return 0;
}

int test_memory_mapping()
{
    char *file_name = "genaro-memory-map.data";
    int len = strlen(folder) + 1 + strlen(file_name);
    char *file = calloc(len + 1, sizeof(char));
    strcpy(file, folder);
    strcat(file, "/");
    strcat(file, file_name);
    file[len] = '\0';

    create_test_upload_file(file);

    FILE *fp = fopen(file, "rb+");
    int fd = fileno(fp);

    if (!fp) {
        printf("failed open.\n");
        return 1;
    }

    fseek(fp, 0L, SEEK_END);
    uint64_t filesize = ftell(fp);
    rewind(fp);

    uint8_t *map = NULL;
    int error = map_file(fd, filesize, &map, false);
    if (error) {
        printf("failed to map file: %i\n", error);
        fail("test_memory_mapping(0)");
        return 1;
    }

    if (map[40001] != 97) {
        fail("test_memory_mapping(1)");
    }

    map[40001] = 0;

    error = unmap_file(map, filesize);
    if (error) {
        printf("failed to unmap file: %d", error);
        fail("test_memory_mapping(2)");
        return 1;
    }

    fclose(fp);

    FILE *fp2 = fopen(file, "rb+");
    int fd2 = fileno(fp2);

    if (!fp2) {
        printf("failed open.\n");
        return 1;
    }

    uint8_t *map2 = NULL;
    error = map_file(fd2, filesize, &map2, false);
    if (error) {
        printf("failed to map file: %i\n", error);
        fail("test_memory_mapping(3)");
        return 1;
    }

    if (map2[40001] != 0) {
        fail("test_memory_mapping(4)");
    }

    error = unmap_file(map2, filesize);
    if (error) {
        printf("failed to unmap file: %d", error);
        fail("test_memory_mapping(5)");
        return error;
    }

    fclose(fp2);
    free(file);

    pass("test_memory_mapping");

    return 0;
}

static int encrypt_file(char *file_path, char *encrypted_file_path, uint8_t *key, uint8_t *ctr)
{
    int ret = 0;

    // Initialize the encryption context
    genaro_encryption_ctx_t *encryption_ctx = prepare_encryption_ctx(ctr, key);
    if (!encryption_ctx) {
        return 1;
    }

    uint8_t cphr_txt[AES_BLOCK_SIZE * 256];
    memset_zero(cphr_txt, AES_BLOCK_SIZE * 256);
    char read_data[AES_BLOCK_SIZE * 256];
    memset_zero(read_data, AES_BLOCK_SIZE * 256);
    unsigned long int read_bytes = 0;
    unsigned long int written_bytes = 0;
    uint64_t total_read = 0;
    uint64_t file_size = 0;

    FILE *original_file = fopen(file_path, "rb");
    FILE *encrypted_file = fopen(encrypted_file_path, "wb+");

    if (original_file == NULL || encrypted_file == NULL) {
        ret = 2;
        goto clean_variables;
    }

    fseek(original_file, 0, SEEK_END);
    file_size = ftell(original_file);
    fseek(original_file, 0, SEEK_SET);

    do {
        read_bytes = pread(fileno(original_file),
                           read_data, AES_BLOCK_SIZE * 256,
                           total_read);

        if (read_bytes == -1) {
            ret = 4;
            goto clean_variables;
        }

        // Encrypt data
        ctr_crypt(encryption_ctx->ctx, (nettle_cipher_func *)aes256_encrypt,
                  AES_BLOCK_SIZE, encryption_ctx->encryption_ctr, read_bytes,
                  (uint8_t *)cphr_txt, (uint8_t *)read_data);

        written_bytes = pwrite(fileno(encrypted_file), cphr_txt, read_bytes, total_read);
        if (written_bytes != read_bytes) {
            ret = 4;
            goto clean_variables;
        }

        memset_zero(read_data, AES_BLOCK_SIZE * 256);
        memset_zero(cphr_txt, AES_BLOCK_SIZE * 256);

        total_read += read_bytes;
    } while(total_read < file_size && read_bytes > 0);

clean_variables:
    if (original_file) {
        fclose(original_file);
    }
    if (encrypted_file) {
        fclose(encrypted_file);
    }
    if (encryption_ctx) {
        free_encryption_ctx(encryption_ctx);
    }

    return ret;
}

static int decrypt_file(char *destination_file_path, uint8_t *key, uint8_t *ctr)
{
    int ret = 0;
    uint64_t file_size = 0;
    uint8_t *data_map = NULL;
    struct aes256_ctx ctx;
    uint64_t bytes_decrypted = 0;
    size_t len = AES_BLOCK_SIZE * 8;

    FILE *destination_file = fopen(destination_file_path, "rb+");

    if (destination_file == NULL) {
        ret = 1;
        goto clean_variables;
    }

    fseek(destination_file, 0, SEEK_END);
    file_size = ftell(destination_file);
    fseek(destination_file, 0, SEEK_SET);

    int error = map_file(fileno(destination_file), file_size, &data_map, false);
    if (error) {
        ret = 2;
        goto clean_variables;
    }

    aes256_set_encrypt_key(&ctx, key);

    while (bytes_decrypted < file_size) {
        if (bytes_decrypted + len > file_size) {
            len = file_size - bytes_decrypted;
        }

        ctr_crypt(&ctx, (nettle_cipher_func *)aes256_encrypt,
                AES_BLOCK_SIZE, ctr,
                len,
                data_map + bytes_decrypted,
                data_map + bytes_decrypted);

        bytes_decrypted += len;
    }

    if(data_map) {
        error = unmap_file(data_map, file_size);
        if (error) {
            ret = 3;
            goto clean_variables;
        }
    }

clean_variables:
    if (destination_file) {
        fclose(destination_file);
    }

    return ret;
}

int test_encrypt_and_decrypt_file()
{
    uint8_t key[AES_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t ctr[AES_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    char *file_name = "test_encrypt_and_decrypt_file.txt";
    char *destination_file_path = "destination.txt";

    FILE *new_file = fopen(file_name, "wb+");
    if(!new_file) {
        printf("failed to open file: %s\n", file_name);
        return 1;
    }

    size_t file_size = 3 * 1024 * 1024;  // bytes
    char *data = (char *)malloc((file_size + 1) * sizeof(char));
    if(!data) {
        printf("failed to malloc\n");
        return 1;
    }
    memset(data, '1', file_size);
    data[file_size] = 0;
    size_t written_bytes = fwrite(data, 1, file_size, new_file);
    free(data);
    fclose(new_file);
    if(written_bytes != file_size) {
        printf("failed to write file\n");
        return 1;
    }

    int error = encrypt_file(file_name, destination_file_path, key, ctr);
    if(error) {
        printf("failed to encrypt file: %s\n", file_name);
        fail("test_encrypt_and_decrypt_file");
        return 1;
    }

    error = decrypt_file(destination_file_path, key, ctr);
    if(error) {
        printf("failed to decrypt file: %s, ret: %d\n", file_name, error);
        fail("test_encrypt_and_decrypt_file");
        return 1;
    }

    FILE *original_file = fopen(file_name, "rb");
    if(!original_file) {
        printf("failed to open file: %s\n", file_name);
        return 1;
    }

    FILE *destination_file = fopen(destination_file_path, "rb");
    if(!destination_file) {
        printf("failed to open file: %s\n", destination_file_path);
        return 1;
    }

    uint8_t *original_data = (uint8_t *)malloc(file_size);
    if(!original_data) {
        printf("failed to malloc\n");
        return 1;
    }

    uint8_t *decrypted_data = (uint8_t *)malloc(file_size);
    if(!decrypted_data) {
        printf("failed to malloc\n");
        return 1;
    }

    size_t original_read_bytes = fread(original_data, 1, file_size, original_file);
    size_t decrypted_read_bytes = fread(decrypted_data, 1, file_size, destination_file);
    fclose(original_file);
    fclose(destination_file);
    if(original_read_bytes != file_size || decrypted_read_bytes != file_size) {
        printf("failed to read file\n");
        return 1;
    }

    error = memcmp(original_data, decrypted_data, file_size);
    free(original_data);
    free(decrypted_data);
    if(error) {
        printf("the decrypted file is not the same as the original file\n");
        fail("test_encrypt_and_decrypt_file");
        return 1;
    }

    pass("test_encrypt_and_decrypt_file");
    return 0;
}

// Test Bridge Server
struct MHD_Daemon *start_test_server()
{
    // spin up test bridge server
    return MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
                            8091,
                            NULL,
                            NULL,
                            &mock_bridge_server,
                            NULL,
                            MHD_OPTION_END);
}

int main(void)
{
    // Make sure we have a tmp folder
    folder = getenv("TMPDIR");

    if (folder == 0) {
        printf("You need to set $TMPDIR before running. (e.g. export TMPDIR=/tmp/)\n");
        exit(1);
    }

    // spin up test bridge server
    struct MHD_Daemon *d = start_test_server();
    if (d == NULL) {
        printf("Could not start test server.\n");
        return 0;
    };

    // spin up test farmer server
    struct MHD_Daemon *f = start_farmer_server();

    printf("Test Suite: BIP39\n");
    /*test_mnemonic_check();*/
    test_mnemonic_generate();
    /*test_genaro_mnemonic_generate();
    test_genaro_mnemonic_generate_256();*/
    test_generate_seed();
    test_generate_seed_trezor();
    printf("\n");

    printf("Test Suite: Crypto\n");
    test_get_deterministic_key();
    test_generate_bucket_key();
    test_generate_file_key();
    test_increment_ctr_aes_iv();
    /*test_read_write_encrypted_file();*/
    test_meta_encryption();
    printf("\n");

    printf("Test Suite: Utils\n");
    test_str2hex();
    test_hex_to_str();
    test_get_time_milliseconds();
    test_determine_shard_size();
    test_memory_mapping();
    printf("\n");

    printf("Test Suite: API\n");
    test_api();
    test_encrypt_and_decrypt_file();
    // test_api_badauth();
    printf("\n");

    printf("Test Suite: Uploads\n");
    test_upload();
    test_upload_cancel();
    printf("\n");

    printf("Test Suite: Downloads\n");
    test_download();
    test_download_cancel();
    printf("\n");

    int num_failed = tests_ran - test_status;
    printf(KGRN "\nPASSED: %i" RESET, test_status);
    if (num_failed > 0) {
        printf(KRED " FAILED: %i" RESET, num_failed);
    }
    printf(" TOTAL: %i\n", (tests_ran));

    // Shutdown test servers
    MHD_stop_daemon(d);
    MHD_stop_daemon(f);
    free_farmer_data();

    if (num_failed > 0) {
        return 1;
    }

    return 0;
}
