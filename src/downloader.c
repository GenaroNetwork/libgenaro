#include "downloader.h"

static void free_exchange_report(storj_exchange_report_t *report)
{
    free(report->data_hash);
    free(report->reporter_id);
    free(report->farmer_id);
    free(report->client_id);
    free(report);
}

static void free_download_state(storj_download_state_t *state)
{
    for (int i = 0; i < state->total_pointers; i++) {
        storj_pointer_t *pointer = &state->pointers[i];

        free(pointer->token);
        free(pointer->shard_hash);
        free(pointer->farmer_id);
        free(pointer->farmer_address);

        free_exchange_report(pointer->report);
    }

    if (state->excluded_farmer_ids) {
        free(state->excluded_farmer_ids);
    }

    if (state->decrypt_key) {
        memset_zero(state->decrypt_key, SHA256_DIGEST_SIZE);
        free(state->decrypt_key);
    }

    if (state->decrypt_ctr) {
        memset_zero(state->decrypt_ctr, AES_BLOCK_SIZE);
        free(state->decrypt_ctr);
    }

    if (state->info) {
        if (state->info->erasure) {
            free((char *)state->info->erasure);
        }
        free((char *)state->info->hmac);
        free(state->info);
    }

    if (state->hmac)  {
        free((char *)state->hmac);
    }

    free(state->pointers);
    free(state);
}

static void request_pointers(uv_work_t *work)
{
    json_request_download_t *req = work->data;
    storj_download_state_t *state = req->state;

    int status_code = 0;
    int request_status = fetch_json(req->http_options, req->options, req->method,
                                    req->path, req->body, req->auth,
                                    &req->response, &status_code);


    if (request_status) {
        state->log->warn(state->env->log_options, state->handle,
                         "Request pointers error: %i", request_status);
    }

    req->status_code = status_code;

    if (!req->response) {
        req->status_code = -1;
    }

}

static void request_replace_pointer(uv_work_t *work)
{
    json_request_replace_pointer_t *req = work->data;
    storj_download_state_t *state = req->state;

    int status_code = 0;

    int excluded_farmer_ids_len = (req->excluded_farmer_ids) ? strlen(req->excluded_farmer_ids) : 0;
    char query_args[BUFSIZ];
    memset(query_args, '\0', BUFSIZ);
    snprintf(query_args, BUFSIZ,
             "?limit=1&skip=%i&exclude=%s",
             req->pointer_index,
             req->excluded_farmer_ids);

    int path_len = 9 + strlen(req->bucket_id) + 7 +
        strlen(req->file_id) + strlen(query_args);
    char *path = calloc(path_len + 1, sizeof(char));
    if (!path) {
        req->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    strcat(path, "/buckets/");
    strcat(path, req->bucket_id);
    strcat(path, "/files/");
    strcat(path, req->file_id);
    strcat(path, query_args);

    int request_status = fetch_json(req->http_options, req->options, "GET",
                                    path, NULL, true,
                                    &req->response, &status_code);

    if (request_status) {
        state->log->warn(state->env->log_options, state->handle,
                         "Request replace pointer error: %i", request_status);
    }

    req->status_code = status_code;

    if (!req->response) {
        req->status_code = -1;
    }

    free(path);

}

static void set_pointer_from_json(storj_download_state_t *state,
                                  storj_pointer_t *p,
                                  struct json_object *json,
                                  bool is_replaced)
{
    if (!json_object_is_type(json, json_type_object)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }

    struct json_object *token_value;
    char *token = NULL;
    if (json_object_object_get_ex(json, "token", &token_value)) {
        token = (char *)json_object_get_string(token_value);
    }

    struct json_object *hash_value;
    if (!json_object_object_get_ex(json, "hash", &hash_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    char *hash = (char *)json_object_get_string(hash_value);

    struct json_object *size_value;
    if (!json_object_object_get_ex(json, "size", &size_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    uint64_t size = json_object_get_int64(size_value);

    struct json_object *parity_value;
    bool parity = false;
    if (json_object_object_get_ex(json, "parity", &parity_value)) {
        parity = json_object_get_boolean(parity_value);
    }

    struct json_object *index_value;
    if (!json_object_object_get_ex(json, "index", &index_value)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
        return;
    }
    uint32_t index = json_object_get_int(index_value);

    struct json_object *farmer_value;
    char *address = NULL;
    uint32_t port = 0;
    char *farmer_id = NULL;
    if (json_object_object_get_ex(json, "farmer", &farmer_value) &&
        json_object_is_type(farmer_value, json_type_object)) {

        struct json_object *address_value;
        if (!json_object_object_get_ex(farmer_value, "address",
                                       &address_value)) {
            state->error_status = STORJ_BRIDGE_JSON_ERROR;
            return;
        }
        address = (char *)json_object_get_string(address_value);

        struct json_object *port_value;
        if (!json_object_object_get_ex(farmer_value, "port", &port_value)) {
            state->error_status = STORJ_BRIDGE_JSON_ERROR;
            return;
        }
        port = json_object_get_int(port_value);

        struct json_object *farmer_id_value;
        if (!json_object_object_get_ex(farmer_value, "nodeID",
                                       &farmer_id_value)) {
            state->error_status = STORJ_BRIDGE_JSON_ERROR;
            return;
        }
        farmer_id = (char *)json_object_get_string(farmer_id_value);
    }

    if (is_replaced) {
        p->replace_count += 1;
    } else {
        p->replace_count = 0;
    }

    // Check to see if we have a token for this shard, otherwise
    // we will immediatly move this shard to POINTER_MISSING
    // so that it can be retried and possibly recovered.
    if (address && token) {
        // reset the status
        p->status = POINTER_CREATED;
    } else {
        state->log->warn(state->env->log_options,
                         state->handle,
                         "Missing shard %s at index %i",
                         hash,
                         index);
        p->status = POINTER_MISSING;
    }

    p->size = size;
    p->parity = parity;
    p->downloaded_size = 0;
    p->index = index;
    p->farmer_port = port;

    if (is_replaced) {
        free(p->token);
        free(p->shard_hash);
        free(p->farmer_address);
        free(p->farmer_id);
    }
    if (token) {
        p->token = strdup(token);
    } else {
        p->token = NULL;
    }
    p->shard_hash = strdup(hash);
    if (address) {
        p->farmer_address = strdup(address);
    } else {
        p->farmer_address = NULL;
    }
    if (farmer_id) {
        p->farmer_id = strdup(farmer_id);
    } else {
        p->farmer_id = NULL;
    }

    // setup exchange report values
    if (is_replaced) {
        free_exchange_report(p->report);
    }
    p->report = malloc(
        sizeof(storj_exchange_report_t));

    if (!p->report) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    const char *client_id = state->env->bridge_options->user;
    p->report->reporter_id = strdup(client_id);
    p->report->client_id = strdup(client_id);
    p->report->data_hash = strdup(hash);
    if (farmer_id) {
        p->report->farmer_id = strdup(farmer_id);
    } else {
        p->report->farmer_id = NULL;
    }
    p->report->send_status = 0; // not sent
    p->report->send_count = 0;

    // these values will be changed in after_request_shard
    p->report->start = 0;
    p->report->end = 0;
    p->report->code = STORJ_REPORT_FAILURE;
    p->report->message = STORJ_REPORT_DOWNLOAD_ERROR;

    p->work = NULL;

    if (!state->shard_size) {
        // TODO make sure all except last shard is the same size
        state->shard_size = size;
        state->log->debug(state->env->log_options,
                          state->handle,
                          "Shard size set to %" PRIu64,
                          state->shard_size);
    };
}

static void append_pointers_to_state(storj_download_state_t *state,
                                     struct json_object *res)
{
    int length = json_object_array_length(res);

    if (length == 0) {
        state->log->debug(state->env->log_options,
                          state->handle,
                          "Finished requesting pointers");
        state->pointers_completed = true;
    } else if (length > 0) {

        int prev_total_pointers = state->total_pointers;
        int total_pointers = state->total_pointers + length;

        if (state->total_pointers > 0) {
            state->pointers = realloc(state->pointers,
                                      total_pointers * sizeof(storj_pointer_t));
        } else {
            state->pointers = malloc(length * sizeof(storj_pointer_t) * 100);
        }
        if (!state->pointers) {
            state->error_status = STORJ_MEMORY_ERROR;
            return;
        }

        state->total_pointers = total_pointers;
        state->total_shards = total_pointers;

        for (int i = 0; i < length; i++) {

            // get the relative index
            int j = i + prev_total_pointers;

            struct json_object *json = json_object_array_get_idx(res, i);

            set_pointer_from_json(state, &state->pointers[j], json, false);

            // Keep track of the number of data and parity pointers
            storj_pointer_t *pointer = &state->pointers[j];
            if (pointer->parity) {
                state->total_parity_pointers += 1;
            }
        }
    }

}

static void after_request_pointers(uv_work_t *work, int status)
{
    json_request_download_t *req = work->data;
    storj_download_state_t *state = req->state;

    state->pending_work_count--;
    state->requesting_pointers = false;

    if (req->response) {
        state->log->debug(state->env->log_options, state->handle,
                          "Finished request pointers - JSON Response %s",
                          json_object_to_json_string(req->response));
    }

    if (status != 0)  {

        state->error_status = STORJ_BRIDGE_POINTER_ERROR;

    } else if (req->status_code == 429 || req->status_code == 420) {

        state->error_status = STORJ_BRIDGE_RATE_ERROR;

    } else if (req->status_code != 200) {
        if (req->status_code > 0 && req->status_code < 500) {
            state->error_status = STORJ_BRIDGE_POINTER_ERROR;
        } else {
            state->pointer_fail_count += 1;
        }

        state->log->debug(state->env->log_options, state->handle,
                          "Request pointers fail count: %i",
                          state->pointer_fail_count);

        if (state->pointer_fail_count >= STORJ_MAX_POINTER_TRIES) {
            state->pointer_fail_count = 0;
            state->error_status = STORJ_BRIDGE_POINTER_ERROR;
        }

    } else if (!json_object_is_type(req->response, json_type_array)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
    } else {
        append_pointers_to_state(state, req->response);
    }

    queue_next_work(state);

    if (req->response) {
        json_object_put(req->response);
    }
    free(req->path);
    free(req);
    free(work);
}

static void after_request_replace_pointer(uv_work_t *work, int status)
{
    json_request_replace_pointer_t *req = work->data;
    storj_download_state_t *state = req->state;

    state->pending_work_count--;
    state->requesting_pointers = false;

    state->log->debug(state->env->log_options, state->handle,
                      "Finished request replace pointer %i - JSON Response: %s",
                      req->pointer_index,
                      json_object_to_json_string(req->response));

    if (status != 0) {

        state->error_status = STORJ_BRIDGE_REPOINTER_ERROR;

    } else if (req->error_status) {

        state->error_status = req->error_status;

    } else if (req->status_code == 429 || req->status_code == 420) {

        state->error_status = STORJ_BRIDGE_RATE_ERROR;

    } else if (req->status_code != 200) {

        if (req->status_code > 0 && req->status_code < 500) {
            state->pointers[req->pointer_index].status = POINTER_MISSING;
        } else {
            // Update status so that it will be retried
            state->pointers[req->pointer_index].status = POINTER_ERROR_REPORTED;
            state->pointer_fail_count += 1;
        }

        state->log->debug(state->env->log_options, state->handle,
                          "Request replace pointer fail count: %i",
                          state->pointer_fail_count);

        if (state->pointer_fail_count >= STORJ_MAX_POINTER_TRIES) {
            // Skip retrying mark as missing
            state->pointer_fail_count = 0;
            state->pointers[req->pointer_index].status = POINTER_MISSING;
        }

    } else if (!json_object_is_type(req->response, json_type_array)) {
        state->error_status = STORJ_BRIDGE_JSON_ERROR;
    } else {
        struct json_object *json = json_object_array_get_idx(req->response, 0);

        set_pointer_from_json(state,
                              &state->pointers[req->pointer_index],
                              json,
                              true);

        if (state->pointers[req->pointer_index].index != req->pointer_index) {

            state->log->error(state->env->log_options,
                              state->handle,
                              "Replacement shard index %i does not match %i",
                              state->pointers[req->pointer_index].index,
                              req->pointer_index);

            state->error_status = STORJ_BRIDGE_JSON_ERROR;
        }
    }

    queue_next_work(state);

    json_object_put(req->response);
    free(work->data);
    free(work);
}

static void queue_request_pointers(storj_download_state_t *state)
{
    if (state->requesting_pointers || state->canceled) {
        return;
    }

    // queue request to replace pointer if any pointers have failure
    for (int i = 0; i < state->total_pointers; i++) {

        storj_pointer_t *pointer = &state->pointers[i];

        if (pointer->replace_count >= STORJ_DEFAULT_MIRRORS) {
            state->log->warn(state->env->log_options,
                             state->handle,
                             "Unable to download shard %s at index %i",
                             pointer->shard_hash,
                             pointer->index);
            pointer->replace_count = 0;
            pointer->status = POINTER_MISSING;
            return;
        }

        if (pointer->status == POINTER_ERROR_REPORTED) {

            // exclude this farmer id from future requests
            state->log->debug(state->env->log_options,
                              state->handle,
                              "Adding farmer_id %s to excluded list",
                              pointer->report->farmer_id);

            if (!state->excluded_farmer_ids) {
                state->excluded_farmer_ids = calloc(42, sizeof(char));
                if (!state->excluded_farmer_ids) {
                    state->error_status = STORJ_MEMORY_ERROR;
                    return;
                }
                strcat(state->excluded_farmer_ids, pointer->report->farmer_id);
            } else {
                state->excluded_farmer_ids =
                    realloc(state->excluded_farmer_ids,
                            strlen(state->excluded_farmer_ids) + 42);
                if (!state->excluded_farmer_ids) {
                    state->error_status = STORJ_MEMORY_ERROR;
                    return;
                }
                strcat(state->excluded_farmer_ids, ",");
                strcat(state->excluded_farmer_ids, pointer->report->farmer_id);
            }

            json_request_replace_pointer_t *req =
                malloc(sizeof(json_request_replace_pointer_t));
            if (!req) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }

            req->pointer_index = i;

            req->http_options = state->env->http_options;
            req->options = state->env->bridge_options;
            req->bucket_id = state->bucket_id;
            req->file_id = state->file_id;
            req->state = state;
            req->excluded_farmer_ids = state->excluded_farmer_ids;
            req->error_status = 0;
            req->response = NULL;
            req->status_code = 0;

            uv_work_t *work = malloc(sizeof(uv_work_t));
            if (!work) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }
            work->data = req;

            state->log->info(state->env->log_options,
                             state->handle,
                             "Requesting replacement pointer at index: %i",
                             req->pointer_index);

            state->pending_work_count++;
            int status = uv_queue_work(state->env->loop,
                                       (uv_work_t*) work,
                                       request_replace_pointer,
                                       after_request_replace_pointer);

            if (status) {
                state->error_status = STORJ_QUEUE_ERROR;
                return;
            }

            pointer->status = POINTER_BEING_REPLACED;

            // we're done until the next pass
            state->requesting_pointers = true;
            return;
        }

    }

    // only request the next set of pointers if we're not finished
    if (state->pointers_completed) {
        return;
    }

    json_request_download_t *req = malloc(sizeof(json_request_download_t));
    if (!req) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    char query_args[BUFSIZ];
    memset(query_args, '\0', BUFSIZ);
    snprintf(query_args, BUFSIZ, "?limit=3&skip=%d", state->total_pointers);

    int path_len = 9 + strlen(state->bucket_id) + 7 +
        strlen(state->file_id) + strlen(query_args);

    char *path = calloc(path_len + 1, sizeof(char));
    if (!path) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }
    strcat(path, "/buckets/");
    strcat(path, state->bucket_id);
    strcat(path, "/files/");
    strcat(path, state->file_id);
    strcat(path, query_args);

    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->method = "GET";
    req->path = path;
    req->body = NULL;
    req->auth = true;

    req->state = state;

    uv_work_t *work = malloc(sizeof(uv_work_t));
    if (!work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }
    work->data = req;

    state->log->info(state->env->log_options,
                     state->handle,
                     "Requesting next set of pointers, total pointers: %i",
                     state->total_pointers);

    state->pending_work_count++;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_pointers, after_request_pointers);

    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
        return;
    }

    state->requesting_pointers = true;
}

static void request_shard(uv_work_t *work)
{
    shard_request_download_t *req = work->data;

    int status_code;
    int write_code = 0;

    req->start = get_time_milliseconds();

    uint64_t file_position = req->pointer_index * req->state->shard_size;

    int error_status = fetch_shard(req->http_options,
                                   req->farmer_id,
                                   req->farmer_proto,
                                   req->farmer_host,
                                   req->farmer_port,
                                   req->shard_hash,
                                   req->shard_total_bytes,
                                   req->token,
                                   req->state->destination,
                                   file_position,
                                   &status_code,
                                   &write_code,
                                   &req->progress_handle,
                                   req->canceled);

    req->end = get_time_milliseconds();

    if (write_code != 0) {
        req->state->log->error(req->state->env->log_options, req->state->handle,
                        "Put shard read error: %i", write_code);
    }

    if (error_status) {
        req->error_status = error_status;
    } else if (status_code != 200) {
        switch(status_code) {
            case 401:
            case 403:
                req->error_status = STORJ_FARMER_AUTH_ERROR;
                break;
            case 504:
                req->error_status = STORJ_FARMER_TIMEOUT_ERROR;
                break;
            default:
                req->error_status = STORJ_FARMER_REQUEST_ERROR;
        }
    } else {
        req->error_status = 0;
    }
}

static void free_request_shard_work(uv_handle_t *progress_handle)
{
    uv_work_t *work = progress_handle->data;
    shard_request_download_t *req = work->data;

    free(req);
    free(work);
}

static uint64_t calculate_data_filesize(storj_download_state_t *state)
{
    uint64_t total_bytes = 0;

    for (int i = 0; i < state->total_pointers; i++) {
        storj_pointer_t *pointer = &state->pointers[i];
        if (pointer->parity) {
            continue;
        }
        total_bytes += pointer->size;
    }

    return total_bytes;
}

static void report_progress(storj_download_state_t *state)
{
    uint64_t downloaded_bytes = 0;
    uint64_t total_bytes = 0;

    for (int i = 0; i < state->total_pointers; i++) {

        storj_pointer_t *pointer = &state->pointers[i];

        downloaded_bytes += pointer->downloaded_size;
        total_bytes += pointer->size;
    }

    double total_progress = (double)downloaded_bytes / (double)total_bytes;

    state->progress_cb(total_progress,
                       downloaded_bytes,
                       total_bytes,
                       state->handle);
}

static void after_request_shard(uv_work_t *work, int status)
{
    shard_request_download_t *req = work->data;

    req->state->pending_work_count--;
    req->state->resolving_shards -= 1;

    uv_handle_t *progress_handle = (uv_handle_t *) &req->progress_handle;

    // free the download progress
    free(progress_handle->data);

    // assign work so that we can free after progress_handle is closed
    progress_handle->data = work;

    // update the pointer status
    storj_pointer_t *pointer = &req->state->pointers[req->pointer_index];

    pointer->report->start = req->start;
    pointer->report->end = req->end;

    if (req->error_status) {

        req->state->log->warn(req->state->env->log_options,
                              req->state->handle,
                              "Error downloading shard: %s, reason: %s",
                              req->shard_hash,
                              storj_strerror(req->error_status));

        pointer->status = POINTER_ERROR;

        switch(req->error_status) {
            case STORJ_FARMER_INTEGRITY_ERROR:
                pointer->report->code = STORJ_REPORT_FAILURE;
                pointer->report->message = STORJ_REPORT_FAILED_INTEGRITY;
            default:
                pointer->report->code = STORJ_REPORT_FAILURE;
                pointer->report->message = STORJ_REPORT_DOWNLOAD_ERROR;
        }

    } else {

        req->state->log->info(req->state->env->log_options,
                              req->state->handle,
                              "Finished downloading shard: %s",
                              req->shard_hash);

        pointer->report->code = STORJ_REPORT_SUCCESS;
        pointer->report->message = STORJ_REPORT_SHARD_DOWNLOADED;
        pointer->status = POINTER_DOWNLOADED;

        // Make sure the downloaded size is updated
        pointer->downloaded_size = pointer->size;

        report_progress(req->state);

    }

    queue_next_work(req->state);

    // close the async progress handle
    uv_close(progress_handle, free_request_shard_work);
}

static void progress_request_shard(uv_async_t* async)
{
    shard_download_progress_t *progress = async->data;

    storj_download_state_t *state = progress->state;

    state->pointers[progress->pointer_index].downloaded_size = progress->bytes;

    report_progress(state);
}

static void queue_request_shards(storj_download_state_t *state)
{
    if (state->canceled) {
        return;
    }

    int i = 0;

    while (state->resolving_shards < state->download_max_concurrency &&
           i < state->total_pointers) {

        storj_pointer_t *pointer = &state->pointers[i];

        if (pointer->status == POINTER_CREATED) {
            shard_request_download_t *req = malloc(sizeof(shard_request_download_t));
            if (!req) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }

            req->http_options = state->env->http_options;
            req->farmer_id = pointer->farmer_id;
            req->farmer_proto = "http";
            req->farmer_host = pointer->farmer_address;
            req->farmer_port = pointer->farmer_port;
            req->shard_hash = pointer->shard_hash;
            req->shard_total_bytes = pointer->size;
            req->byte_position = state->shard_size * i;
            req->token = pointer->token;
            req->error_status = 0;

            req->pointer_index = pointer->index;

            req->state = state;
            req->canceled = &state->canceled;

            uv_work_t *work = malloc(sizeof(uv_work_t));
            if (!work) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }

            work->data = req;

            state->resolving_shards += 1;
            pointer->status = POINTER_BEING_DOWNLOADED;
            pointer->work = work;

            state->log->info(state->env->log_options,
                             state->handle,
                             "Queue request shard: %s",
                             req->shard_hash);

            // setup download progress reporting
            shard_download_progress_t *progress =
                malloc(sizeof(shard_download_progress_t));
            if (!progress) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }

            progress->pointer_index = pointer->index;
            progress->bytes = 0;
            progress->state = state;

            req->progress_handle.data = progress;

            uv_async_init(state->env->loop, &req->progress_handle,
                          progress_request_shard);

            // queue download
            state->pending_work_count++;
            int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                                       request_shard, after_request_shard);
            if (status) {
                state->error_status = STORJ_QUEUE_ERROR;
                return;
            }
        }

        i++;
    }
}

static void send_exchange_report(uv_work_t *work)
{
    shard_send_report_t *req = work->data;
    storj_download_state_t *state = req->state;

    struct json_object *body = json_object_new_object();

    json_object_object_add(body, "dataHash",
                           json_object_new_string(req->report->data_hash));

    json_object_object_add(body, "reporterId",
                           json_object_new_string(req->report->reporter_id));

    json_object_object_add(body, "farmerId",
                           json_object_new_string(req->report->farmer_id));

    json_object_object_add(body, "clientId",
                           json_object_new_string(req->report->client_id));

    json_object_object_add(body, "exchangeStart",
                           json_object_new_int64(req->report->start));

    json_object_object_add(body, "exchangeEnd",
                           json_object_new_int64(req->report->end));

    json_object_object_add(body, "exchangeResultCode",
                           json_object_new_int(req->report->code));

    json_object_object_add(body, "exchangeResultMessage",
                           json_object_new_string(req->report->message));

    int status_code = 0;

    // there should be an empty object in response
    struct json_object *response = NULL;
    int request_status = fetch_json(req->http_options,
                                    req->options, "POST",
                                    "/reports/exchanges", body,
                                    true, &response, &status_code);


    if (request_status) {
        state->log->warn(state->env->log_options, state->handle,
                         "Send exchange report error: %i", request_status);
    }

    req->status_code = status_code;

    // free all memory for body and response
    if (response) {
        json_object_put(response);
    }
    json_object_put(body);
}

static void after_send_exchange_report(uv_work_t *work, int status)
{
    shard_send_report_t *req = work->data;

    req->state->pending_work_count--;

    // set status so that this pointer can be replaced
    if (req->report->send_count >= STORJ_MAX_REPORT_TRIES ||
        req->status_code == 201) {

        storj_pointer_t *pointer = &req->state->pointers[req->pointer_index];

        if (pointer->status == POINTER_ERROR) {
            pointer->status = POINTER_ERROR_REPORTED;
        }
    }

    if (req->status_code == 201) {
        // set the status so that this pointer can be replaced
        req->report->send_status = 2; // report has been sent
    } else {
        req->report->send_status = 0; // reset report back to unsent
    }

    queue_next_work(req->state);

    free(work->data);
    free(work);

}

static void queue_send_exchange_reports(storj_download_state_t *state)
{

    if (state->canceled) {
        return;
    }

    for (int i = 0; i < state->total_pointers; i++) {

        storj_pointer_t *pointer = &state->pointers[i];

        if (pointer->report->send_status < 1 &&
            pointer->report->send_count < STORJ_MAX_REPORT_TRIES &&
            pointer->report->start > 0 &&
            pointer->report->end > 0) {

            uv_work_t *work = malloc(sizeof(uv_work_t));
            if (!work) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }

            shard_send_report_t *req = malloc(sizeof(shard_send_report_t));
            if (!req) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }

            req->http_options = state->env->http_options;
            req->options = state->env->bridge_options;
            req->status_code = 0;
            req->report = pointer->report;
            req->report->send_status = 1; // being reported
            req->report->send_count += 1;
            req->state = state;
            req->pointer_index = i;

            work->data = req;

            state->pending_work_count++;
            int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                                       send_exchange_report,
                                       after_send_exchange_report);
            if (status) {
                state->error_status = STORJ_QUEUE_ERROR;
                return;
            }
        }
    }
}

static void determine_decryption_key_v1(storj_download_state_t *state)
{
    uint8_t *index = NULL;
    char *file_key_as_str = NULL;

    file_key_as_str = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    if (!file_key_as_str) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    if (generate_file_key(state->env->encrypt_options->mnemonic,
                          state->bucket_id,
                          state->info->index, &file_key_as_str)) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }
    file_key_as_str[DETERMINISTIC_KEY_SIZE] = '\0';

    uint8_t *decrypt_key = str2hex(strlen(file_key_as_str), file_key_as_str);
    if (!decrypt_key) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    state->decrypt_key = decrypt_key;

    index = str2hex(strlen(state->info->index), (char *)state->info->index);
    if (!index) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    uint8_t *decrypt_ctr = calloc(AES_BLOCK_SIZE, sizeof(uint8_t));
    if (!decrypt_ctr) {
        state->error_status = STORJ_MEMORY_ERROR;
        goto cleanup;
    }

    memcpy(decrypt_ctr, index, AES_BLOCK_SIZE);
    state->decrypt_ctr = decrypt_ctr;

cleanup:
    if (file_key_as_str) {
        free(file_key_as_str);
    }
    if (index) {
        free(index);
    }
}

static void determine_decryption_key_v0(storj_download_state_t *state)
{
    char *file_key = calloc(DETERMINISTIC_KEY_SIZE + 1, sizeof(char));
    if (!file_key) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    if (generate_file_key(state->env->encrypt_options->mnemonic,
                          state->bucket_id,
                          state->file_id, &file_key)) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }
    file_key[DETERMINISTIC_KEY_SIZE] = '\0';

    uint8_t *decrypt_key = calloc(SHA256_DIGEST_SIZE + 1, sizeof(uint8_t));
    if (!decrypt_key) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    sha256_of_str((uint8_t *)file_key, DETERMINISTIC_KEY_SIZE, decrypt_key);
    decrypt_key[SHA256_DIGEST_SIZE] = '\0';

    memset_zero(file_key, DETERMINISTIC_KEY_SIZE + 1);
    free(file_key);

    state->decrypt_key = decrypt_key;

    uint8_t *file_id_hash = calloc(RIPEMD160_DIGEST_SIZE + 1, sizeof(uint8_t));
    if (!file_id_hash) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }
    ripemd160_of_str((uint8_t *)state->file_id,
                     strlen(state->file_id), file_id_hash);
    file_id_hash[RIPEMD160_DIGEST_SIZE] = '\0';

    uint8_t *decrypt_ctr = calloc(AES_BLOCK_SIZE, sizeof(uint8_t));
    if (!decrypt_ctr) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }
    memcpy(decrypt_ctr, file_id_hash, AES_BLOCK_SIZE);

    free(file_id_hash);

    state->decrypt_ctr = decrypt_ctr;
}

static void determine_decryption_key(storj_download_state_t *state)
{
    if (!state->env->encrypt_options ||
        !state->env->encrypt_options->mnemonic) {

        state->decrypt_key = NULL;
        state->decrypt_ctr = NULL;
    } else {
        if (state->info->index) {
            // calculate decryption key based on the index
            determine_decryption_key_v1(state);
        } else {
            // calculate decryption key based on the file_id
            determine_decryption_key_v0(state);
        }
    };
}

static void after_request_info(uv_work_t *work, int status)
{
    file_info_request_t *req = work->data;

    req->state->pending_work_count--;
    req->state->requesting_info = false;

    if (status != 0) {
        req->state->error_status = STORJ_BRIDGE_FILEINFO_ERROR;
    } else if (req->status_code == 200 || req->status_code == 304) {
        req->state->info = req->info;
        if (req->info->erasure) {
            if (strcmp(req->info->erasure, "reedsolomon") == 0) {
                req->state->rs = true;
                req->state->truncated = false;
            } else {
                req->state->error_status = STORJ_FILE_UNSUPPORTED_ERASURE;
            }
        }

        // Now that we have info we can calculate the decryption key
        determine_decryption_key(req->state);

    } else if (req->error_status) {
        switch(req->error_status) {
            case STORJ_BRIDGE_REQUEST_ERROR:
            case STORJ_BRIDGE_INTERNAL_ERROR:
                req->state->info_fail_count += 1;
                break;
            default:
                req->state->error_status = req->error_status;
                break;
        }
        if (req->state->info_fail_count >= STORJ_MAX_INFO_TRIES) {
            req->state->info_fail_count = 0;
            req->state->error_status = req->error_status;
        }
    } else {
        req->state->error_status = STORJ_BRIDGE_FILEINFO_ERROR;
    }

    queue_next_work(req->state);

    free(req);
    free(work);

}

static void request_info(uv_work_t *work)
{
    file_info_request_t *req = work->data;
    storj_download_state_t *state = req->state;

    int path_len = 9 + strlen(req->bucket_id) + 7 + strlen(req->file_id) + 5;
    char *path = calloc(path_len + 1, sizeof(char));
    if (!path) {
        req->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    strcat(path, "/buckets/");
    strcat(path, req->bucket_id);
    strcat(path, "/files/");
    strcat(path, req->file_id);
    strcat(path, "/info");

    int status_code = 0;
    struct json_object *response = NULL;
    int request_status = fetch_json(req->http_options,
                                    req->options,
                                    "GET",
                                    path,
                                    NULL,
                                    true,
                                    &response,
                                    &status_code);

    req->status_code = status_code;

    state->log->debug(state->env->log_options,
                      state->handle,
                      "fn[request_info] - JSON Response: %s",
                      json_object_to_json_string(response));

    if (request_status) {
        req->error_status = STORJ_BRIDGE_REQUEST_ERROR;
        state->log->warn(state->env->log_options, state->handle,
                         "Request file info error: %i", request_status);

    } else if (status_code == 200 || status_code == 304) {

        req->info = malloc(sizeof(storj_file_meta_t));
        req->info->created = NULL;
        req->info->filename = NULL;
        req->info->mimetype = NULL;
        req->info->erasure = NULL;
        req->info->size = 0;
        req->info->hmac = NULL;
        req->info->id = NULL;
        req->info->decrypted = false;
        req->info->index = NULL;

        struct json_object *erasure_obj;
        struct json_object *erasure_value;
        char *erasure = NULL;
        if (json_object_object_get_ex(response, "erasure", &erasure_obj)) {
            if (json_object_object_get_ex(erasure_obj, "type", &erasure_value)) {
                erasure = (char *)json_object_get_string(erasure_value);
            }   else {
                state->log->warn(state->env->log_options, state->handle,
                                 "value missing from erasure response");
            }
        }

        if (erasure) {
            req->info->erasure = strdup(erasure);
        }

        struct json_object *index_value;
        char *index = NULL;
        if (json_object_object_get_ex(response, "index", &index_value)) {
            index = (char *)json_object_get_string(index_value);
        }

        if (index) {
            req->info->index = strdup(index);
        }

        struct json_object *hmac_obj;
        if (!json_object_object_get_ex(response, "hmac", &hmac_obj)) {
            state->log->warn(state->env->log_options, state->handle,
                             "hmac missing from response");
            goto clean_up;
        }
        if (!json_object_is_type(hmac_obj, json_type_object)) {
            state->log->warn(state->env->log_options, state->handle,
                             "hmac not an object");
            goto clean_up;
        }

        // check the type of hmac
        struct json_object *hmac_type;
        if (!json_object_object_get_ex(hmac_obj, "type", &hmac_type)) {
            state->log->warn(state->env->log_options, state->handle,
                             "hmac.type missing from response");
            goto clean_up;
        }
        if (!json_object_is_type(hmac_type, json_type_string)) {
            state->log->warn(state->env->log_options, state->handle,
                             "hmac.type not a string");
            goto clean_up;
        }
        char *hmac_type_str = (char *)json_object_get_string(hmac_type);
        if (0 != strcmp(hmac_type_str, "sha512")) {
            state->log->warn(state->env->log_options, state->handle,
                             "hmac.type is unknown");
            goto clean_up;
        }

        // get the hmac value
        struct json_object *hmac_value;
        if (!json_object_object_get_ex(hmac_obj, "value", &hmac_value)) {
            state->log->warn(state->env->log_options, state->handle,
                             "hmac.value missing from response");
            goto clean_up;
        }
        if (!json_object_is_type(hmac_value, json_type_string)) {
            state->log->warn(state->env->log_options, state->handle,
                             "hmac.value not a string");
            goto clean_up;
        }
        char *hmac = (char *)json_object_get_string(hmac_value);
        req->info->hmac = strdup(hmac);

    } else if (status_code == 403 || status_code == 401) {
        req->error_status = STORJ_BRIDGE_AUTH_ERROR;
    } else if (status_code == 404 || status_code == 400) {
        req->error_status = STORJ_BRIDGE_FILE_NOTFOUND_ERROR;
    } else if (status_code == 500) {
        req->error_status = STORJ_BRIDGE_INTERNAL_ERROR;
    } else {
        req->error_status = STORJ_BRIDGE_REQUEST_ERROR;
    }

clean_up:
    if (response) {
        json_object_put(response);
    }
    free(path);
}

static void queue_request_info(storj_download_state_t *state)
{
    if (state->requesting_info || state->canceled) {
        return;
    }

    uv_work_t *work = malloc(sizeof(uv_work_t));
    if (!work) {
        state->error_status = STORJ_MEMORY_ERROR;
        return;
    }

    state->requesting_info = true;

    file_info_request_t *req = malloc(sizeof(file_info_request_t));
    req->http_options = state->env->http_options;
    req->options = state->env->bridge_options;
    req->status_code = 0;
    req->bucket_id = state->bucket_id;
    req->file_id = state->file_id;
    req->error_status = 0;
    req->info = NULL;
    req->state = state;

    work->data = req;

    state->pending_work_count++;
    int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                               request_info,
                               after_request_info);
    if (status) {
        state->error_status = STORJ_QUEUE_ERROR;
        return;
    }

}

static int prepare_file_hmac(storj_download_state_t *state)
{
    // initialize the hmac with the decrypt key
    struct hmac_sha512_ctx hmac_ctx;
    hmac_sha512_set_key(&hmac_ctx, SHA256_DIGEST_SIZE, state->decrypt_key);

    for (int i = 0; i < state->total_pointers; i++) {

        storj_pointer_t *pointer = &state->pointers[i];

        if (!pointer->shard_hash ||
            strlen(pointer->shard_hash) != RIPEMD160_DIGEST_SIZE * 2) {
            return 1;
        }

        struct base16_decode_ctx base16_ctx;
        base16_decode_init(&base16_ctx);

        size_t decode_len = 0;
        uint8_t hash[RIPEMD160_DIGEST_SIZE];
        if (!base16_decode_update(&base16_ctx,
                                  &decode_len,
                                  hash,
                                  RIPEMD160_DIGEST_SIZE * 2,
                                  (uint8_t *)pointer->shard_hash)) {
            return 1;

        }
        if (!base16_decode_final(&base16_ctx) ||
            decode_len != RIPEMD160_DIGEST_SIZE) {
            return 1;
        }
        hmac_sha512_update(&hmac_ctx, RIPEMD160_DIGEST_SIZE, hash);
    }

    uint8_t digest_raw[SHA512_DIGEST_SIZE];
    hmac_sha512_digest(&hmac_ctx, SHA512_DIGEST_SIZE, digest_raw);

    size_t digest_len = BASE16_ENCODE_LENGTH(SHA512_DIGEST_SIZE);
    state->hmac = calloc(digest_len + 1, sizeof(char));
    if (!state->hmac) {
        return 1;
    }

    base16_encode_update((uint8_t *)state->hmac, SHA512_DIGEST_SIZE, digest_raw);

    return 0;
}

static bool has_missing_shard(storj_download_state_t *state)
{
    bool missing = false;
    for (int i = 0; i < state->total_pointers; i++) {
        storj_pointer_t *pointer = &state->pointers[i];
        if (pointer->status == POINTER_MISSING) {
            missing = true;
        }
    }
    return missing;
}

static bool can_recover_shards(storj_download_state_t *state)
{
    if (state->pointers_completed) {
        uint32_t missing_pointers = 0;

        for (int i = 0; i < state->total_pointers; i++) {
            storj_pointer_t *pointer = &state->pointers[i];
            if (pointer->status == POINTER_MISSING) {
                missing_pointers += 1;
            }
        }

        if (missing_pointers > state->total_parity_pointers) {
            return false;
        }
    }

    return true;
}

static void after_recover_shards(uv_work_t *work, int status)
{
    file_request_recover_t *req = work->data;
    storj_download_state_t *state = req->state;

    state->pending_work_count--;
    state->recovering_shards = false;
    state->truncated = true;

    if (status != 0) {
        req->state->error_status = STORJ_QUEUE_ERROR;
    } else if (req->error_status) {
        req->state->error_status = req->error_status;
    } else {
        // Recovery was successful and the pointers have been finished
        for (int i = 0; i < state->total_pointers; i++) {
            state->pointers[i].status = POINTER_FINISHED;
            state->completed_shards += 1;
        }
    }

    queue_next_work(state);

    memset_zero(req->decrypt_key, SHA256_DIGEST_SIZE);
    free(req->decrypt_key);

    memset_zero(req->decrypt_ctr, AES_BLOCK_SIZE);
    free(req->decrypt_ctr);

    free(req->zilch);
    free(req);
    free(work);
}

static void recover_shards(uv_work_t *work)
{
    file_request_recover_t *req = work->data;
    storj_download_state_t *state = req->state;
    reed_solomon* rs = NULL;
    uint8_t *data_map = NULL;
    uint8_t **data_blocks = NULL;
    uint8_t **fec_blocks = NULL;

    int error = 0;

    struct aes256_ctx ctx;
    uint64_t bytes_decrypted = 0;
    size_t len = AES_BLOCK_SIZE * 8;

    // Make sure that the file is the correct size before recovering
    // shards in case that the last shard is the one being recovered.
#ifdef _WIN32

    HANDLE prefile = (HANDLE)_get_osfhandle(req->fd);
    if (prefile == INVALID_HANDLE_VALUE) {
        req->error_status = STORJ_FILE_RESIZE_ERROR;
        return;
    }

    LARGE_INTEGER presize;
    presize.HighPart = (uint32_t)((req->filesize & 0xFFFFFFFF00000000LL) >> 32);
    presize.LowPart = (uint32_t)(req->filesize & 0xFFFFFFFFLL);

    if (!SetFilePointerEx(prefile, presize, 0, FILE_BEGIN)) {
        req->error_status = STORJ_FILE_RESIZE_ERROR;
        return;
    }

    if (!SetEndOfFile(prefile)) {
        req->error_status = STORJ_FILE_RESIZE_ERROR;
        return;
    }

#else
    if (ftruncate(req->fd, req->filesize)) {
        // errno for more details
        req->error_status = STORJ_FILE_RESIZE_ERROR;
    }
#endif

    error = map_file(req->fd, req->filesize, &data_map, false);
    if (error) {
        req->error_status = STORJ_MAPPING_ERROR;
        goto finish;
    }

    if (!req->has_missing) {
        goto decrypt;
    }

    fec_init();

    rs = reed_solomon_new(req->data_shards, req->parity_shards);
    if (!rs) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto finish;
    }

    data_blocks = (uint8_t**)malloc(req->data_shards * sizeof(uint8_t *));
    if (!data_blocks) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto finish;
    }

    fec_blocks = (uint8_t**)malloc(req->parity_shards * sizeof(uint8_t *));
    if (!fec_blocks) {
        req->error_status = STORJ_MEMORY_ERROR;
        goto finish;
    }

    for (int i = 0; i < req->data_shards; i++) {
        data_blocks[i] = data_map + i * req->shard_size;
    }

    for (int i = 0; i < req->parity_shards; i++) {
        fec_blocks[i] = data_map + (req->data_shards + i) * req->shard_size;
    }

    uint32_t total_shards = req->data_shards + req->parity_shards;

    state->log->debug(state->env->log_options, state->handle,
                      "Recovering shards, data_shards: %i, "            \
                      "parity_shards: %i, shard_size: %" PRIu64 ", "    \
                      "file_size: %" PRIu64,
                      req->data_shards,
                      req->parity_shards,
                      req->shard_size,
                      req->data_filesize);

    error = reed_solomon_reconstruct(rs, data_blocks, fec_blocks,
                                     req->zilch, total_shards,
                                     req->shard_size, req->data_filesize);

    if (error) {
        req->error_status = STORJ_FILE_RECOVER_ERROR;
        goto finish;
    }


decrypt:

    aes256_set_encrypt_key(&ctx, req->decrypt_key);

    while (bytes_decrypted < req->data_filesize) {

        if (bytes_decrypted + len > req->data_filesize) {
            len = req->data_filesize - bytes_decrypted;
        }

        ctr_crypt(&ctx, (nettle_cipher_func *)aes256_encrypt,
                  AES_BLOCK_SIZE, req->decrypt_ctr,
                  len,
                  (uint8_t *)data_map + bytes_decrypted,
                  (uint8_t *)data_map + bytes_decrypted);

        bytes_decrypted += len;
    }

finish:
    if (data_map) {
        error = unmap_file(data_map, req->filesize);
        if (error) {
            req->error_status = STORJ_UNMAPPING_ERROR;
        }
    }

    if (data_blocks) {
        free(data_blocks);
    }

    if (fec_blocks) {
        free(fec_blocks);
    }

    if (rs) {
        reed_solomon_release(rs);
    }

#ifdef _WIN32

    HANDLE file = (HANDLE)_get_osfhandle(req->fd);
    if (file == INVALID_HANDLE_VALUE) {
        req->error_status = STORJ_FILE_RESIZE_ERROR;
        return;
    }

    LARGE_INTEGER size;
    size.HighPart = (uint32_t)((req->data_filesize & 0xFFFFFFFF00000000LL) >> 32);
    size.LowPart = (uint32_t)(req->data_filesize & 0xFFFFFFFFLL);

    if (!SetFilePointerEx(file, size, 0, FILE_BEGIN)) {
        req->error_status = STORJ_FILE_RESIZE_ERROR;
        return;
    }

    if (!SetEndOfFile(file)) {
        req->error_status = STORJ_FILE_RESIZE_ERROR;
        return;
    }

#else
    if (ftruncate(req->fd, req->data_filesize)) {
        // errno for more details
        req->error_status = STORJ_FILE_RESIZE_ERROR;
    }
#endif

}

static void queue_recover_shards(storj_download_state_t *state)
{
    if (!state->recovering_shards && state->pointers_completed) {

        int total_missing = 0;
        bool has_missing = false;
        bool is_ready = true;

        uint8_t *zilch = (uint8_t *)calloc(1, state->total_pointers);

        for (int i = 0; i < state->total_pointers; i++) {
            storj_pointer_t *pointer = &state->pointers[i];
            if (pointer->status == POINTER_MISSING) {
                total_missing += 1;
                has_missing = true;
                zilch[i] = 1;
            }

            if (pointer->status != POINTER_MISSING &&
                pointer->status != POINTER_DOWNLOADED) {
                is_ready = false;
                state->log->debug(state->env->log_options,
                                  state->handle,
                                  "Pointer %i not ready with status: %i",
                                  i, pointer->status);

            }
        }

        if (!is_ready) {
            free(zilch);
            return;
        }

        state->log->info(state->env->log_options,
                         state->handle,
                         "Queuing recovery of %i of %i shards",
                         total_missing, state->total_shards);

        file_request_recover_t *req = malloc(sizeof(file_request_recover_t));
        if (!req) {
            state->error_status = STORJ_MEMORY_ERROR;
            return;
        }

        uv_work_t *work = malloc(sizeof(uv_work_t));
        if (!work) {
            state->error_status = STORJ_MEMORY_ERROR;
            return;
        }

        req->fd = fileno(state->destination);
        req->filesize = state->shard_size * state->total_pointers;
        req->data_filesize = calculate_data_filesize(state);
        req->data_shards = state->total_pointers - state->total_parity_pointers;
        req->parity_shards = state->total_parity_pointers;
        req->shard_size = state->shard_size;
        req->zilch = zilch;
        req->has_missing = has_missing;

        if (state->decrypt_key && state->decrypt_ctr) {
            req->decrypt_key = calloc(SHA256_DIGEST_SIZE, sizeof(uint8_t));
            if (!req->decrypt_key) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }
            req->decrypt_ctr = calloc(AES_BLOCK_SIZE, sizeof(uint8_t));
            if (!req->decrypt_ctr) {
                state->error_status = STORJ_MEMORY_ERROR;
                return;
            }
            memcpy(req->decrypt_key, state->decrypt_key, SHA256_DIGEST_SIZE);
            memcpy(req->decrypt_ctr, state->decrypt_ctr, AES_BLOCK_SIZE);

            increment_ctr_aes_iv(req->decrypt_ctr, 0);
        } else {
            req->decrypt_key = NULL;
            req->decrypt_ctr = NULL;
        }

        req->state = state;
        req->error_status = 0;

        work->data = req;

        state->pending_work_count++;
        int status = uv_queue_work(state->env->loop, (uv_work_t*) work,
                                   recover_shards, after_recover_shards);

        if (status) {
            state->error_status = STORJ_QUEUE_ERROR;
            return;
        }

        state->recovering_shards = true;
    }
}

static void queue_next_work(storj_download_state_t *state)
{
    // report any errors
    if (state->error_status != 0) {
        if (!state->finished && state->pending_work_count == 0) {

            state->finished = true;
            state->finished_cb(state->error_status,
                               state->destination,
                               state->handle);

            free_download_state(state);
        }

        return;
    }

    // report download complete
    if (state->pointers_completed &&
        state->completed_shards == state->total_shards &&
        state->truncated) {

        if (!state->finished && state->pending_work_count == 0) {

            // calculate the hmac of all shard hashes
            if (prepare_file_hmac(state)) {
                state->error_status = STORJ_FILE_GENERATE_HMAC_ERROR;
            }

            if (state->info && state->info->hmac) {
                if (0 != strcmp(state->info->hmac, state->hmac)) {
                    state->error_status = STORJ_FILE_DECRYPTION_ERROR;
                }
            } else {
                state->log->warn(state->env->log_options,
                                 state->handle,
                                 "Unable to verify decryption integrity" \
                                 ", missing hmac from file info.");
            }

            state->finished = true;
            state->finished_cb(state->error_status, state->destination, state->handle);

            free_download_state(state);
            return;
        }

        goto finish_up;
    }

    queue_request_pointers(state);

    if (!state->info) {
        queue_request_info(state);
    }

    if (state->info) {
        queue_request_shards(state);

        if (state->rs) {
            if (can_recover_shards(state)) {
                queue_recover_shards(state);
            } else {
                state->error_status = STORJ_FILE_SHARD_MISSING_ERROR;
                queue_next_work(state);
                return;
            }
        } else {
            if (!has_missing_shard(state)) {
                queue_recover_shards(state);
            } else {
                state->error_status = STORJ_FILE_SHARD_MISSING_ERROR;
                queue_next_work(state);
                return;
            }
        }
    }

    queue_send_exchange_reports(state);

finish_up:

    state->log->debug(state->env->log_options, state->handle,
                      "Pending work count: %d", state->pending_work_count);

}

STORJ_API int storj_bridge_resolve_file_cancel(storj_download_state_t *state)
{
    if (state->canceled) {
        return 0;
    }

    state->canceled = true;
    state->error_status = STORJ_TRANSFER_CANCELED;

    // loop over all pointers, and cancel any that are queued to be downloaded
    // any downloads that are in-progress will monitor the state->canceled
    // status and exit when set to true
    for (int i = 0; i < state->total_pointers; i++) {
        storj_pointer_t *pointer = &state->pointers[i];
        if (pointer->status == POINTER_BEING_DOWNLOADED) {
            uv_cancel((uv_req_t *)pointer->work);
        }
    }

    return 0;
}

STORJ_API storj_download_state_t *storj_bridge_resolve_file(storj_env_t *env,
                                                            const char *bucket_id,
                                                            const char *file_id,
                                                            FILE *destination,
                                                            void *handle,
                                                            storj_progress_cb progress_cb,
                                                            storj_finished_download_cb finished_cb)
{
    storj_download_state_t *state = malloc(sizeof(storj_download_state_t));
    if (!state) {
        return NULL;
    }

    // setup download state
    state->total_bytes = 0;
    state->info = NULL;
    state->requesting_info = false;
    state->info_fail_count = 0;
    state->env = env;
    state->file_id = file_id;
    state->bucket_id = bucket_id;
    state->destination = destination;
    state->progress_cb = progress_cb;
    state->finished_cb = finished_cb;
    state->finished = false;
    state->total_shards = 0;
    state->download_max_concurrency = STORJ_DOWNLOAD_CONCURRENCY;
    state->completed_shards = 0;
    state->resolving_shards = 0;
    state->total_pointers = 0;
    state->total_parity_pointers = 0;
    state->rs = false;
    state->recovering_shards = false;
    state->truncated = true;
    state->pointers = NULL;
    state->pointers_completed = false;
    state->pointer_fail_count = 0;
    state->requesting_pointers = false;
    state->error_status = STORJ_TRANSFER_OK;
    state->writing = false;
    state->shard_size = 0;
    state->excluded_farmer_ids = NULL;
    state->hmac = NULL;
    state->pending_work_count = 0;
    state->canceled = false;
    state->log = env->log;
    state->handle = handle;
    state->decrypt_key = NULL;
    state->decrypt_ctr = NULL;

    // start download
    queue_next_work(state);

    return state;
}
