For detailed method/struct description, please see [genaro.h](./src/genaro.h)   

usage example  

0. include header file

```c
#include "genaro.h"
```

1. first of all make an env object which will be used through most actions.

```c
genaro_bridge_options_t bridge_options = {
    .proto       = "http",
    .host        = "127.0.0.1",
    .port        = 8080
};

genaro_encrypt_options_t encrypt_options = {
    .priv_key = xxx;
    .key_len = xxx;
}

genaro_http_options_t http_options = {
    .user_agent = CLI_VERSION,
    .low_speed_limit = GENARO_LOW_SPEED_LIMIT,
    .low_speed_time = GENARO_LOW_SPEED_TIME,
    .timeout = GENARO_HTTP_TIMEOUT
}

genaro_log_options_t log_options = {
    .logger     = json_logger,
    .level      = 0
};

env = genaro_init_env(&bridge_options, &encrypt_options, &http_options, &log_options, false);
```

2. create bucket

```c
char *bucket_name = "new bucket";
genaro_bridge_create_bucket(env, bucket_name, NULL, create_bucket_callback);
```

3. get bucket list

```c
genaro_bridge_get_buckets(env, NULL, get_buckets_callback);
```

4. delete bucket

```c
char *bucket_id = "abcd...";
genaro_bridge_delete_bucket(env, bucket_id, NULL, delete_bucket_callback);
```

5. list files in a bucket

```c
char *bucket_id = "abcd...";
genaro_bridge_list_files(env, bucket_id, NULL, list_files_callback);
```

6. delete file

```c
char *bucket_id = "abcd...";
char *file_id = "abcd...";

genaro_bridge_delete_file(env, bucket_id, file_id, NULL, delete_file_callback);
```

7. download

```c
char *bucket_id = "abcd..."; 
char *file_id = "abcd...";
char *path = "/usr/user/download/download.file";
char *renamed_path = "/usr/user/download/download.file.genarotmp";

FILE *fd = NULL;
fd = fopen(path, "w+");

genaro_bridge_resolve_file(env, bucket_id, file_id, NULL, path,
                           renamed_path, fd, true, NULL,
                           download_file_onprogress_callback,
                           download_file_complete_callback);
```

8. upload

```c
char *bucket_id = "368be0816766b28fd5f43af5";
char *file_id = "998960317b6725a3f8080c2b";
char *path = "/usr/user/download/upload.file"; // file full path

FILE *fd = NULL;
fd = fopen(path, "r");
const char *file_name = "upload.file"; // file name in bucket

char *prepare_frame_limit = getenv("GENARO_PREPARE_FRAME_LIMIT");
char *push_frame_limit = getenv("GENARO_PUSH_FRAME_LIMIT");
char *push_shard_limit = getenv("GENARO_PUSH_SHARD_LIMIT");
char *rs = getenv("GENARO_REED_SOLOMON");
struct {} upload_opts = {
        int prepare_frame_limit = (prepare_frame_limit) ? atoi(prepare_frame_limit) : 1,
        int push_frame_limit = (push_frame_limit) ? atoi(push_frame_limit) : 64,
        int push_shard_limit = (push_shard_limit) ? atoi(push_shard_limit) : 64,
        bool rs = (!rs) ? true : (strcmp(rs, "false") == 0) ? false : true,
        const char *bucket_id = bucket_id,
        const char *file_name = file_name,
        const char *fd = fd
}

genaro_encryption_info_t *encryption_info = genaro_generate_encryption_info(env, NULL, bucket_id);
genaro_bridge_store_file(env, &upload_opts, encryption_info->index,
                         encryption_info->key_ctr_as_str, NULL, NULL,
                         upload_file_onprogress_callback,
                         upload_file_complete_callback);
```

9. get basic information

```c
genaro_bridge_get_info(env, NULL, get_info_callback);
```
