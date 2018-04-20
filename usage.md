More use methods please see [genaro.h](./src/genaro.h)   

调用方法  

0. 引用头文件
```
#include "genaro.h"
```

1. 生成 env 
```
genaro_bridge_options_t bridge_options = {
    const char *proto       = "http",
    const char *host        = "127.0.0.1",
    int port                = "8080",
    const char *user        = "account@example.com",
    const char *pass        = "password",
    const char *apikey      = "xx0000000000000000000000000000000000000000",
    const char *secretkey   = "xx0000000000000000000000000000000000000000"
};

genaro_encrypt_options encrypt_options = {
    const char *mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
}

genaro_http_options_t http_options = {
    const char *user_agent      = "user_agent",
    const char *proxy_url       = "",
    const char *cainfo_path     = "",
    uint64_t low_speed_limit    = GENARO_LOW_SPEED_LIMIT,
    uint64_t low_speed_time     = GENARO_LOW_SPEED_TIME,
    uint64_t timeout            = GENARO_HTTP_TIMEOUT
}

genaro_log_options_t log_options = {
    genaro_logger_fn logger     = json_logger,
    int level                   = 0
};

env = genaro_init_env(&bridge_options, &encrypt_options, &http_options, &log_options);
```
其中，除注册以外，调用其他方法是所使用的 env， 【user + pass】 与 【apikey + secretkey】 仅需提供其一


2. 注册
```
char *user = "account@example.com";
char *pass = "password";
struct {
    char *user;
    char *pass;
    char *host;
    char *mnemonic;
    char *key;
} user_opts = {
    .user       = user,
    .pass       = pass,
    .host       = "127.0.0.1",
    .mnemonic   = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    .key        = NULL
}
genaro_bridge_register(env, user, pass, &user_opts, register_callback);
```

3. 新建 bucket
```
char *bucket_name = "new bucket";
genaro_bridge_create_bucket(env, bucket_name, NULL, create_bucket_callback);
```

4. 获取 bucket 列表
```
genaro_bridge_get_buckets(env, NULL, get_buckets_callback);
```

5. 删除 bucket
```
char *bucket_id = "abcd..."; // genaro_bridge_get_buckets 回调
genaro_bridge_delete_bucket(env, bucket_id, NULL, delete_bucket_callback);
```

6. 获取 bucket 下的文件
```
char *bucket_id = "abcd..."; // genaro_bridge_get_buckets 回调
genaro_bridge_list_files(env, bucket_id, NULL, list_files_callback);
```

7. 删除文件
```
char *bucket_id = "abcd..."; // genaro_bridge_get_buckets 回调
char *file_id = "abcd..."; // genaro_bridge_list_files 回调

genaro_bridge_delete_file(env, bucket_id, file_id, NULL, delete_file_callback);
```

8. 下载文件
```
char *bucket_id = "abcd..."; // genaro_bridge_get_buckets 回调
char *file_id = "abcd..."; // genaro_bridge_list_files 回调
char *path = "/usr/user/download/download.file"; // 文件下载路径 （需指定文件名）

FILE *fd = NULL;
fd = fopen(path, "w+");

genaro_bridge_resolve_file(env, bucket_id, file_id, fd, NULL,
                            download_file_onprogress_callback,
                            download_file_complete_callback);
```

9. 上传文件
```
char *bucket_id = "abcd..."; // genaro_bridge_get_buckets 回调
char *file_id = "abcd..."; // genaro_bridge_list_files 回调
char *path = "/usr/user/download/upload.file"; // 文件路径

FILE *fd = NULL;
fd = fopen(path, "r");
const char *file_name = "upload.file"; // 上传后的文件名

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
genaro_bridge_store_file(env, &upload_opts, NULL,
                            upload_file_onprogress_callback,
                            upload_file_complete_callback);
```

10. 获取信息
```
genaro_bridge_get_info(env, NULL, get_info_callback);
```
