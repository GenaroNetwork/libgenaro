# DOC

## 编译

* CMakeLists.txt文件的"SET(DEBUG xx)"可以设置是否包含调试信息，以便调试。
* CMakeLists.txt文件的"SET(STATIC xx)"可以设置静态链接某些依赖库还是动态链接（PS：Windows系统中目前都是静态链接）。

## 调试信息

* 通过设置genaro_init_env函数的第四个参数log_options结构体（类型为genaro_log_options_t *）的level，可以设置调试信息的输出级别。
* 设置环境变量GENARO_DEBUG的值为1, 2, 3或4，可打印调试信息，级别分别为error, warn, info和debug（debug级别的调试信息最详细）。
* 设置环境GENARO_CURL_OUT_DIR可以将curl进行http通讯的过程打印到相应目录的_genaro_curl_debug.log文件中。

## 链接的库

* uv: A multi-platform support library with a focus on asynchronous I/O.(http://libuv.org)
* json-c: Implements a reference counting object model that allows you to easily construct JSON objects in C, output them as JSON formatted strings and parse JSON formatted strings back into the C representation of JSON objects.(https://github.com/json-c/json-c)
* gmp: The GNU Multiple Precision Arithmetic Library, it's a free library for arbitrary precision arithmetic, operating on signed integers, rational numbers, and floating-point numbers.(https://gmplib.org)
* nettle: A low-level cryptographic library.(http://www.lysator.liu.se/~nisse/nettle)
* curl: A client-side URL transfer library.(https://curl.haxx.se/libcurl)
* secp256k1: Optimized C library for EC operations on curve secp256k1.(https://github.com/bitcoin-core/secp256k1)
* scrypt: A shared library that implements scrypt() functionality - a replacement for bcrypt().(https://github.com/technion/libscrypt)
* keccak: Keccak-family hashing library.(https://github.com/maandree/libkeccak)

## 文件切片

切片在prepare_upload_state函数中进行，determine_shard_size函数用于确定切片大小。

`file_size`为文件大小，`shard_size`为每个分片的大小（除了最后一片大小<=`shard_size`，其他分片大小都=`shard_size`），`total_shards`为总分片数，`total_data_shards`为数据分片数，`total_parity_shards`为RS算法需要的额外分片数。

`shard_size`计算方法：

* 如果`file_size` <= 32M, 那么`shard_size` = 2M；
* 如果`file_size` > 32M 且 <= 64G, 首先得到整数n，保证`file_size`（单位：M）在(2^(n-1), 2^n]范围内，那么`shard_size` = 2^(n-4)；
* 如果`file_size` > 64G，那么`shard_size` = 4G。

`total_data_shards, total_parity_shards, total_shards`计算方法：

1. `total_data_shards = ceil(file_size / shard_size)`
2. `total_parity_shards = (file_size <= 2M) ? 0 : ceil(total_data_shards * 2.0 / 3)`
3. `total_shards = total_data_shards + total_parity_shards`

所以，`total_shards`的范围为：

* 当`file_size` <= 16M时，`shard_size`为2M，`total_data_shards`在在[1, 8]范围内，即`total_shards`在[1, 14]范围内；
* 当`file_size` > 16M 且 <= 64G时，`shard_size`（单位：M）在[2, 4 * 1024]范围内，且是2的n次方倍，并且`total_data_shards`在(8, 16]范围内，即`total_shards`在(14, 27]范围内；
* 当`file_size` > 64G时，`shard_size`为4G，`total_data_shards`在(16, +INFINITY)范围内，即`total_shards`在(27, +INFINITY)范围内。

## crypto.c

### int increment_ctr_aes_iv(uint8_t *iv, uint64_t bytes_position)

  计算n = bytes_position / AES_BLOCK_SIZE，然后将iv[0~15]看成一个unsigned short型(16字节，iv[0]为最高字节)的变量，函数的功能就是对该变量进行+n操作。

### encrypt_meta/decrypt_meta

  AES-256-GCM加密数据。

### encrypt_meta_hmac_sha256/decrypt_meta_hmac_sha256

  结合AES-256-GCM和HMAC-SHA512的加密，分别调用了encrypt_meta和decrypt_meta，用于加解密bucket名和文件名。

## AES加密和Reed-Solomn

  文件的加密用的是AES-256-CTR对称加密算法，文件的纠错用的是FEC编码算法中的Reed-Solomn算法：
  1. 如果文件小于或等于MIN_SHARD_SIZE，不使用Reed-Solomn算法，并会在对每个shard进行prepare_frame时直接加密后上传，所以上传的数据大小就是原始文件大小。
  2. 如果文件大于MIN_SHARD_SIZE，那么上传文件前会在系统的临时目录中生成以".crypt"为后缀的文件，该文件是通过AES-256-CTR加密的文件，然后生成以".parity"为后缀的文件，该文件是Reed-Solomn算法生成的文件（大约是源文件的2/3大小），上传时直接读取这两个文件的内容后上传，所以上传的数据大概是5/3原始文件大小。
  3. 如果下载过程中，shard存在丢失的情况，用Reed-Solomn算法

## 上传和下载文件

上传逻辑：

1. prepare_upload_state：计算每个shard的大小(会有其中1片不是这个大小)，一共多少个shards，是否需要Reed Solomon，将每个shard的状态置为AWAITING_PREPARE_FRAME，加密文件名等。（完成后，开始queue_next_work逐步进行上传操作，该函数在每个after_xxx函数的最后会调用一次）
2. 检查bucket id是否存在（GET /buckets/:id）。
3. 检查file name是否存在（GET /buckets/:id/file-ids/:filename）。
4. 获取frame id（POST /frames）。
5. 如果需要Reed Solomon（文件大于MIN_SHARD_SIZE），则调用create_encrypted_file在临时目录创建.crypt文件，该文件是经过AES的CTR模式256位加密后的文件，加密后的大小和源文件相等。（如果文件很大，时间可能较长，实际测试大概1 GB需要10s）
6. 如果需要Reed Solomon，则调用create_parity_shards在临时目录创建.parity文件。（非常耗时，实际测试1GB的文件，花了将近1min）
7. 以上1～6步骤是顺序执行的，执行完毕后并行执行如下操作：
  a) 同时对state->prepare_frame_limit（默认为1，根据代码注释，其作用是limit disk reads for dd and network activity）个shard进行prepare_frame操作，该函数为每个shard计算size，hash，challenges和Merkle tree（目前challenges数为4个，如果改为100个，实际测试，对于1 GB的文件，上传前的准备时间会增加25s左右），每完成对一个shard的prepare_frame，则将相应shard状态置为AWAITING_PUSH_FRAME。
  b) 对每个处于AWAITING_PUSH_FRAME的shard进行push_frame（PUT /frames/:frame_id）操作，bridge端收到该操作后会和矿工进行签约，将完成push_frame的shard的状态置为AWAITING_PUSH_SHARD。
  c) 对状态为AWAITING_PUSH_SHARD对shard进行push_shard操作，同时会新建一个异步的progress_put_shard函数调用progress回调函数。push_shard操作调用put_shard函数，该函数利用curl进行shard的上传，某个shard上传完毕后，state->completed_shards加1，并且该shard对应的发送报告的状态置为GENARO_REPORT_AWAITING_SEND。
  d) 当state->completed_shards等于state->total_shards时，调用create_bucket_entry（POST /buckets/:bucket_id/files），该函数完成后将state->completed_upload置为true。
  e) 对发送报告的状态为GENARO_REPORT_AWAITING_SEND的shard进行send_exchange_report操作（POST /reports/exchanges）。
  f) 当state->completed_upload为true时，调用cleanup_state释放内存，并调用传进来的finished回调函数。

上传过程中和bridge, farmer的http接口：

1. GET /buckets/:bucket_id（检查bucketid是否存在，和bridge）
2. GET /buckets/:bucket_id/file-ids/:filename（检查文件名是否存在，和bridge）
3. POST /frames（获取frame id，和bridge）
4. PUT /frames/:frame_id（和矿工签约，和bridge）
5. POST /shards/:shard_hash（上传shard，和farmer）
6. POST /buckets/:bucket_id/files（上传完毕，发送文件加密用的index等信息，和bridge）
7. POST /reports/exchanges（发送报告，和bridge）

下载逻辑：

1. request_pointers: 向bridge请求获取pointers（1个pointer代表1个shard），并保存到state->pointers变量中。（GET /buckets/:bucket_id/files/:file_id）
2. request_info: 向bridge请求获取文件大小等信息。（GET /buckets/:bucket_id/files/:file_id/info）
3. request_shard: 在request_info执行完成，向farmer请求下载shard数据，获取的数据直接写到下载的文件中的相应位置中，每次下载完1个shard后判断下载后的每个shard的哈希值是否和bridge中存储的hash值相等，如果不相等，将相应pointer的status置为POINTER_ERROR。（GET /shards/:shard_hash）
4. recover_shards：在所有shard下载完毕后，判断是否存在丢失（pointer状态为POINTER_MISSING）的shard，如果不存在则直接进行解密和truncate操作，如果存在且丢失的shard数小于等于total_parity_shards，那么用Reed-Solomn算法恢复数据，然后进行解密和truncate操作，如果丢失的shard数大于total_parity_shards，则无法恢复。
5. send_exchange_report：以上执行完毕后，对于每个pointer向bridge发送一个报告。（POST /reports/exchanges）

PS：pointer的报告发送给bridge后，将相应pointer的status置为POINTER_ERROR_REPORTED，然后再次queue_request_pointers时判断存在校验失败的shard，便调用request_replace_pointer向bridge请求替换的pointer，请求过程中会告诉bridge排除相应farmer，如果获取不到可替换的pointer或者经过多次替换pointer后下载得到的shard都校验失败，那么将pinter的status置为POINTER_MISSING。

下载过程中和bridge, farmer的http接口：

1. GET /buckets/:bucket_id/files/:file_id（获取文件的shards在哪些farmer上，和bridge）
2. GET /buckets/:bucket_id/files/:file_id/info（获取文件大小等信息，和bridge）
3. GET /shards/:shard_hash（下载shard，和farmer）
4. POST /reports/exchanges（发送报告，和bridge）

## 文件分享

为实现文件分享功能，在genaro_file_meta_t结构体中添加了rsaKey和rsaCtr字段，分别是经过RSA加密（也可以是其他加密方式）后的key/ctr（文件加解密的AES密钥），还有一个isShareFile字段，用于表示是否是通过分享得到的文件，目前cli程序暂不支持文件分享功能。
