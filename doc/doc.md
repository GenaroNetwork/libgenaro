# DOC

## 编译

* CMakeLists.txt文件的"SET(DEBUG xx)"可以设置是否包含调试信息，以便调试器进行调试。
* CMakeLists.txt文件的"SET(STATIC xx)"可以设置静态链接某些依赖库还是动态链接（P：Windows系统中目前都是静态链接）。

## 调试信息

* 通过设置genaro_init_env函数的第四个参数log_options结构体（类型为genaro_log_options_t *）的level，可以设置调试信息的输出级别。
* 设置环境变量GENARO_DEBUG为1可以打印更多额外信息。
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

## crypto库

* increment_ctr_aes_iv(uint8_t *iv, uint64_t bytes_position)
  计算n = bytes_position / AES_BLOCK_SIZE，然后将iv[0~15]看成一个unsigned short型(16字节，iv[0]为最高字节)的变量，函数的功能就是对该变量进行+n操作。
