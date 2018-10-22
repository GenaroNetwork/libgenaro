# FAQ

## 关于文件的切片

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
