#include "utils.h"

void print_int_array(uint8_t *array, unsigned length, bool is_hex)
{
    printf("{");
    for (int i = 0; i < length; i++) {
        if(is_hex)
            printf("%02x", array[i]);
        else
            printf("%i", array[i]);
        if (i != length - 1) {
            printf(",");
        }
    }
    printf("}\n");
}

char *hex_to_str(size_t length, uint8_t *data)
{
    char *result = (char *)calloc(length * 2 + 1, sizeof(char));

    char byte[3];
    for(int i = 0; i < length; i++) {
        sprintf(byte, "%02x", data[i]);
        strcat(result, byte);
    }

    return result;
}

char *hex_encode_to_str(size_t length, uint8_t *data)
{
    size_t encode_len = BASE16_ENCODE_LENGTH(length);
    uint8_t *result = calloc(encode_len + 1, sizeof(uint8_t));
    if (!result) {
        return NULL;
    }

    base16_encode_update((char *)result, length, data);

    return (char *)result;
}

uint8_t *str_decode_to_hex(size_t length, const char *data)
{
    char *result = calloc(BASE16_DECODE_LENGTH(length) + 1, sizeof(char));
    if (!result) {
        return NULL;
    }

    struct base16_decode_ctx *ctx = malloc(sizeof(struct base16_decode_ctx));
    base16_decode_init(ctx);

    size_t decode_len = 0;
    if (!base16_decode_update(ctx, &decode_len, (uint8_t *)result,
                              length, data)) {
        free(result);
        free(ctx);
        return NULL;
    }

    if (!base16_decode_final(ctx)) {
        free(result);
        free(ctx);
        return NULL;
    }

    free(ctx);
    return (uint8_t *)result;
}

char *str_concat_many(int count, ...)
{
    int length = 1;

    va_list args;
    va_start(args, count);
    for (int i = 0; i < count; i++) {
        char *item = va_arg(args, char *);
        length += strlen(item);
    }
    va_end(args);

    char *combined = calloc(length, sizeof(char));
    if (!combined) {
        return NULL;
    }

    va_start(args, count);
    for (int i = 0; i < count; i++) {
        char *item = va_arg(args, char *);
        strcat(combined, item);
    }
    va_end(args);

    return combined;
}

void random_buffer(uint8_t *buf, size_t len)
{
#ifdef _WIN32
    HCRYPTPROV hProvider;
    int ret = CryptAcquireContext(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    assert(ret);
    ret = CryptGenRandom(hProvider, len, buf);
    assert(ret);
    CryptReleaseContext(hProvider, 0);
#else
    static FILE *frand = NULL;
    if (!frand) {
        frand = fopen("/dev/urandom", "r");
    }
    size_t len_read = fread(buf, 1, len, frand);
    (void)len_read;
    assert(len_read == len);
#endif
}

uint64_t shard_size(int hops)
{
    return MIN_SHARD_SIZE * pow(2, hops);
};

uint64_t get_time_milliseconds() {
#ifdef _WIN32

    // Time between windows epoch and standard epoch
    const int64_t time_to_epoch = 116444736000000000LL;

    FILETIME ft;

    GetSystemTimeAsFileTime(&ft);

    LARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    li.QuadPart -= time_to_epoch;
    li.QuadPart /= 10000;

    uint64_t milliseconds = li.QuadPart;
#else
    struct timeval t;
    gettimeofday(&t, NULL);
    uint64_t milliseconds = t.tv_sec * 1000LL + t.tv_usec / 1000;
#endif

    return milliseconds;
}

void memset_zero(void *v, size_t n)
{
#ifdef _WIN32
    SecureZeroMemory(v, n);
#else
    volatile unsigned char *p = v;
    while (n--) {
        *p++ = 0;
    }
#endif
}

uint64_t determine_shard_size(uint64_t file_size, int accumulator)
{
    if (file_size <= 0) {
        return 0;
    }

    accumulator = accumulator ? accumulator : 0;

    // Determine hops back by accumulator
    int hops = ((accumulator - SHARD_MULTIPLES_BACK) < 0 ) ?
        0 : accumulator - SHARD_MULTIPLES_BACK;

    uint64_t byte_multiple = shard_size(accumulator);
    double check = (double) file_size / byte_multiple;

    // Determine if bytemultiple is highest bytemultiple that is still <= size
    if (check > 0 && check <= 1) {
        while (hops > 0 && shard_size(hops) > MAX_SHARD_SIZE) {
            hops = hops - 1 <= 0 ? 0 : hops - 1;
        }

        return shard_size(hops);
    }

    // Maximum of 2 ^ 41 * 8 * 1024 * 1024
    if (accumulator > 41) {
        return 0;
    }

    return determine_shard_size(file_size, ++accumulator);
}

#ifdef _WIN32
ssize_t pread(int fd, void *buf, size_t count, uint64_t offset)
{
    long unsigned int read_bytes = 0;

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(OVERLAPPED));

    overlapped.OffsetHigh = (uint32_t)((offset & 0xFFFFFFFF00000000LL) >> 32);
    overlapped.Offset = (uint32_t)(offset & 0xFFFFFFFFLL);

    HANDLE file = (HANDLE)_get_osfhandle(fd);
    SetLastError(0);
    bool RF = ReadFile(file, buf, count, &read_bytes, &overlapped);

     // For some reason it errors when it hits end of file so we don't want to check that
    if ((RF == 0) && GetLastError() != ERROR_HANDLE_EOF) {
        errno = GetLastError();
        // printf ("Error reading file : %d\n", GetLastError());
        return -1;
    }

    return read_bytes;
}

ssize_t pwrite(int fd, const void *buf, size_t count, uint64_t offset)
{
    long unsigned int written_bytes = 0;

    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(OVERLAPPED));

    overlapped.OffsetHigh = (uint32_t)((offset & 0xFFFFFFFF00000000LL) >> 32);
    overlapped.Offset = (uint32_t)(offset & 0xFFFFFFFFLL);

    HANDLE file = (HANDLE)_get_osfhandle(fd);
    SetLastError(0);
    bool RF = WriteFile(file, buf, count, &written_bytes, &overlapped);
    if ((RF == 0)) {
        errno = GetLastError();
        // printf ("Error reading file :%d\n", GetLastError());
        return -1;
    }

    return written_bytes;
}
#endif

int allocatefile(int fd, uint64_t length)
{
#ifdef _WIN32
    HANDLE file = (HANDLE)_get_osfhandle(fd);
    if (file == INVALID_HANDLE_VALUE) {
        return EBADF;
    }

    int status = 0;

    LARGE_INTEGER size;
    size.HighPart = (uint32_t)((length & 0xFFFFFFFF00000000LL) >> 32);
    size.LowPart = (uint32_t)(length & 0xFFFFFFFFLL);

    if (!SetFilePointerEx(file, size, 0, FILE_BEGIN)) {
        status = GetLastError();
        goto win_finished;
    }

    if (!SetEndOfFile(file)) {
        status = GetLastError();
        goto win_finished;
    }

win_finished:

    return status;
#elif HAVE_POSIX_FALLOCATE
    return posix_fallocate(fd, 0, length);
#elif __unix__
    if (fallocate(fd, 0, 0, length)) {
        return errno;
    }
    return 0;
#elif __linux__
    if (fallocate(fd, 0, 0, length)) {
        return errno;
    }
    return 0;
#elif __APPLE__
    fstore_t store = {F_ALLOCATECONTIG, F_PEOFPOSMODE, 0, length, 0};
    // Try to get a continous chunk of disk space
    int ret = fcntl(fd, F_PREALLOCATE, &store);
    if (-1 == ret) {
        // OK, perhaps we are too fragmented, allocate non-continuous
        store.fst_flags = F_ALLOCATEALL;
        ret = fcntl(fd, F_PREALLOCATE, &store);
        if ( -1 == ret) {
            return -1;
        }
    }
    return ftruncate(fd, length);
#else
    return -1;
#endif
}

int unmap_file(uint8_t *map, uint64_t filesize)
{
#ifdef _WIN32
    if (!FlushViewOfFile(map, filesize)) {
        return GetLastError();
    }
    if (!UnmapViewOfFile(map)) {
        return GetLastError();
    }
#else
    if (munmap(map, filesize)) {
        return errno;
    }
#endif
    return 0;
}

int map_file(int fd, uint64_t filesize, uint8_t **map, bool read_only)
{
    int status = 0;
#ifdef _WIN32
    HANDLE fh = (HANDLE)_get_osfhandle(fd);
    if (fh == INVALID_HANDLE_VALUE) {
        return EBADF;
    }

    int prot = read_only ? PAGE_READONLY : PAGE_READWRITE;

    HANDLE mh = CreateFileMapping(fh, NULL, prot, 0, 0, NULL);
    if (!mh) {
        status = GetLastError();
        goto win_finished;
    }

    prot = read_only ? FILE_MAP_READ : FILE_MAP_WRITE;

    *map = MapViewOfFileEx(mh, prot, 0, 0, filesize, NULL);
    if (!*map) {
        status = GetLastError();
        goto win_finished;
    }

win_finished:
    CloseHandle(mh);
#else
    int prot = read_only ? PROT_READ : PROT_READ | PROT_WRITE;
    *map = (uint8_t *)mmap(NULL, filesize, prot, MAP_SHARED, fd, 0);
    if (*map == MAP_FAILED) {
        status = errno;
    }
#endif
    return status;
}

size_t read_file(const char *file_path, char **buffer)
{
    FILE *fp;
    fp = fopen(file_path, "r");
    if (fp == NULL) {
		return 0;
    }

    fseek(fp, 0, SEEK_END);
    size_t fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    *buffer = (char *)calloc(fsize + 1, sizeof(char));
    if (*buffer == NULL) {
		return 0;
    }

    size_t read_blocks = 0;
    while ((!feof(fp)) && (!ferror(fp))) {
        read_blocks = fread(*buffer + read_blocks, 1, fsize, fp);
        if (read_blocks <= 0) {
            break;
        }
    }

    int error = ferror(fp);
    fclose(fp);

    if (error) {
		free(*buffer);
		return 0;
    }

    return fsize;
}
