#include "../src/utils.h"
#include "../src/crypto.h"

test_ripemd160sha256_as_string()
{
    char *data_as_str = "0011223344556677889900112233445566778899";
    uint8_t *data = str2hex(RIPEMD160_DIGEST_SIZE * 2, data_as_str);

    char digest[RIPEMD160_DIGEST_SIZE * 2 + 1];
    memset(digest, 0, RIPEMD160_DIGEST_SIZE * 2 + 1);

    printf("input:\n");
    printf("  data:");
    for(int i = 0; i < RIPEMD160_DIGEST_SIZE; i++)
    {
        printf(" %02x", data[i]);
    }
    printf("\n");

    ripemd160sha256_as_string(data, RIPEMD160_DIGEST_SIZE, digest);

    printf("output:\n");
    printf("  digest:");
    for(int i = 0; i < RIPEMD160_DIGEST_SIZE; i++)
    {
        printf(" %x", digest[i]);
    }
    printf("\n");
}

int main()
{
    printf("\n\n----BEGIN TEST ripemd160sha256_as_string----\n");
    test_ripemd160sha256_as_string();
    printf("----END TEST ripemd160sha256_as_string----\n\n");
}
