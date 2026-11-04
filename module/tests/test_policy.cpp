#include "policy.hpp"
#include "sha256.hpp"
#include <stdio.h>
#include <stdlib.h>

static unsigned checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static bool select(const char *config, unsigned uid, const char *name, NianchuTarget *target, bool *found)
{
    char text[16385];
    size_t size = strlen(config);
    if (size > 16384) return false;
    memcpy(text, config, size);
    return nianchu_select(text, size, uid, name, target, found);
}

static void hash_test(const char *input, size_t size, const char *expected)
{
    NianchuSha256 hash;
    for (size_t i = 0; i < size;) {
        size_t n = size - i > 13 ? 13 : size - i;
        hash.update(reinterpret_cast<const unsigned char *>(input + i), n);
        i += n;
    }
    unsigned char digest[32];
    hash.finish(digest);
    char hex[65];
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; ++i) {
        hex[i * 2] = digits[digest[i] >> 4];
        hex[i * 2 + 1] = digits[digest[i] & 15];
    }
    hex[64] = 0;
    CHECK(!strcmp(hex, expected));
}

int main()
{
    NianchuTarget target = {};
    bool found;
    const char *valid = "# default off\n10123 com.example.test 100 14725 wait\n110123 com.example.test:worker 0 31415 resume\n";
    CHECK(select(valid, 10123, "com.example.test", &target, &found) && found);
    CHECK(target.uid == 10123 && target.delay_ms == 100 && target.port == 14725 && target.wait);
    CHECK(select(valid, 10123, "com.example.test:worker", &target, &found) && !found);
    CHECK(select(valid, 10124, "com.example.test", &target, &found) && !found);
    CHECK(select(valid, 110123, "com.example.test:worker", &target, &found) && found && !target.wait);
    CHECK(select("# empty\n", 10123, "com.example.test", &target, &found) && !found);
    CHECK(select("10123\tcom.example.test\t60000\t65535\tresume\r\n", 10123, "com.example.test", &target, &found) && found);
    const char *invalid[] = {
        "1000 system_server 100 14725 wait", "0 com.example.test 100 14725 wait",
        "99000 com.example.test 100 14725 wait", "20000 com.example.test 100 14725 wait",
        "10123 com.example.* 100 14725 wait", "10123 com.example.test 60001 14725 wait",
        "10123 com.example.test -1 14725 wait", "10123 com.example.test 100 65536 wait",
        "10123 com.example.test 100 1 wait", "10123 com.example.test 100 14725 unknown",
        "10123 com.example.test 100 14725 wait extra", "10123 com.example.test 100",
        "99999999999999999999999999999999 com.example.test 100 14725 wait",
        "10123 com.example.test 100 14725 wait\n10123 com.example.test 0 31415 resume",
        "10123 com.example.test 100 14725 wait\ninvalid trailing row"
    };
    for (const char *row : invalid) CHECK(!select(row, 10123, "com.example.test", &target, &found));
    char nul[] = {'#', 0, 'a', 0};
    CHECK(!nianchu_select(nul, 3, 10123, "com.example.test", &target, &found));
    unsigned number;
    CHECK(nianchu_number("2147483647", 2147483647, &number) && number == 2147483647);
    CHECK(!nianchu_number("2147483648", 2147483647, &number));
    CHECK(!nianchu_number("", 65535, &number));
    hash_test("", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    hash_test("abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char *multi = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    hash_test(multi, strlen(multi), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    char repeated[1000];
    memset(repeated, 'a', sizeof(repeated));
    hash_test(repeated, sizeof(repeated), "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3");
    printf("PASS module native policy/hash: %u checks\n", checks);
    return 0;
}
