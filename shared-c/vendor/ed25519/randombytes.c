/*
 * randombytes.c — Platform CSPRNG for TweetNaCl
 *
 * TweetNaCl expects a function: void randombytes(uint8_t *buf, uint64_t len)
 * We implement it using /dev/urandom (Unix) or BCryptGenRandom (Windows).
 */

#include <stdint.h>
#include <stddef.h>

#if defined(__APPLE__) || defined(__linux__) || defined(__unix__)

#include <fcntl.h>
#include <unistd.h>

void randombytes(unsigned char *buf, unsigned long long len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return;

    size_t total = 0;
    while (total < (size_t)len) {
        ssize_t n = read(fd, buf + total, (size_t)len - total);
        if (n <= 0) break;
        total += (size_t)n;
    }
    close(fd);
}

#elif defined(_WIN32)

#include <windows.h>
#include <bcrypt.h>

void randombytes(unsigned char *buf, unsigned long long len) {
    BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

#else
#error "Unsupported platform for randombytes"
#endif
