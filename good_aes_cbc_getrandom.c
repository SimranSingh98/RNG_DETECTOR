#include <stdio.h>
#include <stdint.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <sys/random.h>
#endif

#define IV_SIZE 16


/*
 * Generate a cryptographically suitable IV.
 *
 * Windows:
 *     BCryptGenRandom()
 *
 * Linux:
 *     getrandom()
 */
int generate_iv(uint8_t iv[IV_SIZE])
{
#ifdef _WIN32

    NTSTATUS status = BCryptGenRandom(
        NULL,
        iv,
        IV_SIZE,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    if (status != 0) {
        return -1;
    }

    return 0;

#else

    ssize_t n = getrandom(iv, IV_SIZE, 0);

    if (n != IV_SIZE) {
        return -1;
    }

    return 0;

#endif
}


/*
 * Placeholder for AES-CBC.
 *
 * We are NOT implementing AES yet.
 *
 * The purpose of this program is to demonstrate:
 *
 *     RNG
 *      |
 *      v
 *     IV
 *      |
 *      v
 *   AES-CBC
 */
void aes_cbc_encrypt(
    const uint8_t key[16],
    const uint8_t iv[IV_SIZE],
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t len)
{
    (void)key;
    (void)iv;
    (void)plaintext;
    (void)ciphertext;
    (void)len;

    printf("AES-CBC operation completed\n");
}


int main(void)
{
    uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };

    uint8_t iv[IV_SIZE];

    uint8_t plaintext[16] = {
        'H', 'e', 'l', 'l',
        'o', ' ', 'C', 'r',
        'y', 'p', 't', 'o',
        '!', '!', '!', '!'
    };

    uint8_t ciphertext[16] = {0};


    /*
     * Step 1:
     * Generate random IV.
     */
    if (generate_iv(iv) != 0) {
        fprintf(stderr, "Failed to generate IV\n");
        return 1;
    }


    /*
     * Step 2:
     * Use the random IV with AES-CBC.
     */
    aes_cbc_encrypt(
        key,
        iv,
        plaintext,
        ciphertext,
        sizeof(plaintext)
    );

    return 0;
}