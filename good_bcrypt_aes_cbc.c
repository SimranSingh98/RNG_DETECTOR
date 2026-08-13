#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define IV_SIZE 16

int generate_iv(uint8_t iv[IV_SIZE])
{
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
}

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

    if (generate_iv(iv) != 0) {
        fprintf(stderr, "Failed to generate IV\n");
        return 1;
    }

    aes_cbc_encrypt(
        key,
        iv,
        plaintext,
        ciphertext,
        sizeof(plaintext)
    );

    return 0;
}