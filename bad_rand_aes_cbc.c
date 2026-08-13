#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define IV_SIZE 16

/*
 * BAD EXAMPLE
 *
 * rand() is a general-purpose pseudo-random number generator.
 * It is not suitable for generating cryptographic material.
 */
int generate_iv(uint8_t iv[IV_SIZE])
{
    for (int i = 0; i < IV_SIZE; i++) {
        iv[i] = (uint8_t)(rand() & 0xFF);
    }

    return 0;
}


/*
 * Placeholder for AES-CBC.
 *
 * The actual AES implementation is not important yet.
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