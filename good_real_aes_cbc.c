#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#define AES_BLOCK_SIZE 16

int generate_iv(unsigned char *iv)
{
    NTSTATUS status;

    status = BCryptGenRandom(
        NULL,
        iv,
        AES_BLOCK_SIZE,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );

    return status == 0 ? 0 : -1;
}

int aes_cbc_encrypt(
    const unsigned char *key,
    unsigned char *iv,
    const unsigned char *plaintext,
    unsigned char *ciphertext,
    ULONG len)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    NTSTATUS status;
    DWORD keyObjectSize = 0;
    DWORD dataSize = 0;
    DWORD result = 0;

    unsigned char keyObject[256];

    status = BCryptOpenAlgorithmProvider(
        &hAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0
    );

    if (status != 0)
        return -1;

    status = BCryptSetProperty(
        hAlg,
        BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0
    );

    if (status != 0)
        goto cleanup;

    status = BCryptGetProperty(
        hAlg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&keyObjectSize,
        sizeof(keyObjectSize),
        &dataSize,
        0
    );

    if (status != 0 || keyObjectSize > sizeof(keyObject))
        goto cleanup;

    status = BCryptGenerateSymmetricKey(
        hAlg,
        &hKey,
        keyObject,
        keyObjectSize,
        (PUCHAR)key,
        16,
        0
    );

    if (status != 0)
        goto cleanup;

    /*
     * BCryptEncrypt() modifies the IV buffer.
     * Therefore make a copy so that our original IV remains available
     * for printing/debugging.
     */
    unsigned char ivCopy[AES_BLOCK_SIZE];
    memcpy(ivCopy, iv, AES_BLOCK_SIZE);

    status = BCryptEncrypt(
        hKey,
        (PUCHAR)plaintext,
        len,
        NULL,
        ivCopy,
        AES_BLOCK_SIZE,
        ciphertext,
        len,
        &result,
        0
    );

cleanup:

    if (hKey != NULL)
        BCryptDestroyKey(hKey);

    if (hAlg != NULL)
        BCryptCloseAlgorithmProvider(hAlg, 0);

    return status == 0 ? (int)result : -1;
}

int main(void)
{
    unsigned char key[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F
    };

    unsigned char iv[AES_BLOCK_SIZE];

    unsigned char plaintext[16] = {
        'A','B','C','D',
        'E','F','G','H',
        'I','J','K','L',
        'M','N','O','P'
    };

    unsigned char ciphertext[16];

    if (generate_iv(iv) != 0)
    {
        fprintf(stderr, "Failed to generate IV\n");
        return 1;
    }

    int result = aes_cbc_encrypt(
        key,
        iv,
        plaintext,
        ciphertext,
        sizeof(plaintext)
    );

    if (result < 0)
    {
        fprintf(stderr, "AES-CBC encryption failed\n");
        return 1;
    }

    printf("AES-CBC encryption completed\n");

    printf("IV: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        printf("%02X", iv[i]);

    printf("\n");

    printf("Ciphertext: ");
    for (int i = 0; i < AES_BLOCK_SIZE; i++)
        printf("%02X", ciphertext[i]);

    printf("\n");

    return 0;
}