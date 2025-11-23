#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "rsa.h"

#define RSA_BITS 2048

typedef struct {
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
} RSAKeyPair;

int init_random(void) {
    if (RAND_status() != 1) {
        unsigned char seed[32];
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (urandom) {
            if (fread(seed, 1, sizeof(seed), urandom) == sizeof(seed)) {
                RAND_seed(seed, sizeof(seed));
            }
            fclose(urandom);
        }
        if (RAND_status() != 1) {
            fprintf(stderr, "CSPRNG not properly seeded.\n");
            return 0;
        }
    }
    return 1;
}

int generate_keypair(RSAKeyPair *keypair, int bits) {
    return rsa_generate_keypair(&keypair->n, &keypair->e, &keypair->d, bits);
}

void free_keypair(RSAKeyPair *keypair) {
    if (keypair->n) BN_free(keypair->n);
    if (keypair->e) BN_free(keypair->e);
    if (keypair->d) BN_free(keypair->d);
    keypair->n = NULL;
    keypair->e = NULL;
    keypair->d = NULL;
}

void print_keypair(const RSAKeyPair *keypair) {
    printf("=== Public Key ===\n");
    printf("n (modulus)  = 0x");
    BN_print_fp(stdout, keypair->n);
    printf("\n");
    printf("e (exponent) = 0x");
    BN_print_fp(stdout, keypair->e);
    printf("\n\n");

    printf("=== Private Key ===\n");
    printf("d (exponent) = 0x");
    BN_print_fp(stdout, keypair->d);
    printf("\n\n");
}

int encrypt_message(const BIGNUM *plaintext, const RSAKeyPair *keypair, BIGNUM **ciphertext_out) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed.\n");
        return 0;
    }

    BIGNUM *ciphertext = BN_new();
    if (!ciphertext) {
        fprintf(stderr, "BN_new failed.\n");
        BN_CTX_free(ctx);
        return 0;
    }

    if (!rsa_encrypt(plaintext, keypair->n, keypair->e, ciphertext, ctx)) {
        fprintf(stderr, "Encryption failed.\n");
        BN_free(ciphertext);
        BN_CTX_free(ctx);
        return 0;
    }

    *ciphertext_out = ciphertext;
    BN_CTX_free(ctx);
    return 1;
}

int decrypt_message(const BIGNUM *ciphertext, const RSAKeyPair *keypair, BIGNUM **plaintext_out) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed.\n");
        return 0;
    }

    BIGNUM *plaintext = BN_new();
    if (!plaintext) {
        fprintf(stderr, "BN_new failed.\n");
        BN_CTX_free(ctx);
        return 0;
    }

    if (!rsa_decrypt(ciphertext, keypair->n, keypair->d, plaintext, ctx)) {
        fprintf(stderr, "Decryption failed.\n");
        BN_free(plaintext);
        BN_CTX_free(ctx);
        return 0;
    }

    *plaintext_out = plaintext;
    BN_CTX_free(ctx);
    return 1;
}

BIGNUM *string_to_bn(const char *hex_str) {
    BIGNUM *bn = NULL;
    if (!BN_hex2bn(&bn, hex_str)) {
        return NULL;
    }
    return bn;
}

int main(void) {
    if (!init_random()) {
        return 1;
    }

    RSAKeyPair keypair = {0};

    printf("Generating %d-bit RSA keypair...\n\n", RSA_BITS);
    if (!generate_keypair(&keypair, RSA_BITS)) {
        fprintf(stderr, "Key generation failed.\n");
        return 1;
    }

    print_keypair(&keypair);

    printf("Enter plaintext as HEX (no 0x prefix, must be < n):\n");
    printf("m = ");

    char hex_input[4096];
    if (!fgets(hex_input, sizeof(hex_input), stdin)) {
        fprintf(stderr, "Failed to read input.\n");
        free_keypair(&keypair);
        return 1;
    }

    size_t len = strlen(hex_input);
    while (len > 0 && (hex_input[len-1] == '\n' || hex_input[len-1] == '\r')) {
        hex_input[--len] = '\0';
    }

    BIGNUM *plaintext = string_to_bn(hex_input);
    if (!plaintext) {
        fprintf(stderr, "Failed to parse plaintext.\n");
        free_keypair(&keypair);
        return 1;
    }

    if (BN_cmp(plaintext, keypair.n) >= 0) {
        fprintf(stderr, "Plaintext must be strictly less than n.\n");
        BN_free(plaintext);
        free_keypair(&keypair);
        return 1;
    }

    BIGNUM *ciphertext = NULL;
    printf("\nEncrypting...\n");
    if (!encrypt_message(plaintext, &keypair, &ciphertext)) {
        BN_free(plaintext);
        free_keypair(&keypair);
        return 1;
    }

    printf("Ciphertext:\n");
    printf("c = 0x");
    BN_print_fp(stdout, ciphertext);
    printf("\n");

    BIGNUM *decrypted = NULL;
    printf("\nDecrypting...\n");
    if (!decrypt_message(ciphertext, &keypair, &decrypted)) {
        BN_free(plaintext);
        BN_free(ciphertext);
        free_keypair(&keypair);
        return 1;
    }

    printf("Decrypted plaintext:\n");
    printf("m' = 0x");
    BN_print_fp(stdout, decrypted);
    printf("\n");

    if (BN_cmp(plaintext, decrypted) == 0) {
        printf("\n[OK] Decryption successful! m' == m\n");
    } else {
        printf("\n[ERROR] Decryption failed! m' != m\n");
    }

    BN_free(plaintext);
    BN_free(ciphertext);
    BN_free(decrypted);
    free_keypair(&keypair);

    return 0;
}

