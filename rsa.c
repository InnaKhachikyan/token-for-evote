#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/rand.h>

#define RSA_BITS 2048

int rsa_generate_keypair(BIGNUM **n_out, BIGNUM **e_out, BIGNUM **d_out, int bits) {
    int ret = 0;

    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *phi = NULL, *p1 = NULL, *q1 = NULL;
    BIGNUM *g = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;

    ctx = BN_CTX_new();
    if (!ctx) goto done;

    p   = BN_new();
    q   = BN_new();
    phi = BN_new();
    p1  = BN_new();
    q1  = BN_new();
    g   = BN_new();
    n   = BN_new();
    e   = BN_new();
    d   = BN_new();

    if (!p || !q || !phi || !p1 || !q1 || !g || !n || !e || !d) goto done;

    if (!BN_set_word(e, 65537)) goto done;

    int prime_bits = bits / 2;

    while (1) {
        if (!BN_generate_prime_ex(p, prime_bits, 0, NULL, NULL, NULL)) goto done;
        if (!BN_generate_prime_ex(q, prime_bits, 0, NULL, NULL, NULL)) goto done;

        if (BN_cmp(p, q) == 0) continue;

        if (!BN_copy(p1, p)) goto done;
        if (!BN_sub_word(p1, 1)) goto done;
        if (!BN_copy(q1, q)) goto done;
        if (!BN_sub_word(q1, 1)) goto done;
        if (!BN_mul(phi, p1, q1, ctx)) goto done;

        if (!BN_gcd(g, e, phi, ctx)) goto done;

        if (BN_is_one(g)) {
            break;
        }
    }

    if (!BN_mul(n, p, q, ctx)) goto done;

    if (!BN_mod_inverse(d, e, phi, ctx)) goto done;

    *n_out = n;  n = NULL;
    *e_out = e;  e = NULL;
    *d_out = d;  d = NULL;

    ret = 1;

done:
    if (p)   BN_free(p);
    if (q)   BN_free(q);
    if (phi) BN_free(phi);
    if (p1)  BN_free(p1);
    if (q1)  BN_free(q1);
    if (g)   BN_free(g);
    if (n)   BN_free(n);
    if (e)   BN_free(e);
    if (d)   BN_free(d);
    if (ctx) BN_CTX_free(ctx);
    return ret;
}

int rsa_encrypt(const BIGNUM *m, const BIGNUM *n, const BIGNUM *e, BIGNUM *c_out, BN_CTX *ctx) {
    if (!BN_mod_exp(c_out, m, e, n, ctx)) {
        return 0;
    }
    return 1;
}

int rsa_decrypt(const BIGNUM *c, const BIGNUM *n, const BIGNUM *d, BIGNUM *m_out, BN_CTX *ctx) {
    if (!BN_mod_exp(m_out, c, d, n, ctx)) {
        return 0;
    }
    return 1;
}

static BIGNUM *read_hex_bn(const char *prompt) {
    char buf[4096];

    printf("%s", prompt);
    if (!fgets(buf, sizeof(buf), stdin)) {
        return NULL;
    }

    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r')) {
        buf[--len] = '\0';
    }
    if (len == 0) {
        return NULL;
    }

    BIGNUM *bn = NULL;
    if (!BN_hex2bn(&bn, buf)) {
        return NULL;
    }
    return bn;
}

int main(void) {
    if (RAND_status() != 1) { // the rand func should be seeded
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
            return 1;
        }
    }

    printf("Generating %d-bit RSA keypair...\n", RSA_BITS);

    BIGNUM *n = NULL, *e = NULL, *d = NULL;
    if (!rsa_generate_keypair(&n, &e, &d, RSA_BITS)) {
        fprintf(stderr, "Key generation failed.\n");
        return 1;
    }

    printf("\n=== Public key ===\n");
    printf("n (modulus)  = 0x");
    BN_print_fp(stdout, n);
    printf("\n");
    printf("e (exponent) = 0x");
    BN_print_fp(stdout, e);
    printf("\n");

    printf("\n=== Private key ===\n");
    printf("d (exponent) = 0x");
    BN_print_fp(stdout, d);
    printf("\n\n");

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        fprintf(stderr, "BN_CTX_new failed.\n");
        BN_free(n);
        BN_free(e);
        BN_free(d);
        return 1;
    }

    printf("Enter plaintext as HEX (must be < n):\n");
    BIGNUM *m = read_hex_bn("m = 0x");
    if (!m) {
        fprintf(stderr, "Failed to read plaintext.\n");
        BN_free(n);
        BN_free(e);
        BN_free(d);
        BN_CTX_free(ctx);
        return 1;
    }

    if (BN_cmp(m, n) >= 0) {
        fprintf(stderr, "Plaintext must be strictly less than n.\n");
        BN_free(m);
        BN_free(n);
        BN_free(e);
        BN_free(d);
        BN_CTX_free(ctx);
        return 1;
    }

    BIGNUM *c = BN_new();
    BIGNUM *m_dec = BN_new();
    if (!c || !m_dec) {
        fprintf(stderr, "BN_new failed.\n");
        if (c) BN_free(c);
        if (m_dec) BN_free(m_dec);
        BN_free(m);
        BN_free(n);
        BN_free(e);
        BN_free(d);
        BN_CTX_free(ctx);
        return 1;
    }

    if (!rsa_encrypt(m, n, e, c, ctx)) {
        fprintf(stderr, "Encryption failed.\n");
        goto cleanup;
    }

    printf("\nCiphertext:\n");
    printf("c = 0x");
    BN_print_fp(stdout, c);
    printf("\n");

    if (!rsa_decrypt(c, n, d, m_dec, ctx)) {
        fprintf(stderr, "Decryption failed.\n");
        goto cleanup;
    }

    printf("\nDecrypted plaintext:\n");
    printf("m' = 0x");
    BN_print_fp(stdout, m_dec);
    printf("\n");

    if (BN_cmp(m, m_dec) == 0) {
        printf("\n[OK] m' == m (decryption correct)\n");
    } else {
        printf("\n[!] m' != m (something is wrong)\n");
    }

cleanup:
    BN_free(m);
    BN_free(c);
    BN_free(m_dec);
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_CTX_free(ctx);

    return 0;
}

