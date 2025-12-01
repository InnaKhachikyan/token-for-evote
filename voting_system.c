#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "rsa.h"
#include "paillier.h"

#define NONCE_BYTES 16
#define MAX_VOTERS 38
#define VOTING_DURATION_SECONDS (10 * 60)

static int verify_signature(const BIGNUM *m, const BIGNUM *s,
                            const BIGNUM *N, const BIGNUM *e, BN_CTX *ctx) {
    int res = 0;
    BIGNUM *m_check = BN_new();
    if (!m_check) return 0;

    if (!BN_mod_exp(m_check, s, e, N, ctx)) {
        BN_free(m_check);
        return 0;
    }

    res = (BN_cmp(m_check, m) == 0);
    BN_free(m_check);
    return res;
}

