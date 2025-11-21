#ifndef RSA_H
#define RSA_H

#include <openssl/bn.h>

int rsa_generate_keypair(BIGNUM **n_out, BIGNUM **e_out, BIGNUM **d_out, int bits);

int rsa_encrypt(const BIGNUM *m, const BIGNUM *n, const BIGNUM *e, BIGNUM *c_out, BN_CTX *ctx);

int rsa_decrypt(const BIGNUM *c, const BIGNUM *n, const BIGNUM *d, BIGNUM *m_out, BN_CTX *ctx);

#endif
