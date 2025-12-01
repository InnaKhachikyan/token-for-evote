#ifndef PAILLIER_H
#define PAILLIER_H

#include <stdint.h>

typedef unsigned long long u64;

typedef struct {
    u64 n;
    u64 n_squared;
    u64 g;
} Paillier_pub_key;

typedef struct {
    u64 lambda;
    u64 l_u;
} Paillier_priv_key;

u64 gcd_u64(u64 a, u64 b);
u64 lcm_u64(u64 a, u64 b);
u64 mod_mul(u64 a, u64 b, u64 mod);
u64 exp_mod(u64 base, u64 exp, u64 mod);
u64 mod_inv(u64 a, u64 m);

void paillier_keygen(u64 p, u64 q,
                     Paillier_pub_key *pubKey,
                     Paillier_priv_key *privKey);

u64 paillier_encrypt(u64 m, u64 r, const Paillier_pub_key *pubKey);
u64 paillier_decrypt(u64 c, const Paillier_pub_key *pubKey,
                     const Paillier_priv_key *privKey);

u64 rand_u64();
u64 rand_range(u64 min, u64 max);
u64 random_prime_in_range(u64 min, u64 max);
u64 random_coprime(u64 n);

#endif

