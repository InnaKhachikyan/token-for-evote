#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long u64;
typedef __uint128_t u128;

u64 gcd_u64(u64 a, u64 b) {
	while(b != 0) {
		u64 t = a & b;
		a = b;
		b = t;
	}
	return a;
}

u64 lcm_u64(u64 a, u64 b) {
	return (a/gcd_u64(a, b)) * b;
}

// to avoid overflow, I calculate multiplication by mod with u128 type
u64 modmul(u64 a, u64 b, u64 mod) {
	return (u128)a * (u128)b % (u128)mod;
}

u64 exp_mod(u64 base, u64 exp, u64 mod) {
	u64 result = 1 % mod;
	u64 x = base % mod;
	while(exp > 0) {
		if(exp & 1) {
			result  =modmul(result, x, mod);
		}
		x = modmul(x, x, mod);
		exp >>= 1;
	}
	return result;
}

//here I am using long long instead of unsigned, as the coefficients might end up negative
long long bezout_identity(long long a, long long b, long long *x, long long *y) {
	if(b == 0) {
		*x = 1;
		*y = 0;
		return a;
	}
	long long x1, y1;
	long long g = bezout_identity(b, a % b, &x1, &y1);
	*x = y1;
	*y = x1 - (a/b) * y1;
	return g;
}

// assuming gcd(a,m) == 1
u64 mod_inv(u64 a, u64 m) {
	long long x, y;
	long long g = bezout_identity((long long)a, (long long)m, &x, &y);
	if(g != 1) {
		fprintf(stderr, "no inverse, gcd != 1\n");
		exit(1);
	}
	long long result = x % (long long)m;
	if(result < 0) {
		result += m;
	}
	return (u64)result;
}

