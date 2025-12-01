#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "rsa.h"
#include "token_generation.h"

#define VOTING_DURATION_SECONDS (15 * 60)
#define NUM_STUDENTS 38

BIGNUM *g_public_n = NULL;
BIGNUM *g_public_e = NULL;
static BIGNUM *s_private_d = NULL;

static const char *STUDENT_IDS[] = {
    "arthur_aghamyan",
    "nane_andreasyan",
    "eduard_aramyan",
    "artashes_atanesyan",
    "alik_avakyan",
    "lilit_babakhanyan",
    "erik_badalyan",
    "anahit_baghramyan",
    "hrach_davtyan",
    "mikayel_davtyan",
    "narek_galstyan",
    "sofiya_gasparyan",
    "meri_gasparyan",
    "milena_ghazaryan",
    "levon_ghukasyan",
    "yeghiazar_grigoryan",
    "karine_grigoryan",
    "anna_hakhnazaryan",
    "davit_hakobyan",
    "vahe_hayrapetyan",
    "ruzanna_hunanyan",
    "vahe_jraghatspanyan",
    "inna_khachikyan",
    "siranush_makhmuryan",
    "anush_margaryan",
    "yevgine_mnatsakanyan",
    "narek_otaryan",
    "vahe_sahakyan",
    "davit_sahakyan",
    "vahe_sargsyan",
    "ruben_sargsyan",
    "ararat_saribekyan",
    "diana_stepanyan",
    "mikayel_yeganyan",
    "anahit_yeghiazaryan",
    "sedrak_yerznkyan",
    "khachik_zakaryan"
};

bool token_generated[NUM_STUDENTS] = {false};

static int find_student_index(const char *id) {
    for (int i = 0; i < NUM_STUDENTS; i++) {
        if (strcmp(STUDENT_IDS[i], id) == 0) {
            return i;
        }
    }
    return -1;
}

static bool all_students_done(void) {
    for (int i = 0; i < NUM_STUDENTS; i++) {
        if (!token_generated[i]) {
            return false;
        }
    }
    return true;
}

static void free_keys(void) {
    if (g_public_n) {
        BN_free(g_public_n);
        g_public_n = NULL;
    }
    if (g_public_e) {
        BN_free(g_public_e);
        g_public_e = NULL;
    }
    if (s_private_d) {
        BN_free(s_private_d);
        s_private_d = NULL;
    }
}


int system_blind_sign(const BIGNUM *m_blinded, BIGNUM **s_blinded_out) {
    if (!m_blinded || !s_private_d || !g_public_n || !s_blinded_out) {
        return 0;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return 0;
    }

    BIGNUM *s = BN_new();
    if (!s) {
        BN_CTX_free(ctx);
        return 0;
    }

    if (!rsa_decrypt(m_blinded, g_public_n, s_private_d, s, ctx)) {
        BN_free(s);
        BN_CTX_free(ctx);
        return 0;
    }

    *s_blinded_out = s;
    BN_CTX_free(ctx);
    return 1;
}

