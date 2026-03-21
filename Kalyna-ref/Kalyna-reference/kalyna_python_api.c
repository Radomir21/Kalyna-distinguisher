#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "kalyna.h"

void EncipherRound(kalyna_t* ctx);
void AddRoundKey(int round, kalyna_t* ctx);
void XorRoundKey(int round, kalyna_t* ctx);

#ifdef _WIN32
#define API_EXPORT __declspec(dllexport)
#else
#define API_EXPORT
#endif

static int bytes_to_words_checked(
    const uint8_t* in_bytes,
    size_t word_count,
    uint64_t* out_words
) {
    if (in_bytes == NULL || out_words == NULL) {
        return -1;
    }

    memcpy(out_words, in_bytes, word_count * sizeof(uint64_t));
    return 0;
}

static int words_to_bytes_checked(
    const uint64_t* in_words,
    size_t word_count,
    uint8_t* out_bytes
) {
    if (in_words == NULL || out_bytes == NULL) {
        return -1;
    }

    memcpy(out_bytes, in_words, word_count * sizeof(uint64_t));
    return 0;
}

/*
 * Повне шифрування одного блока.
 * Повертає:
 *   0  -> успіх
 *  -1  -> некоректні аргументи
 *  -2  -> KalynaInit failed
 */
API_EXPORT int kalyna_encrypt_block_api(
    const uint8_t* plaintext,
    const uint8_t* key,
    int block_size_bits,
    int key_size_bits,
    uint8_t* ciphertext
) {
    kalyna_t* ctx = NULL;
    uint64_t* pt_words = NULL;
    uint64_t* key_words = NULL;
    uint64_t* ct_words = NULL;
    size_t nb_words;
    size_t nk_words;
    int status = 0;

    if (plaintext == NULL || key == NULL || ciphertext == NULL) {
        return -1;
    }

    ctx = KalynaInit((size_t)block_size_bits, (size_t)key_size_bits);
    if (ctx == NULL) {
        return -2;
    }

    nb_words = ctx->nb;
    nk_words = ctx->nk;

    pt_words = (uint64_t*)calloc(nb_words, sizeof(uint64_t));
    key_words = (uint64_t*)calloc(nk_words, sizeof(uint64_t));
    ct_words = (uint64_t*)calloc(nb_words, sizeof(uint64_t));

    if (pt_words == NULL || key_words == NULL || ct_words == NULL) {
        status = -1;
        goto cleanup;
    }

    if (bytes_to_words_checked(plaintext, nb_words, pt_words) != 0) {
        status = -1;
        goto cleanup;
    }

    if (bytes_to_words_checked(key, nk_words, key_words) != 0) {
        status = -1;
        goto cleanup;
    }

    KalynaKeyExpand(key_words, ctx);
    KalynaEncipher(pt_words, ctx, ct_words);

    if (words_to_bytes_checked(ct_words, nb_words, ciphertext) != 0) {
        status = -1;
        goto cleanup;
    }

cleanup:
    free(pt_words);
    free(key_words);
    free(ct_words);

    if (ctx != NULL) {
        KalynaDelete(ctx);
    }

    return status;
}

/*
 * Reduced-round версія.
 * rounds = 1..ctx->nr
 *
 * Логіка взята прямо з KalynaEncipher:
 *   AddRoundKey(0)
 *   for round = 1..ctx->nr-1:
 *       EncipherRound
 *       XorRoundKey(round)
 *   final EncipherRound
 *   AddRoundKey(ctx->nr)
 *
 * Для reduced-round робимо:
 *   rounds = 1:
 *       AddRoundKey(0)
 *       EncipherRound
 *       XorRoundKey(1)
 *
 *   rounds = 2:
 *       AddRoundKey(0)
 *       EncipherRound + XorRoundKey(1)
 *       EncipherRound + XorRoundKey(2)
 *
 * Тобто після кожного "внутрішнього" раунду повертаємо state.
 *
 * Якщо rounds == ctx->nr, повертаємо повний ciphertext.
 */
API_EXPORT int kalyna_encrypt_rounds_api(
    const uint8_t* plaintext,
    const uint8_t* key,
    int block_size_bits,
    int key_size_bits,
    int rounds,
    uint8_t* ciphertext
) {
    kalyna_t* ctx = NULL;
    uint64_t* pt_words = NULL;
    uint64_t* key_words = NULL;
    uint64_t* out_words = NULL;
    size_t nb_words;
    size_t nk_words;
    int round;
    int status = 0;

    if (plaintext == NULL || key == NULL || ciphertext == NULL) {
        return -1;
    }

    ctx = KalynaInit((size_t)block_size_bits, (size_t)key_size_bits);
    if (ctx == NULL) {
        return -2;
    }

    if (rounds < 1 || rounds > (int)ctx->nr) {
        status = -1;
        goto cleanup;
    }

    nb_words = ctx->nb;
    nk_words = ctx->nk;

    pt_words = (uint64_t*)calloc(nb_words, sizeof(uint64_t));
    key_words = (uint64_t*)calloc(nk_words, sizeof(uint64_t));
    out_words = (uint64_t*)calloc(nb_words, sizeof(uint64_t));

    if (pt_words == NULL || key_words == NULL || out_words == NULL) {
        status = -1;
        goto cleanup;
    }

    if (bytes_to_words_checked(plaintext, nb_words, pt_words) != 0) {
        status = -1;
        goto cleanup;
    }

    if (bytes_to_words_checked(key, nk_words, key_words) != 0) {
        status = -1;
        goto cleanup;
    }

    KalynaKeyExpand(key_words, ctx);

    memcpy(ctx->state, pt_words, nb_words * sizeof(uint64_t));

    AddRoundKey(0, ctx);

    for (round = 1; round <= rounds; ++round) {
        EncipherRound(ctx);

        if (round < (int)ctx->nr) {
            XorRoundKey(round, ctx);
        } else {
            AddRoundKey(ctx->nr, ctx);
        }
    }

    memcpy(out_words, ctx->state, nb_words * sizeof(uint64_t));

    if (words_to_bytes_checked(out_words, nb_words, ciphertext) != 0) {
        status = -1;
        goto cleanup;
    }

cleanup:
    free(pt_words);
    free(key_words);
    free(out_words);

    if (ctx != NULL) {
        KalynaDelete(ctx);
    }

    return status;
}