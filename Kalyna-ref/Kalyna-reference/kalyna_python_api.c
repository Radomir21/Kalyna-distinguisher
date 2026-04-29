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
#define API_EXPORT __attribute__((visibility("default")))
#endif
 
 
static void encrypt_rounds_internal(
    kalyna_t* ctx,
    const uint8_t* pt,
    uint8_t* ct,
    int rounds
) {
    int round;
    size_t block_bytes = ctx->nb * sizeof(uint64_t);
 
    memcpy(ctx->state, pt, block_bytes);
 
    AddRoundKey(0, ctx);
    for (round = 1; round <= rounds; ++round) {
        EncipherRound(ctx);
        if (round < (int)ctx->nr) {
            XorRoundKey(round, ctx);
        } else {
            AddRoundKey((int)ctx->nr, ctx);
        }
    }
 
    memcpy(ct, ctx->state, block_bytes);
}
 
 
static inline uint64_t splitmix64(uint64_t* state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
 
typedef struct {
    uint64_t s[4];
} xoshiro_state;
 
static inline uint64_t rotl(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}
 
static inline uint64_t xoshiro_next(xoshiro_state* st) {
    uint64_t result = rotl(st->s[0] + st->s[3], 23) + st->s[0];
    uint64_t t = st->s[1] << 17;
    st->s[2] ^= st->s[0];
    st->s[3] ^= st->s[1];
    st->s[1] ^= st->s[2];
    st->s[0] ^= st->s[3];
    st->s[2] ^= t;
    st->s[3] = rotl(st->s[3], 45);
    return result;
}
 
static void xoshiro_seed(xoshiro_state* st, uint64_t seed) {
    uint64_t sm = seed;
    st->s[0] = splitmix64(&sm);
    st->s[1] = splitmix64(&sm);
    st->s[2] = splitmix64(&sm);
    st->s[3] = splitmix64(&sm);
}
 

API_EXPORT int kalyna_encrypt_batch_single_key(
    const uint8_t* plaintexts,
    const uint8_t* key,
    int block_size_bits,
    int key_size_bits,
    int rounds,
    int n_blocks,
    uint8_t* ciphertexts
) {
    kalyna_t* ctx = NULL;
    uint64_t* key_words = NULL;
    size_t block_bytes, nk_words;
    int i;
    int status = 0;
 
    if (plaintexts == NULL || key == NULL || ciphertexts == NULL) return -1;
    if (n_blocks <= 0) return -1;
 
    ctx = KalynaInit((size_t)block_size_bits, (size_t)key_size_bits);
    if (ctx == NULL) return -2;
 
    if (rounds < 1 || rounds > (int)ctx->nr) {
        KalynaDelete(ctx);
        return -1;
    }
 
    nk_words = ctx->nk;
    block_bytes = ctx->nb * sizeof(uint64_t);
 
    key_words = (uint64_t*)calloc(nk_words, sizeof(uint64_t));
    if (key_words == NULL) {
        KalynaDelete(ctx);
        return -1;
    }
 
    memcpy(key_words, key, nk_words * sizeof(uint64_t));
    KalynaKeyExpand(key_words, ctx);
 
    for (i = 0; i < n_blocks; ++i) {
        encrypt_rounds_internal(
            ctx,
            plaintexts + (size_t)i * block_bytes,
            ciphertexts + (size_t)i * block_bytes,
            rounds
        );
    }
 
    free(key_words);
    KalynaDelete(ctx);
    return status;
}
 
API_EXPORT int kalyna_encrypt_batch_multi_keys(
    const uint8_t* plaintexts,
    const uint8_t* keys,
    int block_size_bits,
    int key_size_bits,
    int rounds,
    int n_blocks,
    uint8_t* ciphertexts
) {
    kalyna_t* ctx = NULL;
    uint64_t* key_words = NULL;
    size_t block_bytes, key_bytes, nk_words;
    int i;
    int status = 0;
 
    if (plaintexts == NULL || keys == NULL || ciphertexts == NULL) return -1;
    if (n_blocks <= 0) return -1;
 
    ctx = KalynaInit((size_t)block_size_bits, (size_t)key_size_bits);
    if (ctx == NULL) return -2;
 
    if (rounds < 1 || rounds > (int)ctx->nr) {
        KalynaDelete(ctx);
        return -1;
    }
 
    nk_words = ctx->nk;
    block_bytes = ctx->nb * sizeof(uint64_t);
    key_bytes = nk_words * sizeof(uint64_t);
 
    key_words = (uint64_t*)calloc(nk_words, sizeof(uint64_t));
    if (key_words == NULL) {
        KalynaDelete(ctx);
        return -1;
    }
 
    for (i = 0; i < n_blocks; ++i) {
        memcpy(key_words, keys + (size_t)i * key_bytes, key_bytes);
        KalynaKeyExpand(key_words, ctx);
        encrypt_rounds_internal(
            ctx,
            plaintexts + (size_t)i * block_bytes,
            ciphertexts + (size_t)i * block_bytes,
            rounds
        );
    }
 
    free(key_words);
    KalynaDelete(ctx);
    return status;
}
 
 
API_EXPORT int kalyna_generate_dataset(
    int n_samples,
    int rounds,
    int block_size_bits,
    int key_size_bits,
    uint64_t delta_word0,
    uint64_t delta_word1,
    uint64_t prng_seed,
    uint8_t* labels,
    uint8_t* ciphertexts0,
    uint8_t* ciphertexts1
) {
    kalyna_t* ctx = NULL;
    uint64_t* key_words = NULL;
    uint64_t pt0_words[8];  
    uint64_t pt1_words[8];
    xoshiro_state rng;
    size_t block_bytes, nb_words, nk_words;
    int i, w;
    int status = 0;
 
    if (labels == NULL || ciphertexts0 == NULL || ciphertexts1 == NULL) return -1;
    if (n_samples <= 0) return -1;
 
    ctx = KalynaInit((size_t)block_size_bits, (size_t)key_size_bits);
    if (ctx == NULL) return -2;
 
    if (rounds < 1 || rounds > (int)ctx->nr) {
        KalynaDelete(ctx);
        return -1;
    }
 
    nb_words = ctx->nb;
    nk_words = ctx->nk;
    block_bytes = nb_words * sizeof(uint64_t);
 
    if (nb_words > 8) {
        KalynaDelete(ctx);
        return -1;
    }
 
    key_words = (uint64_t*)calloc(nk_words, sizeof(uint64_t));
    if (key_words == NULL) {
        KalynaDelete(ctx);
        return -1;
    }
 
    xoshiro_seed(&rng, prng_seed);
 
    for (i = 0; i < n_samples; ++i) {
        /* label */
        uint8_t label = (uint8_t)(xoshiro_next(&rng) & 1ULL);
        labels[i] = label;
 
        /* random key */
        for (w = 0; w < (int)nk_words; ++w) {
            key_words[w] = xoshiro_next(&rng);
        }
 
        /* random P0 */
        for (w = 0; w < (int)nb_words; ++w) {
            pt0_words[w] = xoshiro_next(&rng);
        }
 
        /* P1 */
        if (label == 1) {
            /* P1 = P0 + delta (mod 2^64 на слово) - аддитивна різниця */
            pt1_words[0] = pt0_words[0] + delta_word0;
            if (nb_words >= 2) {
                pt1_words[1] = pt0_words[1] + delta_word1;
            }
            for (w = 2; w < (int)nb_words; ++w) {
                pt1_words[w] = pt0_words[w];
            }
        } else {
            /* P1 = повністю випадковий */
            for (w = 0; w < (int)nb_words; ++w) {
                pt1_words[w] = xoshiro_next(&rng);
            }
        }
 
        /* KeyExpand та два шифрування */
        KalynaKeyExpand(key_words, ctx);
 
        encrypt_rounds_internal(
            ctx,
            (const uint8_t*)pt0_words,
            ciphertexts0 + (size_t)i * block_bytes,
            rounds
        );
 
        encrypt_rounds_internal(
            ctx,
            (const uint8_t*)pt1_words,
            ciphertexts1 + (size_t)i * block_bytes,
            rounds
        );
    }
 
    free(key_words);
    KalynaDelete(ctx);
    return status;
}