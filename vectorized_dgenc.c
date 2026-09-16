#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static inline __m512i
generateMask(const __m512i* const restrict key, size_t keySize)
{
    __m512i mask = _mm512_setzero_si512();

    size_t i = 0;
#pragma unroll(1)
    do {
        __m512i next = _mm512_load_epi32((const void*) (key + i));
        mask         = _mm512_xor_si512(mask, next);
        i += 1;
    } while (i < keySize);

    return mask;
}

const uint32_t __attribute__((aligned(64))) masksArray[4][16] = {
    {15, 14, 13, 12, 11, 10, 9, 8,  7,  6,  5,  4,  3,  2,  1,  0},
    { 7,  6,  5,  4,  3,  2, 1, 0, 15, 14, 13, 12, 11, 10,  9,  8},
    { 3,  2,  1,  0,  7,  6, 5, 4, 11, 10,  9,  8, 15, 14, 13, 12},
    { 1,  0,  3,  2,  5,  4, 7, 6,  9,  8, 11, 10, 13, 12, 15, 14},
};

void vdgencEncrypt(
    const __m512i* const restrict text,
    const __m512i* const restrict key,
    __m512i* restrict result,
    size_t textSize,
    size_t keySize
)
{
    const __m512i        mask        = generateMask(key, keySize);
    const uint32_t       reducedMask = _mm512_reduce_add_epi32(mask);
    const __m512i* const masks       = (const __m512i* const) masksArray;

    size_t i = 0;
    do {
        const __m512i  block      = _mm512_load_epi32((const void*) (text + i));
        const __m512i  xored      = _mm512_xor_epi32(block, mask);
        const uint32_t reduced    = _mm512_reduce_add_epi32(xored);
        const uint32_t redXorMask = reduced ^ reducedMask;
        const __m512i  shuffleMask =
            _mm512_load_epi32((const void*) (masks + (redXorMask & 3)));
        const __m512i res = _mm512_permutexvar_epi32(shuffleMask, xored);
        _mm512_store_epi32((void*) (result + i), res);
        i += 1;
    } while (i < textSize);
}

void vdgencDecrypt(
    const __m512i* const restrict text,
    const __m512i* const restrict key,
    __m512i* restrict result,
    size_t textSize,
    size_t keySize
)
{
    const __m512i        mask        = generateMask(key, keySize);
    const uint32_t       reducedMask = _mm512_reduce_add_epi32(mask);
    const __m512i* const masks       = (const __m512i* const) masksArray;

    size_t i = 0;
    do {
        const __m512i  block      = _mm512_load_epi32((const void*) (text + i));
        const uint32_t reduced    = _mm512_reduce_add_epi32(block);
        const uint32_t redXorMask = reduced ^ reducedMask;
        const __m512i  shuffleMask =
            _mm512_load_epi32((const void*) (masks + (redXorMask & 3)));
        const __m512i res   = _mm512_permutexvar_epi32(shuffleMask, block);
        const __m512i xored = _mm512_xor_epi32(res, mask);
        _mm512_store_epi32((void*) (result + i), xored);
        i += 1;
    } while (i < textSize);
}
