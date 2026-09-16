#ifndef VECTORIZED_DGENC_H_
#define VECTORIZED_DGENC_H_

#include <immintrin.h>

void vdgencEncrypt(
    const __m512i* const restrict text,
    const __m512i* const restrict key,
    __m512i* restrict result,
    size_t textSize,
    size_t keySize
);
void vdgencDecrypt(
    const __m512i* const restrict text,
    const __m512i* const restrict key,
    __m512i* restrict result,
    size_t textSize,
    size_t keySize
);

#endif // VECTORIZED_DGENC_H_
