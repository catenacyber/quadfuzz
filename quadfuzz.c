#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t size, size_t MaxSize, unsigned int Seed);
size_t LLVMFuzzerMutate(uint8_t *Data, size_t size, size_t MaxSize);

static bool quad_fuzz_init = false;
static bool quad_fuzz_debug = false;

uint32_t pattern_repeat_nbs[8] = {
    0x200,
    0xFFF,
    0x1000,
    0x1001,
    0xFFFF,
    0x10000,
    0x10001,
    0x20000,
};

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t size, size_t MaxSize, unsigned int Seed)
{
    if (!quad_fuzz_init) {
        quad_fuzz_debug = getenv("QUAD_FUZZ_DEBUG") != NULL;
        if (MaxSize < 0x10000) {
            printf("quadfuzz starts with MaxSize = %zu\n", MaxSize);
        }
        quad_fuzz_init = true;
    }
    if ((Seed & 1) == 0 || MaxSize < 0x10000) {
        return LLVMFuzzerMutate(Data, size, MaxSize);
    }
    Seed = Seed >> 1;
    size_t pattern_repeat_len = 1 + (Seed & 0xF);
    Seed = Seed >> 4;
    size_t pattern_repeat_nb = pattern_repeat_nbs[Seed & 0x7];
    Seed = Seed >> 3;
    size_t prefix_postfix_ratio = (Seed & 0x3F);
    Seed = Seed >> 6;
    bool mutate_pattern = (Seed & 1);
    Seed = Seed >> 1;

    if (pattern_repeat_len > size) {
        pattern_repeat_len = size;
    }
    size_t prefix_postfix_len = size - pattern_repeat_len;
    size_t prefix_len = (prefix_postfix_len * prefix_postfix_ratio) / 0xFF;
    size_t postfix_len = prefix_postfix_len - prefix_len;
    size_t qsize = prefix_len + (pattern_repeat_nb * pattern_repeat_len) + postfix_len;
    if (qsize > MaxSize) {
        pattern_repeat_nb -= 1 + (qsize - MaxSize) / pattern_repeat_len;
        qsize = prefix_len + (pattern_repeat_nb * pattern_repeat_len) + postfix_len;
    }
    if (quad_fuzz_debug) {
        printf("size = %zu\n", size);
        printf("MaxSize = %zu\n", MaxSize);
        printf("Seed = %u\n", Seed);
        printf("pattern_repeat_len = %zu\n", pattern_repeat_len);
        printf("pattern_repeat_nb = %zu\n", pattern_repeat_nb);
        printf("prefix_postfix_ratio = %zu\n", prefix_postfix_ratio);
        printf("prefix_postfix_len = %zu\n", prefix_postfix_len);
        printf("prefix_len = %zu\n", prefix_len);
        printf("postfix_len = %zu\n", postfix_len);
        printf("qsize = %zu\n", qsize);
    }
    uint8_t *qdata = malloc(qsize);
    memcpy(qdata, Data, prefix_len);
    for (size_t i = 0; i < pattern_repeat_nb; i++) {
        memcpy(qdata + prefix_len + i * pattern_repeat_len, Data + prefix_len, pattern_repeat_len);
        if (mutate_pattern) {
            if (i % pattern_repeat_len) {
                Data[prefix_len + (i % pattern_repeat_len)]++;
            } else {
                Data[prefix_len + (i % pattern_repeat_len)]-=pattern_repeat_len;
            }
        }
    }
    memcpy(qdata + qsize - postfix_len, Data + size - postfix_len, postfix_len);
    memcpy(Data, qdata, qsize);
    free(qdata);
    if ((Seed & 1) == 0) {
        return LLVMFuzzerMutate(Data, qsize, MaxSize);
    }
    return qsize;
}
