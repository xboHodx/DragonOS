#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "hash_algo.h"

extern const HashAlgo MD5_ALGO;

typedef struct { // 算法上下文context
    uint32_t state[4];  // A, B, C, D 寄存器
    uint64_t bitlen;    // 已处理总长度(位数)
    uint8_t buffer[64]; // 当前的缓冲区
} MD5_CTX;

void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t len);
void md5_final(MD5_CTX *ctx, uint8_t hash[16]);

#endif