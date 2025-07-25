#ifndef HASH_ALGO_H
#define HASH_ALGO_H

#include <stdint.h>
#include <stddef.h>

// 支持的哈希算法枚举
typedef enum {
    HASH_ALGO_MD5 = 0,
    HASH_ALGO_SHA256 = 1,
    // 未来可以添加更多算法
    HASH_ALGO_COUNT  // 总数
} HashAlgoType;

typedef struct {
    void (*init)(void *ctx);
    void (*update)(void *ctx, const unsigned char *data, size_t len);
    void (*final)(void *ctx, uint8_t *digest);
    size_t ctx_size;      // 上下文大小（字节）
    size_t digest_size;   // 输出长度（如 MD5 是 16 字节，SHA256 是 32 字节）
    const char *name;     // 算法名称
    HashAlgoType algo_type;
} HashAlgo;

typedef struct {
    const HashAlgo *algo;
    void *ctx;
    const char **files;
    size_t filenum;
    int row_number;
} HashJob;

#endif