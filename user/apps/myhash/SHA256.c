/*
参考：https://zhuanlan.zhihu.com/p/94619052
SHA256算法实现过程:
1. 填充：在消息后添加比特'1'，然后添加若干比特'0'，直到长度对512求余的结果等于448
2. 附加长度：用64位表示原始信息的长度，附加在已填充后的消息后面
3. 初始化哈希值：使用8个初始哈希值(定义为前8个质数平方根的小数部分的前32位)
4. 分块计算：将消息分成512位的块，对每个块进行处理
5. 处理每个块：展开消息为64个32位字，然后进行64轮压缩函数计算。加密结束后将获得的四个数abcd分别加进寄存器ABCD中
6. 所有块结束加密后获得的寄存器值按DCBA的顺序叠在一起就是最终哈希值


优化：
1. 使用SIMD技术，通过SSE2指令集，使加载m[]数组时能够并行处理
2. 宏定义替代了原来的循环结构，避免了循环控制带来的开销
*/

#include "SHA256.h"

const HashAlgo SHA256_ALGO = {
    .init = (void (*)(void *))sha256_init,
    .update = (void (*)(void *, const uint8_t *, size_t))sha256_update,
    .final = (void (*)(void *, uint8_t *))sha256_final,
    .ctx_size = sizeof(SHA256_CTX),
    .digest_size = 32,
    .name = "SHA256",
};

// SHA256算法中使用的64个常数（第64个质数的立方根的前32位的小数部分）
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

// SHA256使用的函数宏定义
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHR(x, n) ((x) >> (n))

// SHA256中的六个逻辑函数
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

// 初始化SHA256上下文
void sha256_init(SHA256_CTX *ctx)
{
    ctx->bitlen = 0;
    // SHA256的初始哈希值（前8个质数平方根的小数部分的前32位）
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

#ifdef __SSE2__
#include <emmintrin.h> // SSE2
#endif

// SHA256的核心处理函数，处理一个512位的数据块
static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

#ifdef __SSE2__
    // 使用SIMD加载和转换数据（大端序）
    if (((uintptr_t)data & 0xF) == 0) {  // 检查16字节对齐
        // 使用SSE2指令加载数据，每次加载16字节（4个32位字）
        __m128i *data_ptr = (__m128i*)data;
        __m128i chunk0 = _mm_load_si128(data_ptr);
        __m128i chunk1 = _mm_load_si128(data_ptr + 1);
        __m128i chunk2 = _mm_load_si128(data_ptr + 2);
        __m128i chunk3 = _mm_load_si128(data_ptr + 3);

        // 暂存加载的数据
        uint32_t temp[16];
        _mm_storeu_si128((__m128i*)&temp[0], chunk0);
        _mm_storeu_si128((__m128i*)&temp[4], chunk1);
        _mm_storeu_si128((__m128i*)&temp[8], chunk2);
        _mm_storeu_si128((__m128i*)&temp[12], chunk3);

        // SHA256需要大端序，进行转换
        for (i = 0; i < 16; ++i) {
            m[i] = ((temp[i] & 0xFF) << 24) | ((temp[i] & 0xFF00) << 8) | 
                   ((temp[i] & 0xFF0000) >> 8) | ((temp[i] & 0xFF000000) >> 24);
        }
    } else {
        // 对于未对齐的数据，使用常规方法
        for (i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
#else
    // 标准非SIMD实现
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
#endif

    // 消息扩展，将16个字扩展为64个字
    for (i = 16; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    // 初始化算法的工作变量
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // for (i = 0; i < 64; ++i)
    // {
    //     t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
    //     t2 = EP0(a) + MAJ(a, b, c);
    //     h = g;
    //     g = f;
    //     f = e;
    //     e = d + t1;
    //     d = c;
    //     c = b;
    //     b = a;
    //     a = t1 + t2;
    // }

    // 定义SHA256运算宏，避免循环控制，提高性能
    #define SHA256_ROUND(a, b, c, d, e, f, g, h, k, w) { \
        t1 = h + EP1(e) + CH(e, f, g) + k + w; \
        t2 = EP0(a) + MAJ(a, b, c); \
        h = g; \
        g = f; \
        f = e; \
        e = d + t1; \
        d = c; \
        c = b; \
        b = a; \
        a = t1 + t2; \
    }

    // 展开的64轮压缩函数，替代循环结构
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[0], m[0]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[1], m[1]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[2], m[2]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[3], m[3]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[4], m[4]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[5], m[5]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[6], m[6]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[7], m[7]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[8], m[8]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[9], m[9]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[10], m[10]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[11], m[11]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[12], m[12]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[13], m[13]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[14], m[14]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[15], m[15]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[16], m[16]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[17], m[17]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[18], m[18]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[19], m[19]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[20], m[20]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[21], m[21]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[22], m[22]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[23], m[23]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[24], m[24]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[25], m[25]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[26], m[26]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[27], m[27]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[28], m[28]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[29], m[29]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[30], m[30]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[31], m[31]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[32], m[32]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[33], m[33]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[34], m[34]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[35], m[35]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[36], m[36]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[37], m[37]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[38], m[38]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[39], m[39]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[40], m[40]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[41], m[41]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[42], m[42]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[43], m[43]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[44], m[44]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[45], m[45]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[46], m[46]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[47], m[47]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[48], m[48]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[49], m[49]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[50], m[50]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[51], m[51]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[52], m[52]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[53], m[53]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[54], m[54]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[55], m[55]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[56], m[56]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[57], m[57]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[58], m[58]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[59], m[59]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[60], m[60]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[61], m[61]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[62], m[62]);
    SHA256_ROUND(a, b, c, d, e, f, g, h, K[63], m[63]);

    #undef SHA256_ROUND

    // 将计算结果加到当前的哈希值上
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// 添加数据到SHA256上下文
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len)
{
    // 每收集满64字节（512位）就调用sha256_transform进行一次处理
    size_t i = 0;
    size_t index = (ctx->bitlen / 8) % 64; // 缓冲区中已有的字节数

    // 更新总位数
    ctx->bitlen += len * 8;

    // 如果缓冲区中已有数据，先将缓冲区填满并处理
    if (index > 0)
    {
        size_t fill = 64 - index; // 还需要多少字节填满缓冲区
        if (len < fill)
        { // 不足以填满
            memcpy(&ctx->buffer[index], data, len);
            return;
        }
        // 填满并处理
        memcpy(&ctx->buffer[index], data, fill);
        sha256_transform(ctx, ctx->buffer);
        i += fill;
    }

    // 处理完整的512位数据块
    for (; i + 63 < len; i += 64)
        sha256_transform(ctx, &data[i]);

    // 保存剩余的数据到缓冲区
    memcpy(ctx->buffer, &data[i], len - i);
}

// 完成SHA256哈希计算
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32])
{
    // 补一个1和一堆0直到最后一个块剩下8个字节(64位)存文件长度
    size_t index = (ctx->bitlen / 8) % 64;
    ctx->buffer[index++] = 0x80; // 添加一个字节，最高位为1，其余为0

    // 如果剩余空间不足以存放8字节的长度，则填充本块并处理，然后处理下一块
    if (index > 56) 
    { 
        // 不足以塞下一个64位(8字节)来存文件长度
        memset(&ctx->buffer[index], 0, 64 - index);
        sha256_transform(ctx, ctx->buffer);
        index = 0;
    }

    // 填充0直到第56个字节（留8个字节存放长度）
    memset(&ctx->buffer[index], 0, 56 - index);
    
    // 添加消息长度（以比特为单位，大端序）
    uint64_t bitlen_be = ctx->bitlen;
    for (int i = 0; i < 8; ++i)
        ctx->buffer[56 + i] = (uint8_t)(bitlen_be >> ((7 - i) * 8)) & 0xFF;

    // 处理最后一个数据块
    sha256_transform(ctx, ctx->buffer);

    // 输出最终哈希值（大端序）
    for (int i = 0; i < 8; i++)
    {
        hash[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}
