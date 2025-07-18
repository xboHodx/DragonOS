#include "SHA256.h"

const HashAlgo SHA256_ALGO = {
    .init = (void (*)(void *))sha256_init,
    .update = (void (*)(void *, const uint8_t *, size_t))sha256_update,
    .final = (void (*)(void *, uint8_t *))sha256_final,
    .ctx_size = sizeof(SHA256_CTX),
    .digest_size = 32,
    .name = "SHA256",
};

/*
SHA256算法实现过程:
1. 填充：在消息后添加比特'1'，然后添加若干比特'0'，直到长度对512求余的结果等于448
2. 附加长度：用64位表示原始信息的长度，附加在已填充后的消息后面
3. 初始化哈希值：使用8个初始哈希值(定义为前8个质数平方根的小数部分的前32位)
4. 分块计算：将消息分成512位的块，对每个块进行处理
5. 处理每个块：展开消息为64个32位字，然后进行64轮压缩函数计算
*/

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
    ctx->bit_count = 0;
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

// SHA256的核心处理函数，处理一个512位的数据块
static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    // 准备消息调度，将字节数据转换为32位字并扩展到64个字
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
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

    // 主循环（64轮）
    for (i = 0; i < 64; ++i)
    {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

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
    size_t index = (ctx->bit_count / 8) % 64; // 缓冲区中已有的字节数

    // 更新总位数
    ctx->bit_count += len * 8;

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
    size_t index = (ctx->bit_count / 8) % 64;
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
    uint64_t bitlen_be = ctx->bit_count;
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
