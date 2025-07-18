/*
MD5算法实现过程:
1、填充：如果输入信息的长度(bit)对512求余的结果不等于448，就需要填充使得对512求余的结果等于448。填充的方法是填充一个1和n个0。填充完后，信息的长度就为N*512+448(bit)；
2、记录信息(文件)长度：用64位来存储填充前信息长度(二进制位数)。这64位加在第一步结果的后面，这样信息长度就变为N*512+448+64=(N+1)*512位。然后按512位进行分块；
3、对算法context寄存器装入标准的幻数，然后对每一块使用md5_transform()函数加密。加密结束后将获得的四个数abcd分别加进寄存器ABCD中
4、所有块结束加密后获得的寄存器值按DCBA的顺序叠在一起就是最终哈希值

优化：
1、边读边加密：将 添加数据与通常加密md5_update()接口 和 最终加密md5_final()接口 分开，得以实现获得多文件哈希值
*/

#include "MD5.h"

const HashAlgo MD5_ALGO = {
    .init = (void (*)(void *))md5_init,
    .update = (void (*)(void *, const uint8_t *, size_t))md5_update,
    .final = (void (*)(void *, uint8_t *))md5_final,
    .ctx_size = sizeof(MD5_CTX),
    .digest_size = 16,
    .name = "MD5",
};

// 加密运算中的四个线性函数
#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c)))) // 循环左移

// RFC 1321 中的 64 个常数
static const uint32_t K[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

// 四轮共64次运算中循环左移的位数
static const uint32_t r[] = {
     7, 12, 17, 22,  7, 12, 17, 22, 
     7, 12, 17, 22,  7, 12, 17, 22,
     5,  9, 14, 20,  5,  9, 14, 20, 
     5,  9, 14, 20,  5,  9, 14, 20,
     4, 11, 16, 23,  4, 11, 16, 23, 
     4, 11, 16, 23,  4, 11, 16, 23,
     6, 10, 15, 21,  6, 10, 15, 21, 
     6, 10, 15, 21,  6, 10, 15, 21};

// 初始化context
void md5_init(MD5_CTX *ctx)
{
    ctx->bitlen = 0;
    // 四个标准幻数
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

// 加密函数
static void md5_transform(MD5_CTX *ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, i, f, g, temp, m[16];

    for (i = 0; i < 16; ++i)
    {
        m[i] = ((uint32_t)data[i * 4]) |
               ((uint32_t)data[i * 4 + 1] << 8) |
               ((uint32_t)data[i * 4 + 2] << 16) |
               ((uint32_t)data[i * 4 + 3] << 24);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];

    for (i = 0; i < 64; ++i)
    {
        if (i < 16)
        {
            f = F(b, c, d);
            g = i;
        }
        else if (i < 32)
        {
            f = G(b, c, d);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48)
        {
            f = H(b, c, d);
            g = (3 * i + 5) % 16;
        }
        else
        {
            f = I(b, c, d);
            g = (7 * i) % 16;
        }

        temp = d;
        d = c;
        c = b;
        b = b + LEFTROTATE((a + f + K[i] + m[g]), r[i]);
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t len)
{
    // 每收集满 64 字节（512 位）就调用 md5_transform() 做一次加密运算
    size_t i = 0;
    size_t index = ctx->bitlen / 8 % 64; // 计算缓冲区已经有了多少字节

    // 更新总长度(位数)
    ctx->bitlen += len * 8;

    if (index > 0)
    {                             // 需要填充
        size_t fill = 64 - index; // 还差多少字节填满最后一个块
        if (len < fill)
        { // 长度不足以填满一个块
            memcpy(&ctx->buffer[index], data, len);
            return;
        }
        memcpy(&ctx->buffer[index], data, fill);
        md5_transform(ctx, ctx->buffer);
        i += fill;
    }

    for (; i + 63 < len; i += 64)
        md5_transform(ctx, &data[i]);

    memcpy(ctx->buffer, &data[i], len - i);
}

void md5_final(MD5_CTX *ctx, uint8_t hash[16])
{
    // 补一个1和一堆0直到最后一个块剩下一个字节(uint64_t)存文件长度
    size_t index = ctx->bitlen / 8 % 64;
    ctx->buffer[index++] = 0x80;

    if (index > 56)
    { // 不足以塞下一个uint64_t来存文件长度
        memset(&ctx->buffer[index], 0, 64 - index);
        md5_transform(ctx, ctx->buffer);
        index = 0;
    }

    memset(&ctx->buffer[index], 0, 56 - index);
    uint64_t bitlen_le = ctx->bitlen;

    for (int i = 0; i < 8; ++i)
        ctx->buffer[56 + i] = (uint8_t)(bitlen_le >> (8 * i));

    md5_transform(ctx, ctx->buffer);

    for (int i = 0; i < 4; ++i)
    {
        hash[i] = (uint8_t)(ctx->state[0] >> (8 * i));
        hash[i + 4] = (uint8_t)(ctx->state[1] >> (8 * i));
        hash[i + 8] = (uint8_t)(ctx->state[2] >> (8 * i));
        hash[i + 12] = (uint8_t)(ctx->state[3] >> (8 * i));
    }
}
