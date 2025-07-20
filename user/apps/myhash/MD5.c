/*
参考：https://blog.csdn.net/forgotaboutgirl/article/details/7258109
MD5算法实现过程:
1、填充：如果输入信息的长度(bit)对512求余的结果不等于448，就需要填充使得对512求余的结果等于448。填充的方法是填充一个1和n个0。填充完后，信息的长度就为N*512+448(bit)；
2、记录信息(文件)长度：用64位来存储填充前信息长度(二进制位数)。这64位加在第一步结果的后面，这样信息长度就变为N*512+448+64=(N+1)*512位。然后按512位进行分块；
3、对算法context寄存器装入标准的幻数，然后对每一块使用md5_transform()函数加密。加密结束后将获得的四个数abcd分别加进寄存器ABCD中
4、所有块结束加密后获得的寄存器值按DCBA的顺序叠在一起就是最终哈希值

优化：
1、边读边加密：将 添加数据与通常加密md5_update()接口 和 最终加密md5_final()接口 分开，得以实现获得多文件哈希值
2、使用SIMD技术，通过SSE2指令集，使加载m[]数组时能够并行处理
3、宏定义替代了原来的条件分支结构，避免了循环控制带来的开销
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
// static const uint32_t r[] = {
//      7, 12, 17, 22,  7, 12, 17, 22, 
//      7, 12, 17, 22,  7, 12, 17, 22,
//      5,  9, 14, 20,  5,  9, 14, 20, 
//      5,  9, 14, 20,  5,  9, 14, 20,
//      4, 11, 16, 23,  4, 11, 16, 23, 
//      4, 11, 16, 23,  4, 11, 16, 23,
//      6, 10, 15, 21,  6, 10, 15, 21, 
//      6, 10, 15, 21,  6, 10, 15, 21};

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
#ifdef __SSE2__
#include <emmintrin.h> // SSE2
#endif

static void md5_transform(MD5_CTX *ctx, const uint8_t data[])
{
    uint32_t a, b, c, d, i, m[16];
    // uint32_t f, g, temp;

#ifdef __SSE2__
    // 使用SIMD加载和转换数据
    if (((uintptr_t)data & 0xF) == 0) {  // 检查16字节对齐 在二进制表示中，一个 16 字节对齐的地址的低 4 位必须全为 0
        // 使用SSE2指令加载数据，每次加载16字节（4个32位字）
        __m128i *data_ptr = (__m128i*)data;
        __m128i chunk0 = _mm_load_si128(data_ptr);
        __m128i chunk1 = _mm_load_si128(data_ptr + 1);
        __m128i chunk2 = _mm_load_si128(data_ptr + 2);
        __m128i chunk3 = _mm_load_si128(data_ptr + 3);

        // 小端系统可以直接存储，大端系统需要字节交换
// #if defined(__BIG_ENDIAN__) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
//         // 字节交换，为大端系统
//         chunk0 = _mm_shuffle_epi8(chunk0, _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));
//         chunk1 = _mm_shuffle_epi8(chunk1, _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));
//         chunk2 = _mm_shuffle_epi8(chunk2, _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));
//         chunk3 = _mm_shuffle_epi8(chunk3, _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3));
// #endif
        // 将数据存储到m数组
        _mm_storeu_si128((__m128i*)&m[0], chunk0);
        _mm_storeu_si128((__m128i*)&m[4], chunk1);
        _mm_storeu_si128((__m128i*)&m[8], chunk2);
        _mm_storeu_si128((__m128i*)&m[12], chunk3);
    } else {
        // 对于未对齐的数据，使用常规方法
        for (i = 0; i < 16; ++i)
        {
            m[i] = ((uint32_t)data[i * 4]) |
                   ((uint32_t)data[i * 4 + 1] << 8) |
                   ((uint32_t)data[i * 4 + 2] << 16) |
                   ((uint32_t)data[i * 4 + 3] << 24);
        }
    }
#else
    // 标准非SIMD实现
    for (i = 0; i < 16; ++i)
    {
        m[i] = ((uint32_t)data[i * 4]) |
               ((uint32_t)data[i * 4 + 1] << 8) |
               ((uint32_t)data[i * 4 + 2] << 16) |
               ((uint32_t)data[i * 4 + 3] << 24);
    }
#endif

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];

    // for (i = 0; i < 64; ++i)
    // {
    //     if (i < 16)
    //     {
    //         f = F(b, c, d);
    //         g = i;
    //     }
    //     else if (i < 32)
    //     {
    //         f = G(b, c, d);
    //         g = (5 * i + 1) % 16;
    //     }
    //     else if (i < 48)
    //     {
    //         f = H(b, c, d);
    //         g = (3 * i + 5) % 16;
    //     }
    //     else
    //     {
    //         f = I(b, c, d);
    //         g = (7 * i) % 16;
    //     }

    //     temp = d;
    //     d = c;
    //     c = b;
    //     b = b + LEFTROTATE((a + f + K[i] + m[g]), r[i]);
    //     a = temp;
    // }

    // 定义MD5运算宏，避免循环控制，提高性能
    #define MD5_FF(a, b, c, d, x, s, ac) { \
        (a) += F(b, c, d) + (x) + (uint32_t)(ac); \
        (a) = LEFTROTATE((a), (s)); \
        (a) += (b); \
    }
    
    #define MD5_GG(a, b, c, d, x, s, ac) { \
        (a) += G(b, c, d) + (x) + (uint32_t)(ac); \
        (a) = LEFTROTATE((a), (s)); \
        (a) += (b); \
    }
    
    #define MD5_HH(a, b, c, d, x, s, ac) { \
        (a) += H(b, c, d) + (x) + (uint32_t)(ac); \
        (a) = LEFTROTATE((a), (s)); \
        (a) += (b); \
    }
    
    #define MD5_II(a, b, c, d, x, s, ac) { \
        (a) += I(b, c, d) + (x) + (uint32_t)(ac); \
        (a) = LEFTROTATE((a), (s)); \
        (a) += (b); \
    }

    // 第1轮
    MD5_FF(a, b, c, d, m[0],   7, K[0]);
    MD5_FF(d, a, b, c, m[1],  12, K[1]);
    MD5_FF(c, d, a, b, m[2],  17, K[2]);
    MD5_FF(b, c, d, a, m[3],  22, K[3]);
    MD5_FF(a, b, c, d, m[4],   7, K[4]);
    MD5_FF(d, a, b, c, m[5],  12, K[5]);
    MD5_FF(c, d, a, b, m[6],  17, K[6]);
    MD5_FF(b, c, d, a, m[7],  22, K[7]);
    MD5_FF(a, b, c, d, m[8],   7, K[8]);
    MD5_FF(d, a, b, c, m[9],  12, K[9]);
    MD5_FF(c, d, a, b, m[10], 17, K[10]);
    MD5_FF(b, c, d, a, m[11], 22, K[11]);
    MD5_FF(a, b, c, d, m[12],  7, K[12]);
    MD5_FF(d, a, b, c, m[13], 12, K[13]);
    MD5_FF(c, d, a, b, m[14], 17, K[14]);
    MD5_FF(b, c, d, a, m[15], 22, K[15]);

    // 第2轮
    MD5_GG(a, b, c, d, m[1],   5, K[16]);
    MD5_GG(d, a, b, c, m[6],   9, K[17]);
    MD5_GG(c, d, a, b, m[11], 14, K[18]);
    MD5_GG(b, c, d, a, m[0],  20, K[19]);
    MD5_GG(a, b, c, d, m[5],   5, K[20]);
    MD5_GG(d, a, b, c, m[10],  9, K[21]);
    MD5_GG(c, d, a, b, m[15], 14, K[22]);
    MD5_GG(b, c, d, a, m[4],  20, K[23]);
    MD5_GG(a, b, c, d, m[9],   5, K[24]);
    MD5_GG(d, a, b, c, m[14],  9, K[25]);
    MD5_GG(c, d, a, b, m[3],  14, K[26]);
    MD5_GG(b, c, d, a, m[8],  20, K[27]);
    MD5_GG(a, b, c, d, m[13],  5, K[28]);
    MD5_GG(d, a, b, c, m[2],   9, K[29]);
    MD5_GG(c, d, a, b, m[7],  14, K[30]);
    MD5_GG(b, c, d, a, m[12], 20, K[31]);

    // 第3轮
    MD5_HH(a, b, c, d, m[5],   4, K[32]);
    MD5_HH(d, a, b, c, m[8],  11, K[33]);
    MD5_HH(c, d, a, b, m[11], 16, K[34]);
    MD5_HH(b, c, d, a, m[14], 23, K[35]);
    MD5_HH(a, b, c, d, m[1],   4, K[36]);
    MD5_HH(d, a, b, c, m[4],  11, K[37]);
    MD5_HH(c, d, a, b, m[7],  16, K[38]);
    MD5_HH(b, c, d, a, m[10], 23, K[39]);
    MD5_HH(a, b, c, d, m[13],  4, K[40]);
    MD5_HH(d, a, b, c, m[0],  11, K[41]);
    MD5_HH(c, d, a, b, m[3],  16, K[42]);
    MD5_HH(b, c, d, a, m[6],  23, K[43]);
    MD5_HH(a, b, c, d, m[9],   4, K[44]);
    MD5_HH(d, a, b, c, m[12], 11, K[45]);
    MD5_HH(c, d, a, b, m[15], 16, K[46]);
    MD5_HH(b, c, d, a, m[2],  23, K[47]);

    // 第4轮
    MD5_II(a, b, c, d, m[0],   6, K[48]);
    MD5_II(d, a, b, c, m[7],  10, K[49]);
    MD5_II(c, d, a, b, m[14], 15, K[50]);
    MD5_II(b, c, d, a, m[5],  21, K[51]);
    MD5_II(a, b, c, d, m[12],  6, K[52]);
    MD5_II(d, a, b, c, m[3],  10, K[53]);
    MD5_II(c, d, a, b, m[10], 15, K[54]);
    MD5_II(b, c, d, a, m[1],  21, K[55]);
    MD5_II(a, b, c, d, m[8],   6, K[56]);
    MD5_II(d, a, b, c, m[15], 10, K[57]);
    MD5_II(c, d, a, b, m[6],  15, K[58]);
    MD5_II(b, c, d, a, m[13], 21, K[59]);
    MD5_II(a, b, c, d, m[4],   6, K[60]);
    MD5_II(d, a, b, c, m[11], 10, K[61]);
    MD5_II(c, d, a, b, m[2],  15, K[62]);
    MD5_II(b, c, d, a, m[9],  21, K[63]);
    
    #undef MD5_FF
    #undef MD5_GG
    #undef MD5_HH
    #undef MD5_II

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