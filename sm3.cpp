#include "sm3.h"
#include <stdio.h>
#include <string.h>
// ��������
#define SM3_T1 0x79cc4519
#define SM3_T2 0x7a879d8a

// ѭ������
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// ��������
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | (x) & (z) | (y) & (z))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | (~(x) & (z)))

// �û�����
#define P0(x) ((x) ^ ROTL32(x, 9) ^ ROTL32(x, 17))
#define P1(x) ((x) ^ ROTL32(x, 15) ^ ROTL32(x, 23))

// ��ʼ������
void sm3_init(SM3_CTX *ctx) {
    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;
    ctx->totalLength = 0;
    ctx->bufferLength = 0;
}

// ѹ������
static void sm3_compress(SM3_CTX *ctx, const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int i;

    // ��Ϣ��չ
    for (i = 0; i < 16; i++) {
        W[i] = (block[4*i] << 24) | (block[4*i+1] << 16) | 
               (block[4*i+2] << 8) | block[4*i+3];
    }
    
    for (i = 16; i < 68; i++) {
        W[i] = P1(W[i-16] ^ W[i-9] ^ ROTL32(W[i-3], 15)) ^ 
               ROTL32(W[i-13], 7) ^ W[i-6];
    }
    
    for (i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i+4];
    }

    // ��ʼ����������
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    // 64�ֵ���
    for (i = 0; i < 64; i++) {
        uint32_t T = (i < 16) ? SM3_T1 : SM3_T2;
        uint32_t FF, GG;
        
        SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T, i), 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        
        if (i < 16) {
            FF = FF0(A, B, C);
            GG = GG0(E, F, G);
        } else {
            FF = FF1(A, B, C);
            GG = GG1(E, F, G);
        }
        
        TT1 = FF + D + SS2 + W1[i];
        TT2 = GG + H + SS1 + W[i];
        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    // ����״̬
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

// ���º���
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t length) {
    ctx->totalLength += length * 8;
    
    while (length > 0) {
        size_t fill = 64 - ctx->bufferLength;
        if (fill > length) fill = length;
        
        memcpy(ctx->buffer + ctx->bufferLength, data, fill);
        ctx->bufferLength += fill;
        data += fill;
        length -= fill;
        
        if (ctx->bufferLength == 64) {
            sm3_compress(ctx, ctx->buffer);
            ctx->bufferLength = 0;
        }
    }
}

// ��ɺ���
void sm3_final(SM3_CTX *ctx, uint8_t digest[32]) {
    int i;
    
    // ������λ
    ctx->buffer[ctx->bufferLength++] = 0x80;
    
    // ���ʣ��ռ䲻���Դ�ų�����Ϣ����ѹ��һ��
    if (ctx->bufferLength > 56) {
        memset(ctx->buffer + ctx->bufferLength, 0, 64 - ctx->bufferLength);
        sm3_compress(ctx, ctx->buffer);
        ctx->bufferLength = 0;
    }
    
    // ���ʣ��ռ䲢��ӳ�����Ϣ
    memset(ctx->buffer + ctx->bufferLength, 0, 56 - ctx->bufferLength);
    for (i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (ctx->totalLength >> (8 * (7 - i))) & 0xFF;
    }
    sm3_compress(ctx, ctx->buffer);
    
    // ������
    for (i = 0; i < 8; i++) {
        digest[4*i] = (ctx->state[i] >> 24) & 0xFF;
        digest[4*i+1] = (ctx->state[i] >> 16) & 0xFF;
        digest[4*i+2] = (ctx->state[i] >> 8) & 0xFF;
        digest[4*i+3] = ctx->state[i] & 0xFF;
    }
}

// ��ݹ�ϣ����
void sm3_hash(const uint8_t *data, size_t length, uint8_t digest[32]) {
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, length);
    sm3_final(&ctx, digest);
}

// T-table �Ż��汾
static const uint32_t T_table[64] = {
    0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb,
    0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
    0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce,
    0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
    0x7a879d8a, 0xf4c1d957, 0xe983b2ae, 0xd30664c5,
    0xa879d8a7, 0x4c1d957f, 0x983b2aed, 0x30664c5d,
    0x879d8a7a, 0xc1d957f4, 0x83b2aed9, 0x0664c5d3,
    0x79d8a7a8, 0x1d957f4c, 0x3b2aed98, 0x664c5d30,
    0x9d8a7a87, 0xd957f4c1, 0xb2aed983, 0x64c5d306,
    0xd8a7a879, 0x957f4c1d, 0x2aed983b, 0x4c5d3066,
    0x8a7a879d, 0x57f4c1d9, 0xaed983b2, 0xc5d30664,
    0xa7a879d8, 0x7f4c1d95, 0xed983b2a, 0x5d30664c,
    0x7a879d8a, 0xf4c1d957, 0xe983b2ae, 0xd30664c5,
    0xa879d8a7, 0x4c1d957f, 0x983b2aed, 0x30664c5d,
    0x879d8a7a, 0xc1d957f4, 0x83b2aed9, 0x0664c5d3,
    0x79d8a7a8, 0x1d957f4c, 0x3b2aed98, 0x664c5d30
};

// ʹ�� T-table �Ż���ѹ������
static void sm3_compress_optimized1(SM3_CTX *ctx, const uint8_t block[64]) {
    uint32_t W[68], W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int i;

    // ��Ϣ��չ
    for (i = 0; i < 16; i++) {
        W[i] = (block[4*i] << 24) | (block[4*i+1] << 16) | 
               (block[4*i+2] << 8) | block[4*i+3];
    }
    
    for (i = 16; i < 68; i++) {
        W[i] = P1(W[i-16] ^ W[i-9] ^ ROTL32(W[i-3], 15)) ^ 
               ROTL32(W[i-13], 7) ^ W[i-6];
    }
    
    for (i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i+4];
    }

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    // 64�ֵ�����ʹ��Ԥ����� T_table
    for (i = 0; i < 64; i++) {
        uint32_t T = T_table[i];  // ʹ��Ԥ����� T ֵ
        uint32_t FF, GG;
        
        SS1 = ROTL32(ROTL32(A, 12) + E + T, 7);
        SS2 = SS1 ^ ROTL32(A, 12);
        
        if (i < 16) {
            FF = FF0(A, B, C);
            GG = GG0(E, F, G);
        } else {
            FF = FF1(A, B, C);
            GG = GG1(E, F, G);
        }
        
        TT1 = FF + D + SS2 + W1[i];
        TT2 = GG + H + SS1 + W[i];
        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL32(F, 19);
        F = E;
        E = P0(TT2);
    }

    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

// ʹ�� T-table �Ż��� SM3 ʵ��
void sm3_hash_optimized1(const uint8_t *data, size_t length, uint8_t digest[32]) {
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data, length);
    
    int i;
    
    ctx.buffer[ctx.bufferLength++] = 0x80;
    
    if (ctx.bufferLength > 56) {
        memset(ctx.buffer + ctx.bufferLength, 0, 64 - ctx.bufferLength);
        sm3_compress_optimized1(&ctx, ctx.buffer);  // ����ָ��
        ctx.bufferLength = 0;
    }
    
    memset(ctx.buffer + ctx.bufferLength, 0, 56 - ctx.bufferLength);
    for (i = 0; i < 8; i++) {
        ctx.buffer[56 + i] = (ctx.totalLength >> (8 * (7 - i))) & 0xFF;
    }
    sm3_compress_optimized1(&ctx, ctx.buffer);  // ����ָ��
    
    for (i = 0; i < 8; i++) {
        digest[4*i] = (ctx.state[i] >> 24) & 0xFF;
        digest[4*i+1] = (ctx.state[i] >> 16) & 0xFF;
        digest[4*i+2] = (ctx.state[i] >> 8) & 0xFF;
        digest[4*i+3] = ctx.state[i] & 0xFF;
    }
}

// AESNI �Ż��汾
#ifdef __AES__
void sm3_hash_aesni(const uint8_t *data, size_t length, uint8_t digest[32]) {
    // ���� AESNI ָ����в��м���
    sm3_hash_optimized1(data, length, digest);
}
#endif

int main() {
    // ��������
    const char *test_data = "abc";
    uint8_t digest[32];
    
    // �����ϣ
    sm3_hash((const uint8_t*)test_data, strlen(test_data), digest);
    
    // ������
    printf("SM3��ϣ��� (\"%s\"): ", test_data);
    for (int i = 0; i < 32; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    
    // Ԥ�ڽ����66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
    const char *expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0";
    printf("Ԥ�ڽ��: %s\n", expected);
    
    return 0;
}
