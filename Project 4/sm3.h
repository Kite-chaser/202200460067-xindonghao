// sm3.h
#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// SM3 上下文结构体
typedef struct {
    uint32_t state[8];       // 压缩函数状态
    uint64_t totalLength;    // 消息总长度（比特）
    size_t bufferLength;     // 当前缓冲区长度（字节）
    uint8_t buffer[64];      // 消息缓冲区（64字节块）
} SM3_CTX;

// 函数声明
void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t length);
void sm3_final(SM3_CTX *ctx, uint8_t digest[32]);
void sm3_hash(const uint8_t *data, size_t length, uint8_t digest[32]);
void sm3_hash_optimized1(const uint8_t *data, size_t length, uint8_t digest[32]);

#endif
