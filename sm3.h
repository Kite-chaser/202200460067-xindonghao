// sm3.h
#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// SM3 �����Ľṹ��
typedef struct {
    uint32_t state[8];       // ѹ������״̬
    uint64_t totalLength;    // ��Ϣ�ܳ��ȣ����أ�
    size_t bufferLength;     // ��ǰ���������ȣ��ֽڣ�
    uint8_t buffer[64];      // ��Ϣ��������64�ֽڿ飩
} SM3_CTX;

// ��������
void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t length);
void sm3_final(SM3_CTX *ctx, uint8_t digest[32]);
void sm3_hash(const uint8_t *data, size_t length, uint8_t digest[32]);
void sm3_hash_optimized1(const uint8_t *data, size_t length, uint8_t digest[32]);

#endif
