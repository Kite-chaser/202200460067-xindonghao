#include <iostream>
#include <immintrin.h>
#include <wmmintrin.h>
#include <cstring>
#include <vector>

// SM4常量定义
constexpr uint32_t SM4_BLOCK_SIZE = 16;
constexpr uint32_t SM4_NUM_ROUNDS = 32;
constexpr uint32_t FK[4] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};
constexpr uint32_t CK[32] = {
    0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
    0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
    0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
    0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
    0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
    0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
    0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
    0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
};

// SM4 S盒
alignas(64) const uint8_t SM4_SBOX[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// T-table优化实现
class SM4_TTable {
public:
    SM4_TTable() {
        // 预计算T表
        for (int i = 0; i < 256; i++) {
            uint32_t s = SM4_SBOX[i];
            uint32_t t = (s << 24) | (s << 16) | (s << 8) | s;
            T0[i] = L_transform(t);
            T1[i] = ROTL(T0[i], 8);
            T2[i] = ROTL(T0[i], 16);
            T3[i] = ROTL(T0[i], 24);
        }
    }

    void encrypt(uint8_t out[16], const uint8_t in[16], const uint32_t rk[SM4_NUM_ROUNDS]) {
        uint32_t x[4];
        load_block(x, in);
        
        for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
            uint32_t t = x[1] ^ x[2] ^ x[3] ^ rk[i];
            uint32_t x4 = x[0] ^ T0[t & 0xFF] ^ T1[(t >> 8) & 0xFF] ^ 
                         T2[(t >> 16) & 0xFF] ^ T3[t >> 24];
            
            // 移位寄存器
            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = x4;
        }
        
        store_block(out, x[3], x[2], x[1], x[0]); // 反序输出
    }

private:
    alignas(64) uint32_t T0[256], T1[256], T2[256], T3[256];

    static inline uint32_t ROTL(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }

    static uint32_t L_transform(uint32_t b) {
        return b ^ ROTL(b, 2) ^ ROTL(b, 10) ^ ROTL(b, 18) ^ ROTL(b, 24);
    }

    void load_block(uint32_t x[4], const uint8_t in[16]) {
        x[0] = (in[0] << 24) | (in[1] << 16) | (in[2] << 8) | in[3];
        x[1] = (in[4] << 24) | (in[5] << 16) | (in[6] << 8) | in[7];
        x[2] = (in[8] << 24) | (in[9] << 16) | (in[10] << 8) | in[11];
        x[3] = (in[12] << 24) | (in[13] << 16) | (in[14] << 8) | in[15];
    }

    void store_block(uint8_t out[16], uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3) {
        for (int i = 0; i < 4; i++) {
            out[i]     = (x0 >> (24 - i*8)) & 0xFF;
            out[i+4]  = (x1 >> (24 - i*8)) & 0xFF;
            out[i+8]  = (x2 >> (24 - i*8)) & 0xFF;
            out[i+12] = (x3 >> (24 - i*8)) & 0xFF;
        }
    }
};

// 使用AES-NI优化的SM4实现
class SM4_AESNI {
public:
    void encrypt(uint8_t out[16], const uint8_t in[16], const uint32_t rk[SM4_NUM_ROUNDS]) {
        __m128i state = _mm_loadu_si128((const __m128i*)in);
        __m128i tmp;
        
        for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
            // 轮密钥加
            tmp = _mm_xor_si128(state, _mm_set1_epi32(rk[i]));
            
            // S盒变换（使用AES-NI近似）
            tmp = _mm_aesenc_si128(tmp, _mm_setzero_si128());
            
            // 线性变换
            state = linear_transform(tmp);
            
            // 移位寄存器
            state = _mm_shuffle_epi32(state, 0x39); // 循环左移32位
        }
        
        // 最终置换
        state = _mm_shuffle_epi32(state, 0x1B); // 反序
        _mm_storeu_si128((__m128i*)out, state);
    }

private:
    __m128i linear_transform(__m128i x) {
        __m128i t1 = _mm_xor_si128(x, _mm_rolv_epi32(x, _mm_set_epi32(0,0,0,2)));
        __m128i t2 = _mm_xor_si128(t1, _mm_rolv_epi32(x, _mm_set_epi32(0,0,0,10)));
        __m128i t3 = _mm_xor_si128(t2, _mm_rolv_epi32(x, _mm_set_epi32(0,0,0,18)));
        return _mm_xor_si128(t3, _mm_rolv_epi32(x, _mm_set_epi32(0,0,0,24)));
    }

    __m128i _mm_rolv_epi32(__m128i x, __m128i y) {
        return _mm_or_si128(_mm_sllv_epi32(x, y), 
                           _mm_srlv_epi32(x, _mm_sub_epi32(_mm_set1_epi32(32), y)));
    }
};

// SM4密钥扩展
void sm4_key_schedule(uint32_t rk[SM4_NUM_ROUNDS], const uint8_t key[16]) {
    uint32_t k[4];
    k[0] = (key[0] << 24) | (key[1] << 16) | (key[2] << 8) | key[3];
    k[1] = (key[4] << 24) | (key[5] << 16) | (key[6] << 8) | key[7];
    k[2] = (key[8] << 24) | (key[9] << 16) | (key[10] << 8) | key[11];
    k[3] = (key[12] << 24) | (key[13] << 16) | (key[14] << 8) | key[15];
    
    k[0] ^= FK[0]; k[1] ^= FK[1]; k[2] ^= FK[2]; k[3] ^= FK[3];
    
    SM4_TTable sm4; // 复用T-table实现
    uint8_t tmp[16];
    
    for (int i = 0; i < SM4_NUM_ROUNDS; i++) {
        uint32_t t = k[1] ^ k[2] ^ k[3] ^ CK[i];
        
        // 使用T-table计算F函数
        uint32_t x4 = k[0] ^ sm4.T0[t & 0xFF] ^ sm4.T1[(t >> 8) & 0xFF] ^ 
                     sm4.T2[(t >> 16) & 0xFF] ^ sm4.T3[t >> 24];
        
        rk[i] = x4;
        
        // 更新密钥状态
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = x4;
    }
}

// SM4-GCM实现
class SM4_GCM {
public:
    SM4_GCM(const uint8_t key[16]) {
        sm4_key_schedule(enc_rk, key);
        
        // 计算H = SM4(0)
        uint8_t zero[16] = {0};
        SM4_TTable().encrypt(H, zero, enc_rk);
        
        // 预计算H的幂次
        precompute_H_table();
    }

    void encrypt(uint8_t* ciphertext, uint8_t* tag, 
                const uint8_t* plaintext, size_t len,
                const uint8_t* iv, size_t iv_len,
                const uint8_t* aad, size_t aad_len) {
        // 初始化计数器
        uint8_t counter[16] = {0};
        init_counter(counter, iv, iv_len);
        
        // 加密数据
        ctr_mode(ciphertext, plaintext, len, counter);
        
        // 计算认证标签
        compute_tag(tag, ciphertext, len, aad, aad_len, counter);
    }

private:
    uint32_t enc_rk[SM4_NUM_ROUNDS];
    __m128i H;
    __m128i H_table[16][256]; // 4KB预计算表
    
    void precompute_H_table() {
        // 实现略，实际中应使用CLMUL指令优化
    }
    
    void init_counter(uint8_t counter[16], const uint8_t* iv, size_t iv_len) {
        // 简化的计数器初始化
        if (iv_len == 12) {
            memcpy(counter, iv, 12);
            counter[15] = 1;
        } else {
            // 更复杂的处理
            memcpy(counter, iv, std::min(iv_len, 16UL));
        }
    }
    
    void ctr_mode(uint8_t* out, const uint8_t* in, size_t len, uint8_t counter[16]) {
        SM4_TTable sm4;
        uint8_t keystream[16];
        uint32_t block_count = 0;
        
        for (size_t i = 0; i < len; i += 16) {
            // 生成密钥流
            sm4.encrypt(keystream, counter, enc_rk);
            
            // 计数器递增
            for (int j = 15; j >= 0; j--) {
                if (++counter[j] != 0) break;
            }
            
            // 异或加密
            size_t block_size = std::min<size_t>(16, len - i);
            for (size_t j = 0; j < block_size; j++) {
                out[i + j] = in[i + j] ^ keystream[j];
            }
        }
    }
    
    void compute_tag(uint8_t tag[16], const uint8_t* ciphertext, size_t ciphertext_len,
                    const uint8_t* aad, size_t aad_len, const uint8_t counter[16]) {
        // GHASH计算
        __m128i ghash = _mm_setzero_si128();
        
        // 处理AAD
        ghash_block(ghash, aad, aad_len);
        
        // 处理密文
        ghash_block(ghash, ciphertext, ciphertext_len);
        
        // 处理长度块
        __m128i len_block = _mm_set_epi64x(
            (static_cast<uint64_t>(aad_len) * 8) << 64,
            (static_cast<uint64_t>(ciphertext_len) * 8)
        );
        ghash = _mm_xor_si128(ghash, len_block);
        
        // 最终加密
        uint8_t final_block[16];
        SM4_TTable().encrypt(final_block, counter, enc_rk);
        
        // 生成标签
        for (int i = 0; i < 16; i++) {
            tag[i] = (reinterpret_cast<uint8_t*>(&ghash)[i] ^ final_block[i]);
        }
    }
    
    void ghash_block(__m128i& ghash, const uint8_t* data, size_t len) {
        // 简化的GHASH实现
        for (size_t i = 0; i < len; i += 16) {
            __m128i block = _mm_loadu_si128((const __m128i*)(data + i));
            ghash = _mm_xor_si128(ghash, block);
            // 实际中应使用GF乘法
            // ghash = gf_mult(ghash, H);
        }
    }
    
    // 实际中应使用PCLMULQDQ指令实现
    __m128i gf_mult(__m128i a, __m128i b) {
        // 简化的占位实现
        return _mm_xor_si128(a, b);
    }
};

// 测试函数
int main() {
    // 示例密钥和明文
    uint8_t key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t plaintext[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    uint8_t ciphertext[16], decrypted[16];
    
    // 密钥扩展
    uint32_t rk[SM4_NUM_ROUNDS];
    sm4_key_schedule(rk, key);
    
    // T-table加密
    SM4_TTable sm4_ttable;
    sm4_ttable.encrypt(ciphertext, plaintext, rk);
    
    std::cout << "SM4-TTable Ciphertext: ";
    for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    std::cout << "\n";
    
    // AES-NI加密（需要支持AES-NI的CPU）
    #ifdef __AES__
    SM4_AESNI sm4_aesni;
    sm4_aesni.encrypt(ciphertext, plaintext, rk);
    
    std::cout << "SM4-AESNI Ciphertext: ";
    for (int i = 0; i < 16; i++) printf("%02x ", ciphertext[i]);
    std::cout << "\n";
    #endif
    
    // SM4-GCM测试
    uint8_t iv[12] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b};
    uint8_t aad[20] = {0x54,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x41,0x41,0x44};
    uint8_t tag[16];
    uint8_t long_plaintext[64] = { /* 64字节测试数据 */ };
    uint8_t long_ciphertext[64];
    
    SM4_GCM gcm(key);
    gcm.encrypt(long_ciphertext, tag, long_plaintext, 64, iv, 12, aad, 11);
    
    std::cout << "GCM Tag: ";
    for (int i = 0; i < 16; i++) printf("%02x ", tag[i]);
    std::cout << "\n";
    
    return 0;
}
