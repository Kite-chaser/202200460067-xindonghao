import struct
import random

class SM4:
    """SM4分组密码算法实现"""
    # 系统参数和固定密钥
    Sbox = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x4d, 0x39, 0xc8,
        0x57, 0x11, 0xd9, 0x03, 0xdb, 0x53, 0x0a, 0x0c, 0x32, 0xc7, 0x23, 0x0d, 0x55, 0x9b, 0xe3, 0x2f,
        0xaf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe0, 0x3e, 0xb5, 0x66, 0x48, 0x02, 0xf5, 0x5a, 0x65, 0x7a,
        0x87, 0xd0, 0x21, 0x10, 0x7d, 0x29, 0xe5, 0x7a, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa1, 0x93, 0x9e,
        0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc4, 0x18, 0xf7, 0xdc, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x82,
        0xf2, 0x8a, 0x81, 0x6d, 0xb8, 0x1b, 0xaf, 0x84, 0x56, 0x75, 0xb9, 0xda, 0x8e, 0x15, 0x46, 0x5b,
        0x5d, 0x93, 0x84, 0x12, 0x81, 0x12, 0x71, 0x28, 0x76, 0x7b, 0x73, 0x76, 0x1e, 0xa7, 0x6d, 0x6e,
        0x6a, 0x64, 0x5d, 0x8b, 0x1e, 0x1b, 0x74, 0x65, 0x4a, 0x1a, 0x68, 0x59, 0x2c, 0x07, 0x63, 0x5c,
        0x25, 0x78, 0x86, 0x30, 0x6e, 0x0f, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc4, 0x18, 0xf7, 0xdc,
        0xca, 0x83, 0x5d, 0x96, 0x60, 0xa7, 0x38, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x88
    ]

    # 固定参数FK和CK
    FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
    CK = [
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    ]

    def __init__(self, key):
        """初始化SM4加密器/解密器，生成轮密钥"""
        self.key = key
        self.round_keys = self._generate_round_keys()

    def _rotate_left(self, x, n):
        """循环左移n位"""
        return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)

    def _sbox_transform(self, x):
        """S盒变换"""
        return self.Sbox[x]

    def _t_transform(self, x):
        """T变换：S盒变换后进行线性变换"""
        # 拆分为4个字节
        bytes_ = [(x >> i) & 0xFF for i in [24, 16, 8, 0]]
        # S盒变换
        s_bytes = [self._sbox_transform(b) for b in bytes_]
        # 重组为32位整数
        s = (s_bytes[0] << 24) | (s_bytes[1] << 16) | (s_bytes[2] << 8) | s_bytes[3]
        # 线性变换L
        return s ^ self._rotate_left(s, 13) ^ self._rotate_left(s, 23)

    def _generate_round_keys(self):
        """生成32轮轮密钥"""
        # 密钥扩展
        MK = [(self.key >> (96 - i * 32)) & 0xFFFFFFFF for i in range(4)]
        K = [MK[i] ^ self.FK[i] for i in range(4)]
        
        round_keys = []
        for i in range(32):
            # 生成轮密钥
            k = K[(i + 1) % 4] ^ self._t_transform(
                K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ self.CK[i]
            )
            round_keys.append(k)
            K.append(k)
        
        return round_keys

    def _block_encrypt(self, block):
        """加密一个128位数据块"""
        # 将输入块拆分为4个32位字
        X = [(block >> (96 - i * 32)) & 0xFFFFFFFF for i in range(4)]
        
        # 32轮迭代
        for i in range(32):
            X.append(X[i] ^ self._t_transform(X[i+1] ^ X[i+2] ^ X[i+3] ^ self.round_keys[i]))
        
        # 输出变换
        cipher_block = (X[35] << 96) | (X[34] << 64) | (X[33] << 32) | X[32]
        return cipher_block

    def encrypt_block(self, block):
        """加密一个16字节的数据块"""
        if len(block) != 16:
            raise ValueError("SM4加密块必须是16字节")
        # 转换为128位整数
        block_int = int.from_bytes(block, byteorder='big')
        # 加密
        cipher_int = self._block_encrypt(block_int)
        # 转换回字节
        return cipher_int.to_bytes(16, byteorder='big')


class SM4GCM:
    """SM4-GCM认证加密模式实现"""
    
    def __init__(self, key, nonce=None):
        """初始化SM4-GCM实例"""
        self.sm4 = SM4(self._key_to_int(key))
        self.nonce = nonce if nonce is not None else b'\x00' * 12  # 默认12字节nonce
        self.H = self.sm4.encrypt_block(b'\x00' * 16)  # 哈希子密钥
        self.J0 = self._compute_j0()  # 初始计数器值
        
        # 预计算GHASH的部分乘积，优化认证计算
        self._precompute_ghash_table()
    
    @staticmethod
    def _key_to_int(key):
        """将密钥字节转换为32位整数列表"""
        if len(key) != 16:
            raise ValueError("SM4密钥必须是16字节")
        return int.from_bytes(key, byteorder='big')
    
    def _compute_j0(self):
        """计算初始计数器值J0"""
        if len(self.nonce) == 12:
            # 对于12字节nonce，按特殊规则计算J0
            return self.nonce + b'\x00\x00\x00\x01'
        else:
            # 对于其他长度nonce，使用GHASH计算
            len_bits = len(self.nonce) * 8
            len_bytes = len_bits.to_bytes(8, byteorder='big')
            return self.ghash(b'', self.nonce + b'\x00' * ((16 - len(self.nonce) % 16) % 16) + len_bytes)
    
    def _precompute_ghash_table(self):
        """预计算GHASH的乘法表，加速认证计算"""
        self.ghash_table = []
        h = int.from_bytes(self.H, byteorder='big')
        
        # 预计算每个位的乘法结果 - 修复：将range(8)改为range(16)
        for i in range(16):
            row = []
            current_h = h  # 每次循环使用初始h值，避免上一次循环的修改影响结果
            for j in range(256):
                val = 0
                x = j
                for k in range(8):
                    if x & 1:
                        val ^= current_h
                    x >>= 1
                    # 伽罗瓦域乘法的移位操作
                    if current_h & 0x80000000000000000000000000000000:
                        current_h = (current_h << 1) ^ 0x87
                    else:
                        current_h <<= 1
                    current_h &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF  # 保持128位
                row.append(val.to_bytes(16, byteorder='big'))
            self.ghash_table.append(row)
    
    def ghash(self, auth_data, ciphertext):
        """优化的GHASH函数实现，用于计算认证标签"""
        # 组合数据并填充
        data = auth_data + ciphertext
        pad_length = (16 - len(data) % 16) % 16
        data += b'\x00' * pad_length
        
        # 添加长度信息
        al = len(auth_data) * 8
        cl = len(ciphertext) * 8
        data += al.to_bytes(8, byteorder='big')
        data += cl.to_bytes(8, byteorder='big')
        
        # 初始化哈希值
        hash_val = b'\x00' * 16
        
        # 处理每个16字节块
        for i in range(0, len(data), 16):
            block = data[i:i+16]
            # 异或当前块与哈希值
            x = bytes(a ^ b for a, b in zip(hash_val, block))
            
            # 使用预计算表加速伽罗瓦乘法
            y = [0] * 16
            for j in range(16):
                y[j] = self.ghash_table[j][x[j]]
            
            # 累加结果
            hash_val = b'\x00' * 16
            for j in range(16):
                hash_val = bytes(
                    (hash_val[k] ^ y[j][k]) for k in range(16)
                )
        
        return hash_val
    
    def ctr_encrypt(self, plaintext):
        """CTR模式加密"""
        ciphertext = b''
        counter = int.from_bytes(self.J0, byteorder='big')
        
        # 处理每个块
        for i in range(0, len(plaintext), 16):
            block = plaintext[i:i+16]
            
            # 加密计数器值作为密钥流
            counter_bytes = counter.to_bytes(16, byteorder='big')
            keystream = self.sm4.encrypt_block(counter_bytes)
            
            # 异或得到密文
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext += cipher_block
            
            # 递增计数器
            counter += 1
        
        return ciphertext
    
    def encrypt_and_tag(self, plaintext, auth_data=b'', tag_length=16):
        """加密并生成认证标签"""
        if tag_length not in [4, 8, 12, 13, 14, 15, 16]:
            raise ValueError("标签长度必须是4, 8, 12, 13, 14, 15或16字节")
            
        # 加密
        ciphertext = self.ctr_encrypt(plaintext)
        
        # 计算认证标签
        tag = self.ghash(auth_data, ciphertext)
        
        # 用初始计数器加密标签
        tag_encrypted = self.sm4.encrypt_block(self.J0)
        tag = bytes(a ^ b for a, b in zip(tag, tag_encrypted))
        
        # 返回指定长度的标签
        return ciphertext, tag[:tag_length]
    
    def decrypt_and_verify(self, ciphertext, tag, auth_data=b'', tag_length=16):
        """解密并验证认证标签"""
        if len(tag) != tag_length:
            raise ValueError("标签长度不匹配")
            
        # 解密
        plaintext = self.ctr_encrypt(ciphertext)  # CTR模式解密与加密相同
        
        # 计算认证标签
        computed_tag = self.ghash(auth_data, ciphertext)
        
        # 用初始计数器加密计算的标签
        tag_encrypted = self.sm4.encrypt_block(self.J0)
        computed_tag = bytes(a ^ b for a, b in zip(computed_tag, tag_encrypted))
        
        # 验证标签（使用常数时间比较防止侧信道攻击）
        if self._constant_time_compare(tag, computed_tag[:tag_length]):
            return plaintext
        else:
            raise ValueError("认证失败：标签不匹配")
    
    @staticmethod
    def _constant_time_compare(a, b):
        """常数时间比较，防止侧信道攻击"""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0


# 示例用法
if __name__ == "__main__":
    # 生成随机密钥和nonce
    def generate_random_bytes(length):
        """生成指定长度的随机字节"""
        return bytes(random.getrandbits(8) for _ in range(length))
    
    key = generate_random_bytes(16)  # 16字节密钥
    nonce = generate_random_bytes(12)  # 12字节nonce
    
    # 待加密数据
    plaintext_str = "SM4-GCM"
    plaintext = plaintext_str.encode('utf-8')
    
    auth_data_str = "关联数据"
    auth_data = auth_data_str.encode('utf-8')
    
    # 创建SM4-GCM实例
    sm4gcm = SM4GCM(key, nonce)
    
    # 加密并生成标签
    ciphertext, tag = sm4gcm.encrypt_and_tag(plaintext, auth_data)
    print(f"密钥: {key.hex()}")
    print(f"Nonce: {nonce.hex()}")
    print(f"明文: {plaintext.hex()}")
    print(f"ADD: {auth_data.hex()}")
    print(f"密文: {ciphertext.hex()}")
    print(f"标签: {tag.hex()}")
    
    # 解密并验证
    try:
        decrypted = sm4gcm.decrypt_and_verify(ciphertext, tag, auth_data)
        print(f"解密结果: {decrypted.decode('utf-8')}")
        
        # 验证原始消息与解密消息是否一致
        assert decrypted == plaintext
        print("验证成功：解密消息与原始消息一致")
    except ValueError as e:
        print(f"验证失败: {e}")
