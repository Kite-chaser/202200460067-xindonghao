import sys

class SM3:
    """SM3哈希算法实现"""
    # 初始向量
    IV = [
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    ]
    
    # 常量T
    T = [0x79CC4519] * 16 + [0x7A879D8A] * 48
    
    @staticmethod
    def rotate_left(x, n):
        """循环左移n位"""
        return ((x << n) & 0xFFFFFFFF) | ((x >> (32 - n)) & 0xFFFFFFFF)
    
    @staticmethod
    def FF_j(X, Y, Z, j):
        """布尔函数FF_j"""
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (X & Z) | (Y & Z)
    
    @staticmethod
    def GG_j(X, Y, Z, j):
        """布尔函数GG_j"""
        if 0 <= j <= 15:
            return X ^ Y ^ Z
        else:
            return (X & Y) | (~X & Z)
    
    @staticmethod
    def P0(X):
        """置换函数P0"""
        return X ^ SM3.rotate_left(X, 9) ^ SM3.rotate_left(X, 17)
    
    @staticmethod
    def P1(X):
        """置换函数P1"""
        return X ^ SM3.rotate_left(X, 15) ^ SM3.rotate_left(X, 23)
    
    @staticmethod
    def padding(message, total_bit_length=None):
        """对消息进行填充"""
        if total_bit_length is None:
            total_bit_length = len(message) * 8
        
        message = bytearray(message)
        message.append(0x80)  # 添加分隔符
        
        # 填充0直到满足长度要求
        while (len(message) * 8) % 512 != 448:
            message.append(0x00)
        
        # 添加总长度（64位）
        message += total_bit_length.to_bytes(8, byteorder='big')
        return bytes(message)
    
    @staticmethod
    def message_extension(B):
        """消息扩展"""
        if len(B) != 64:
            raise ValueError("消息分组必须为64字节")
        
        W = []
        # 提取16个32位字
        for i in range(16):
            start, end = i * 4, (i + 1) * 4
            W.append(int.from_bytes(B[start:end], byteorder='big'))
        
        # 扩展生成68个字
        for i in range(16, 68):
            val = (SM3.P1(W[i-16] ^ W[i-9] ^ SM3.rotate_left(W[i-3], 15)) 
                  ^ SM3.rotate_left(W[i-13], 7) ^ W[i-6]) & 0xFFFFFFFF
            W.append(val)
        
        # 生成W'数组
        W_prime = [W[i] ^ W[i+4] for i in range(64)]
        return W, W_prime
    
    @staticmethod
    def compression_function(V, B):
        """压缩函数"""
        A, B_reg, C, D, E, F, G, H = V
        W, W_prime = SM3.message_extension(B)
        
        for j in range(64):
            # 计算SS1和SS2
            SS1 = SM3.rotate_left((SM3.rotate_left(A, 12) + E + 
                                 SM3.rotate_left(SM3.T[j], j % 32)) & 0xFFFFFFFF, 7)
            SS2 = SS1 ^ SM3.rotate_left(A, 12)
            
            # 计算TT1和TT2
            TT1 = (SM3.FF_j(A, B_reg, C, j) + D + SS2 + W_prime[j]) & 0xFFFFFFFF
            TT2 = (SM3.GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
            
            # 更新寄存器
            D, C, B_reg, A = C, SM3.rotate_left(B_reg, 9), A, TT1
            H, G, F, E = G, SM3.rotate_left(F, 19), E, SM3.P0(TT2)
        
        # 与初始状态异或
        return [
            (A ^ V[0]) & 0xFFFFFFFF,
            (B_reg ^ V[1]) & 0xFFFFFFFF,
            (C ^ V[2]) & 0xFFFFFFFF,
            (D ^ V[3]) & 0xFFFFFFFF,
            (E ^ V[4]) & 0xFFFFFFFF,
            (F ^ V[5]) & 0xFFFFFFFF,
            (G ^ V[6]) & 0xFFFFFFFF,
            (H ^ V[7]) & 0xFFFFFFFF
        ]
    
    @staticmethod
    def hash(message, initial_vector=None, total_bit_length=None):
        """计算消息的SM3哈希值"""
        V = SM3.IV.copy() if initial_vector is None else initial_vector.copy()
        padded_message = SM3.padding(message, total_bit_length)
        
        # 按64字节分组处理
        for i in range(0, len(padded_message), 64):
            B = padded_message[i:i+64]
            V = SM3.compression_function(V, B)
        
        # 转换为十六进制字符串
        return ''.join(f'{x:08x}' for x in V)


class LengthExtensionAttacker:
    """SM3长度扩展攻击实现"""
    
    @staticmethod
    def attack(original_hash, original_length, append_data):
        """
        执行长度扩展攻击
        original_hash: 原始消息的哈希值
        original_length: 原始消息的长度（字节）
        append_data: 要附加的数据
        返回: 扩展消息的哈希值
        """
        # 将原始哈希转换为初始向量
        hash_bytes = bytes.fromhex(original_hash)
        initial_vector = [
            int.from_bytes(hash_bytes[i*4:(i+1)*4], byteorder='big')
            for i in range(8)
        ]
        
        # 计算原始消息填充后的长度
        padding_length = (64 - (original_length + 9) % 64) % 64
        original_padded_length = original_length + 1 + padding_length + 8
        
        # 计算扩展后的总长度（比特）
        total_length = original_padded_length + len(append_data)
        total_bit_length = total_length * 8
        
        # 计算扩展消息的哈希
        return SM3.hash(append_data, initial_vector, total_bit_length)


def verify_attack():
    """验证长度扩展攻击的演示函数"""
    # 原始消息（攻击者不知道内容）
    original_message = b"secret_key"
    print(f"原始消息: {original_message.decode()}")
    
    # 计算原始消息的哈希和长度（攻击者已知的信息）
    original_hash = SM3.hash(original_message)
    original_length = len(original_message)
    print(f"原始哈希值: {original_hash}")
    print(f"原始消息长度: {original_length}字节")
    
    # 攻击者要附加的数据
    append_data = b"&user=admin&password=123&"
    print(f"附加数据: {append_data.decode()}")
    
    # 执行攻击
    attacker = LengthExtensionAttacker()
    attack_hash = attacker.attack(original_hash, original_length, append_data)
    print(f"攻击生成的哈希: {attack_hash}")
    
    # 计算实际扩展消息的哈希（用于验证）
    padded_original = SM3.padding(original_message)
    full_extended = padded_original + append_data
    actual_hash = SM3.hash(full_extended)
    print(f"实际扩展消息哈希: {actual_hash}")
    
    # 验证结果
    if attack_hash == actual_hash:
        print("长度扩展攻击成功！")
    else:
        print("长度扩展攻击失败！")


if __name__ == "__main__":
    verify_attack()
