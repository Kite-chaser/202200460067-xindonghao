import hashlib
import os
import random
from typing import Tuple, List, Dict

# 定义一些常量
HASH_LENGTH = 32  # SHA-256哈希长度
RANDOM_LENGTH = 16  # 随机数长度

def hash_password(password: str) -> bytes:
    """对密码进行哈希处理，使用SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).digest()

def generate_random_bytes(length: int = RANDOM_LENGTH) -> bytes:
    """生成指定长度的随机字节"""
    return os.urandom(length)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """对两个字节序列进行XOR操作"""
    return bytes(x ^ y for x, y in zip(a, b))

class User:
    """用户角色：希望检查自己的密码是否泄露"""
    
    def __init__(self, password: str):
        self.password = password
        self.h_p = hash_password(password)  # 密码的哈希值
        self.r = generate_random_bytes()    # 生成随机数r
        
    def prepare_data(self) -> Tuple[bytes, bytes]:
        """准备发送给服务器和辅助服务器的数据"""
        # 计算a = h_p XOR r
        a = xor_bytes(self.h_p, self.r)
        # 计算b = r
        b = self.r
        return a, b

class Server:
    """服务器角色：存储泄露密码的哈希集合"""
    
    def __init__(self, leaked_passwords: List[str]):
        # 存储泄露密码的哈希集合
        self.leaked_hashes = {hash_password(pwd) for pwd in leaked_passwords}
        # 生成服务器的随机数集合s_h
        self.salt_map = self._generate_salt_map()
        
    def _generate_salt_map(self) -> Dict[bytes, bytes]:
        """为每个泄露的哈希生成随机盐值"""
        return {h: generate_random_bytes() for h in self.leaked_hashes}
    
    def process_request(self, a: bytes) -> Dict[bytes, bytes]:
        """处理来自用户的请求，返回T集合"""
        T = {}
        for h in self.leaked_hashes:
            # 计算t = (h XOR s_h) XOR a
            t = xor_bytes(xor_bytes(h, self.salt_map[h]), a)
            T[t] = self.salt_map[h]
        return T

class Helper:
    """辅助服务器角色：协助进行隐私计算"""
    
    def process_request(self, b: bytes, T: Dict[bytes, bytes]) -> bool:
        """处理来自用户和服务器的数据，判断密码是否泄露"""
        for t, s_h in T.items():
            # 计算c = t XOR b XOR s_h
            c = xor_bytes(xor_bytes(t, b), s_h)
            # 如果c为全0字节序列，则密码在泄露集合中
            if all(byte == 0 for byte in c):
                return True
        return False

def simulate_protocol(user_password: str, leaked_passwords: List[str]) -> bool:
    """模拟整个密码检查协议"""
    # 初始化各参与方
    user = User(user_password)
    server = Server(leaked_passwords)
    
    # 用户准备数据
    a, b = user.prepare_data()
    
    # 服务器处理请求
    T = server.process_request(a)
    
    # 辅助服务器处理并判断结果
    helper = Helper()
    is_leaked = helper.process_request(b, T)
    
    return is_leaked

# 演示协议的使用
if __name__ == "__main__":
    # 模拟一些泄露的密码
    leaked_passwords = [
        "password123",
        "qwerty",
        "123456",
        "letmein",
        "secret"
    ]
    
    # 测试1：检查一个已泄露的密码
    test_password1 = "letmein"
    result1 = simulate_protocol(test_password1, leaked_passwords)
    print(f"密码 '{test_password1}' 是否泄露: {result1}")  # 应输出True
    
    # 测试2：检查一个未泄露的密码
    test_password2 = "MySecurePassword123!"
    result2 = simulate_protocol(test_password2, leaked_passwords)
    print(f"密码 '{test_password2}' 是否泄露: {result2}")  # 应输出False

