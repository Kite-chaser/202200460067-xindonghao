import random
from hashlib import sha256

# SM2推荐的椭圆曲线参数 (GBT 32918.1-2016)
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

def mod_inverse(a, m):
    """模逆运算"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        return None  # 逆元不存在
    else:
        return x % m

def extended_gcd(a, b):
    """扩展欧几里得算法"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

class Point:
    """椭圆曲线上的点"""
    def __init__(self, x, y, is_infinity=False):
        self.x = x % p
        self.y = y % p
        self.is_infinity = is_infinity
    
    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y
    
    def __repr__(self):
        if self.is_infinity:
            return "Point(infinity)"
        return f"Point({hex(self.x)}, {hex(self.y)})"

def point_add(p1, p2):
    """椭圆曲线点加法"""
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    if p1.x == p2.x and p1.y != p2.y:
        return Point(0, 0, True)  # 无穷远点
    
    if p1 != p2:
        # 不同点相加
        dx = (p2.x - p1.x) % p
        dy = (p2.y - p1.y) % p
        inv_dx = mod_inverse(dx, p)
        if inv_dx is None:
            return Point(0, 0, True)  # 逆元不存在，返回无穷远点
        lam = (dy * inv_dx) % p
    else:
        # 同一点加倍
        dy = (2 * p1.y) % p
        inv_dy = mod_inverse(dy, p)
        if inv_dy is None:
            return Point(0, 0, True)  # 逆元不存在，返回无穷远点
        lam = ((3 * p1.x * p1.x + a) * inv_dy) % p
    
    x3 = (lam * lam - p1.x - p2.x) % p
    y3 = (lam * (p1.x - x3) - p1.y) % p
    return Point(x3, y3)

def point_multiply(p, k):
    """椭圆曲线点乘法（倍点加法）"""
    result = Point(0, 0, True)  # 无穷远点
    current = p
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2
    return result

# 生成SM2密钥对
def generate_key_pair():
    """生成SM2密钥对"""
    d = random.randint(1, n-2)  # 私钥
    Q = point_multiply(Point(Gx, Gy), d)  # 公钥
    return d, Q

def sm3_hash(msg):
    """简化实现的SM3哈希（实际应用中应使用标准实现）"""
    # 这里使用sha256代替SM3作为演示
    return int.from_bytes(sha256(msg).digest(), byteorder='big')

def sm2_sign(d, msg):
    """SM2签名算法"""
    e = sm3_hash(msg)
    while True:
        k = random.randint(1, n-1)
        P = point_multiply(Point(Gx, Gy), k)
        r = (e + P.x) % n
        if r == 0 or r + k == n:
            continue
        s = (mod_inverse(1 + d, n) * (k - r * d)) % n
        if s != 0:
            break
    return (r, s)

def sm2_verify(Q, msg, signature):
    """SM2验证算法"""
    r, s = signature
    if r < 1 or r > n-1 or s < 1 or s > n-1:
        return False
    
    e = sm3_hash(msg)
    t = (r + s) % n
    if t == 0:
        return False
    
    P1 = point_multiply(Point(Gx, Gy), s)
    P2 = point_multiply(Q, t)
    P = point_add(P1, P2)
    
    if P.is_infinity:
        return False
    
    return (e + P.x) % n == r

# 示例用法
if __name__ == "__main__":
    # 生成密钥对
    private_key, public_key = generate_key_pair()
    print(f"私钥: {hex(private_key)}")
    print(f"公钥: {public_key}")
    
    # 待签名消息
    message = b"Hello, SM2!"
    print(f"消息: {message.decode()}")
    
    # 签名
    signature = sm2_sign(private_key, message)
    print(f"签名: (r={hex(signature[0])}, s={hex(signature[1])})")
    
    # 验证
    valid = sm2_verify(public_key, message, signature)
    print(f"验证结果: {'成功' if valid else '失败'}")
