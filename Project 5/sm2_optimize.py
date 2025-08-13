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
    # 这里使用sha256代替SM3作为演示，先将字符串编码为字节
    return int.from_bytes(sha256(msg).digest(), byteorder='big')

def sm2_sign(d, msg, multiply_func=point_multiply):
    """SM2签名算法，可指定点乘法函数"""
    # 对消息进行编码后再哈希
    e = sm3_hash(msg.encode('utf-8'))
    while True:
        k = random.randint(1, n-1)
        P = multiply_func(Point(Gx, Gy), k)
        r = (e + P.x) % n
        if r == 0 or r + k == n:
            continue
        s = (mod_inverse(1 + d, n) * (k - r * d)) % n
        if s != 0:
            break
    return (r, s)

def sm2_verify(Q, msg, signature, multiply_func=point_multiply):
    """SM2验证算法，可指定点乘法函数"""
    r, s = signature
    if r < 1 or r > n-1 or s < 1 or s > n-1:
        return False
    
    # 对消息进行编码后再哈希
    e = sm3_hash(msg.encode('utf-8'))
    t = (r + s) % n
    if t == 0:
        return False
    
    P1 = multiply_func(Point(Gx, Gy), s)
    P2 = multiply_func(Q, t)
    P = point_add(P1, P2)
    
    if P.is_infinity:
        return False
    
    return (e + P.x) % n == r

# 1. 使用窗口法优化点乘法
def point_multiply_window(p, k, window_size=4):
    """使用窗口法优化点乘法"""
    # 预计算窗口表
    def precompute_table(p, window_size):
        table = [Point(0, 0, True)]  # 无穷远点
        current = p
        # 预计算1,3,5,...,2^window_size-1倍的点
        for i in range(1, 2**window_size, 2):
            table.append(current)
            current = point_add(current, point_multiply(p, 2))
        return table
    
    table = precompute_table(p, window_size)
    result = Point(0, 0, True)
    bits = bin(k)[2:]  # 转换为二进制字符串
    # 补齐为window_size的整数倍
    bits = bits.zfill((len(bits) + window_size - 1) // window_size * window_size)
    
    for i in range(0, len(bits), window_size):
        window = bits[i:i+window_size]
        if window == '0' * window_size:
            result = point_add(result, result)  # 左移一位
            continue
        
        # 找到窗口中的第一个1
        first_one = window.find('1')
        if first_one == -1:
            result = point_add(result, result)
            continue
            
        # 提取有效位并转换为整数（应为奇数）
        value = int(window[first_one:], 2)
        # 移位
        for _ in range(first_one):
            result = point_add(result, result)
        
        # 修正索引计算：table的索引为(value + 1) // 2
        result = point_add(result, table[(value + 1) // 2])
    
    return result

# 2. 抗侧信道攻击的点乘法实现
def point_multiply_secure(p, k):
    """抗简单功耗分析的点乘法实现（固定模式）"""
    result = Point(0, 0, True)
    current = p
    # 将k转换为固定长度的二进制表示
    bits = bin(k)[2:].zfill(256)  # 假设k为256位
    
    for bit in bits:
        # 每一步都执行相同的操作序列，无论bit是0还是1
        temp = point_add(result, current)
        # 根据bit选择结果，但使用条件移动而非条件分支
        result = temp if bit == '1' else result
        current = point_add(current, current)
    
    return result

# 3. 结合密钥封装机制
def sm2_key_encapsulation(Q):
    """SM2密钥封装（KEK）"""
    k = random.randint(1, n-1)
    C1 = point_multiply(Point(Gx, Gy), k)
    S = point_multiply(Q, k)
    # 从S中提取共享密钥
    shared_key = sha256((hex(S.x) + hex(S.y)).encode()).digest()
    return C1, shared_key

def sm2_key_decapsulation(d, C1):
    """SM2密钥解封装"""
    S = point_multiply(C1, d)
    shared_key = sha256((hex(S.x) + hex(S.y)).encode()).digest()
    return shared_key

# 4. 批处理验证优化
def sm2_batch_verify(public_keys, messages, signatures):
    """批处理验证多个签名，提高效率"""
    if len(public_keys) != len(messages) or len(messages) != len(signatures):
        raise ValueError("输入长度不匹配")
    
    n_sigs = len(signatures)
    if n_sigs == 0:
        return []
    
    # 生成随机数作为批处理系数
    c = [random.randint(1, n-1) for _ in range(n_sigs)]
    
    # 计算总和
    sum_r = 0
    sum_s = 0
    sum_e = 0
    P_total = Point(0, 0, True)
    
    for i in range(n_sigs):
        Q = public_keys[i]
        msg = messages[i]
        r, s = signatures[i]
        
        # 验证单个签名的基本条件
        if r < 1 or r > n-1 or s < 1 or s > n-1:
            return [False] * n_sigs  # 简化处理，实际应单独验证
        
        # 对消息进行编码后再哈希
        e = sm3_hash(msg.encode('utf-8'))
        ti = (r + s) % n
        
        # 累加值
        sum_r = (sum_r + c[i] * r) % n
        sum_s = (sum_s + c[i] * s) % n
        sum_e = (sum_e + c[i] * e) % n
        
        # 累加点
        Qi_ci = point_multiply(Q, (c[i] * ti) % n)
        P_total = point_add(P_total, Qi_ci)
    
    # 计算最终验证点
    G_sum_s = point_multiply(Point(Gx, Gy), sum_s)
    P = point_add(G_sum_s, P_total)
    
    # 检查批处理结果
    batch_result = (sum_e + P.x) % n == sum_r
    
    # 简化处理：如果批处理失败，需要逐个验证
    if not batch_result:
        return [sm2_verify(public_keys[i], messages[i], signatures[i]) 
                for i in range(n_sigs)]
    
    return [True] * n_sigs

# 验证示例代码
if __name__ == "__main__":
    import time
    
    # 生成密钥对
    private_key, public_key = generate_key_pair()
    print(f"私钥: {hex(private_key)[:30]}...")  # 简化显示
    print(f"公钥: {public_key}\n")
    
    # 测试消息（支持中文）
    messages = [
        "SM2优化算法测试消息 1",
        "SM2椭圆曲线密码算法批处理验证测试",
        "这是一个用于测试抗侧信道攻击实现的消息",
        "窗口法点乘法效率测试消息"
    ]
    
    # 1. 测试不同点乘法的签名验证
    multiply_methods = {
        "普通点乘法": point_multiply,
        "窗口法优化点乘法": point_multiply_window,
        "抗侧信道点乘法": point_multiply_secure
    }
    
    for name, method in multiply_methods.items():
        print(f"\n--- 测试{name} ---")
        start_time = time.time()
        signature = sm2_sign(private_key, messages[0], method)
        sign_time = time.time() - start_time
        
        start_time = time.time()
        valid = sm2_verify(public_key, messages[0], signature, method)
        verify_time = time.time() - start_time
        
        print(f"签名: (r={hex(signature[0])[:20]}..., s={hex(signature[1])[:20]}...)")
        print(f"验证结果: {'成功' if valid else '失败'}")
        print(f"签名时间: {sign_time:.6f}秒")
        print(f"验证时间: {verify_time:.6f}秒")
    
    # 2. 测试密钥封装与解封装
    print("\n--- 测试密钥封装与解封装 ---")
    C1, enc_key = sm2_key_encapsulation(public_key)
    dec_key = sm2_key_decapsulation(private_key, C1)
    print(f"封装密钥: {enc_key.hex()[:20]}...")
    print(f"解封装密钥: {dec_key.hex()[:20]}...")
    print(f"密钥匹配: {'成功' if enc_key == dec_key else '失败'}")
    
    # 3. 测试批处理验证
    print("\n--- 测试批处理验证 ---")
    # 生成多个签名
    signatures = [sm2_sign(private_key, msg) for msg in messages]
    public_keys = [public_key] * len(messages)  # 所有签名使用同一公钥
    
    start_time = time.time()
    batch_results = sm2_batch_verify(public_keys, messages, signatures)
    batch_time = time.time() - start_time
    
    # 对比单独验证
    start_time = time.time()
    individual_results = [sm2_verify(public_keys[i], messages[i], signatures[i]) 
                         for i in range(len(messages))]
    individual_time = time.time() - start_time
    
    print(f"批处理验证结果: {batch_results}")
    print(f"单独验证结果: {individual_results}")
    print(f"批处理时间: {batch_time:.6f}秒")
    print(f"单独验证时间: {individual_time:.6f}秒")
    print(f"结果一致性: {'一致' if batch_results == individual_results else '不一致'}")
    
    # 4. 测试篡改消息验证
    print("\n--- 测试篡改消息验证 ---")
    tampered_msg = "原始消息被篡改了!!!"
    signature = sm2_sign(private_key, messages[0])
    valid = sm2_verify(public_key, tampered_msg, signature)
    print(f"篡改消息验证结果: {'成功' if valid else '失败'} (预期失败)")
