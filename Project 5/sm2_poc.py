import random

# SM2参数
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D541234
G = (0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
     0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0)

# 基础模运算函数
def mod_add(a, b, mod):
    return (a + b) % mod

def mod_sub(a, b, mod):
    return (a - b) % mod

def mod_mul(a, b, mod):
    return (a * b) % mod

def mod_inv(a, mod):
    """扩展欧几里得算法求模逆"""
    g, x, y = extended_gcd(a, mod)
    if g != 1:
        raise ValueError(f"模逆不存在 (gcd={g})")
    return x % mod

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extended_gcd(b % a, a)
        return g, x - (b // a) * y, y

# 生成符合条件的私钥（确保1+d与N互质）
def generate_valid_private_key():
    while True:
        d = random.randint(1, N-2)  # 保留足够空间确保1+d < N
        val = mod_add(1, d, N)
        g, _, _ = extended_gcd(val, N)
        if g == 1:
            return d

# 生成与N互质的随机数k
def generate_valid_k():
    while True:
        k = random.randint(1, N-1)
        g, _, _ = extended_gcd(k, N)
        if g == 1:
            return k

# 椭圆曲线点运算
def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
        
    x1, y1 = p
    x2, y2 = q
    
    # 确保所有坐标在模P范围内
    x1 %= P
    y1 %= P
    x2 %= P
    y2 %= P
    
    # 检查是否为逆元点
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
        
    if x1 == x2 and y1 == y2:
        # 点加倍
        x1_sq = mod_mul(x1, x1, P)
        numerator = mod_add(mod_mul(3, x1_sq, P), 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC, P)
        denominator = mod_mul(2, y1, P)
        lam = mod_mul(numerator, mod_inv(denominator, P), P)
    else:
        # 点加法
        dy = mod_sub(y2, y1, P)
        dx = mod_sub(x2, x1, P)
        lam = mod_mul(dy, mod_inv(dx, P), P)
        
    x3 = mod_sub(mod_mul(lam, lam, P), mod_add(x1, x2, P), P)
    y3 = mod_sub(mod_mul(lam, mod_sub(x1, x3, P), P), y1, P)
    
    return (x3, y3)

def point_mul(k, p):
    result = None
    current = p
    k = k % N  # 确保k在有效范围内
    
    while k > 0:
        if k & 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k >>= 1
        
    return result

# 签名生成
def sign(d, e):
    """生成SM2签名，返回(r, s, k)"""
    while True:
        k = generate_valid_k()  # 使用确保与N互质的k
        kG = point_mul(k, G)
        if kG is None:
            continue
            
        x1 = kG[0] % N
        r = mod_add(e, x1, N)
        
        if r == 0 or (r + k) % N == 0:
            continue
            
        # 计算s = (k - r*d) * inv(1 + d) mod N
        numerator = mod_sub(k, mod_mul(r, d, N), N)
        denominator = mod_inv(mod_add(1, d, N), N)
        s = mod_mul(numerator, denominator, N)
        
        # 检查：确保s + r与N互质，避免后续模逆计算失败
        denominator_check = mod_add(s, r, N)
        g, _, _ = extended_gcd(denominator_check, N)
        if g != 1:
            continue
            
        if s != 0:
            return r, s, k

# 测试场景1: 泄露随机数k导致私钥泄露
def test_scenario1():
    print("=== 测试场景1核心逻辑 ===")
    
    # 生成符合条件的私钥
    d = generate_valid_private_key()
    print(f"私钥 d: {hex(d)[:10]}...")
    
    # 固定消息哈希值
    e = 0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
    
    # 生成签名
    r, s, k = sign(d, e)
    print(f"签名 r: {hex(r)[:10]}..., s: {hex(s)[:10]}...")
    print(f"随机数 k: {hex(k)[:10]}...")
    
    # 从k推导私钥
    numerator = mod_sub(k, s, N)
    denominator = mod_inv(mod_add(s, r, N), N)
    d_derived = mod_mul(numerator, denominator, N)
    print(f"推导私钥: {hex(d_derived)[:10]}...")
    print(f"验证结果: {'成功' if d == d_derived else '失败'}\n")

# 测试场景2: 同一用户重复使用k导致私钥泄露
def test_scenario2():
    print("=== 测试场景2核心逻辑 ===")
    
    # 生成符合条件的私钥
    d = generate_valid_private_key()
    print(f"私钥 d: {hex(d)[:10]}...")
    
    # 固定随机数（确保与N互质）
    k = generate_valid_k()
    print(f"共享随机数 k: {hex(k)[:10]}...")
    
    # 第一个签名
    e1 = 0x1111111111111111111111111111111111111111111111111111111111111111
    kG = point_mul(k, G)
    x1 = kG[0] % N
    r1 = mod_add(e1, x1, N)
    s1_num = mod_sub(k, mod_mul(r1, d, N), N)
    s1_den = mod_inv(mod_add(1, d, N), N)
    s1 = mod_mul(s1_num, s1_den, N)
    print(f"签名1 r: {hex(r1)[:10]}..., s: {hex(s1)[:10]}...")
    
    # 第二个签名
    e2 = 0x2222222222222222222222222222222222222222222222222222222222222222
    x2 = kG[0] % N
    r2 = mod_add(e2, x2, N)
    s2_num = mod_sub(k, mod_mul(r2, d, N), N)
    s2_den = mod_inv(mod_add(1, d, N), N)
    s2 = mod_mul(s2_num, s2_den, N)
    print(f"签名2 r: {hex(r2)[:10]}..., s: {hex(s2)[:10]}...")
    
    # 推导私钥
    numerator = mod_sub(s2, s1, N)
    denominator = mod_sub(mod_add(s1, r1, N), mod_add(s2, r2, N), N)
    denominator = mod_inv(denominator, N)
    d_derived = mod_mul(numerator, denominator, N)
    print(f"推导私钥: {hex(d_derived)[:10]}...")
    print(f"验证结果: {'成功' if d == d_derived else '失败'}\n")

# 测试场景3: 不同用户重复使用k导致相互推导私钥
def test_scenario3():
    print("=== 测试场景3核心逻辑 ===")
    
    # 生成符合条件的私钥（确保1+d与N互质）
    d_a = generate_valid_private_key()
    d_b = generate_valid_private_key()
    print(f"Alice私钥: {hex(d_a)[:10]}...")
    print(f"Bob私钥: {hex(d_b)[:10]}...")
    
    # 验证1+d与N是否互质
    g_a, _, _ = extended_gcd(mod_add(1, d_a, N), N)
    g_b, _, _ = extended_gcd(mod_add(1, d_b, N), N)
    print(f"检查Alice的1+d与N互质: {'是' if g_a == 1 else '否'}")
    print(f"检查Bob的1+d与N互质: {'是' if g_b == 1 else '否'}")
    
    # 固定共享随机数（确保与N互质）
    k = generate_valid_k()
    print(f"共享随机数 k: {hex(k)[:10]}...")
    
    # Alice签名 - 添加检查确保s + r与N互质
    e_a = 0xAAAA111122223333444455556666777788889999AABBCCddeeff001122
    kG = point_mul(k, G)
    x_a = kG[0] % N
    r_a = mod_add(e_a, x_a, N)
    s_a_num = mod_sub(k, mod_mul(r_a, d_a, N), N)
    s_a_den = mod_inv(mod_add(1, d_a, N), N)
    s_a = mod_mul(s_a_num, s_a_den, N)
    
    # 检查并确保s_a + r_a与N互质
    g, _, _ = extended_gcd(mod_add(s_a, r_a, N), N)
    if g != 1:
        print("Alice签名不满足s + r与N互质，调整e_a重新生成签名...")
        e_a = (e_a + 1) % N  # 调整消息哈希值
        r_a = mod_add(e_a, x_a, N)
        s_a_num = mod_sub(k, mod_mul(r_a, d_a, N), N)
        s_a = mod_mul(s_a_num, s_a_den, N)
    
    print(f"Alice签名 r: {hex(r_a)[:10]}..., s: {hex(s_a)[:10]}...")
    
    # Bob签名 - 添加检查确保s + r与N互质
    e_b = 0xBBBB111122223333444455556666777788889999AABBCCddeeff001122
    x_b = kG[0] % N
    r_b = mod_add(e_b, x_b, N)
    s_b_num = mod_sub(k, mod_mul(r_b, d_b, N), N)
    s_b_den = mod_inv(mod_add(1, d_b, N), N)
    s_b = mod_mul(s_b_num, s_b_den, N)
    
    # 检查并确保s_b + r_b与N互质
    g, _, _ = extended_gcd(mod_add(s_b, r_b, N), N)
    if g != 1:
        print("Bob签名不满足s + r与N互质，调整e_b重新生成签名...")
        e_b = (e_b + 1) % N  # 调整消息哈希值
        r_b = mod_add(e_b, x_b, N)
        s_b_num = mod_sub(k, mod_mul(r_b, d_b, N), N)
        s_b = mod_mul(s_b_num, s_b_den, N)
    
    print(f"Bob签名 r: {hex(r_b)[:10]}..., s: {hex(s_b)[:10]}...")
    
    # 推导私钥
    d_a_derived = mod_mul(
        mod_sub(k, s_a, N),
        mod_inv(mod_add(s_a, r_a, N), N),
        N
    )
    
    d_b_derived = mod_mul(
        mod_sub(k, s_b, N),
        mod_inv(mod_add(s_b, r_b, N), N),
        N
    )
    
    print(f"推导Alice私钥: {hex(d_a_derived)[:10]}...")
    print(f"推导Bob私钥: {hex(d_b_derived)[:10]}...")
    print(f"验证结果: {'成功' if d_a == d_a_derived and d_b == d_b_derived else '失败'}\n")

# 测试场景4: 跨算法复用参数导致私钥泄露
def test_scenario4():
    print("=== 测试场景4核心逻辑 ===")
    
    # 生成符合条件的私钥
    d = generate_valid_private_key()
    print(f"私钥 d: {hex(d)[:10]}...")
    
    # 循环直到找到合适的k和签名，确保分母与N互质
    while True:
        # 生成与N互质的随机数k
        k = generate_valid_k()
        print(f"尝试随机数 k: {hex(k)[:10]}...")
        
        # ECDSA签名
        e_ecdsa = 0x112233445566778899AABBCCDEEFF00AABBCCddeeff112233445566
        kG = point_mul(k, G)
        x = kG[0] % N
        r_ecdsa = x % N
        s_ecdsa = mod_mul(
            mod_add(e_ecdsa, mod_mul(r_ecdsa, d, N), N),
            mod_inv(k, N),
            N
        )
        
        # SM2签名
        e_sm2 = 0x66778899AABBCCDEEFF00112233445566778899AABBCCDEEFF0011223344
        r_sm2 = mod_add(e_sm2, x, N)
        s_sm2 = mod_mul(
            mod_sub(k, mod_mul(r_sm2, d, N), N),
            mod_inv(mod_add(1, d, N), N),
            N
        )
        
        # 预计算分母并检查互质性
        denominator = mod_sub(
            r_ecdsa,
            mod_add(
                mod_mul(s_ecdsa, s_sm2, N),
                mod_mul(s_ecdsa, r_sm2, N),
                N
            ),
            N
        )
        
        # 检查分母与N是否互质
        g, _, _ = extended_gcd(denominator, N)
        if g == 1:
            print(f"找到合适的随机数 k: {hex(k)[:10]}...")
            break
        print(f"当前k导致分母与N的gcd={g}，重新生成k...")
    
    print(f"ECDSA签名 r: {hex(r_ecdsa)[:10]}..., s: {hex(s_ecdsa)[:10]}...")
    print(f"SM2签名 r: {hex(r_sm2)[:10]}..., s: {hex(s_sm2)[:10]}...")
    
    # 推导私钥: 联立方程求解
    numerator = mod_sub(
        mod_mul(s_ecdsa, s_sm2, N),
        e_ecdsa,
        N
    )
    
    d_derived = mod_mul(numerator, mod_inv(denominator, N), N)
    
    print(f"推导私钥: {hex(d_derived)[:10]}...")
    print(f"验证结果: {'成功' if d == d_derived else '失败'}\n")

if __name__ == "__main__":
    # 使用固定种子确保结果可复现
    random.seed(42)
    test_scenario1()
    test_scenario2()
    test_scenario3()
    test_scenario4()
    print("所有测试完成")
    
