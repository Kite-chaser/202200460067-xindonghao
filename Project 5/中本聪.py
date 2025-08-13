import hashlib
import binascii
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

def generate_key_pair():
    """生成ECDSA密钥对（私钥和公钥），使用比特币的secp256k1曲线"""
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    
    return private_key, public_key

def sign_message(private_key, message):
    """使用私钥对消息进行签名"""
    # 验证输入确实是私钥
    if not isinstance(private_key, SigningKey):
        raise TypeError("签名必须使用私钥(SigningKey)，而不是公钥(VerifyingKey)")
    
    # 先对消息进行SHA-256哈希
    hashed_message = hashlib.sha256(message.encode()).digest()
    
    # 使用私钥对哈希后的消息进行签名
    signature = private_key.sign(hashed_message)
    
    return signature

def verify_signature(public_key, message, signature):
    """使用公钥验证签名的有效性"""
    # 验证输入确实是公钥
    if not isinstance(public_key, VerifyingKey):
        raise TypeError("验证必须使用公钥(VerifyingKey)，而不是私钥(SigningKey)")
    
    try:
        # 对消息进行同样的哈希处理
        hashed_message = hashlib.sha256(message.encode()).digest()
        
        # 使用公钥验证签名
        public_key.verify(signature, hashed_message)
        return True
    except BadSignatureError:
        return False
    except Exception as e:
        print(f"验证过程出错: {str(e)}")
        return False

def main():
    # 生成密钥对
    private_key, public_key = generate_key_pair()
    print(f"私钥: {binascii.hexlify(private_key.to_string()).decode()[:32]}... (省略部分字符)")
    print(f"公钥: {binascii.hexlify(public_key.to_string()).decode()[:32]}... (省略部分字符)")
    
    # 原始消息
    original_message = "这是中本聪风格的数字签名演示 - 原始消息"
    print(f"\n原始消息: {original_message}")
    
    # 对消息进行签名（正确用法：使用私钥）
    try:
        signature = sign_message(private_key, original_message)
        print(f"签名结果: {binascii.hexlify(signature).decode()[:64]}... (省略部分字符)")
    except TypeError as e:
        print(f"签名失败: {str(e)}")
        return
    
    # 验证签名（正确用法：使用公钥）
    is_valid = verify_signature(public_key, original_message, signature)
    print(f"\n签名验证结果: {'有效' if is_valid else '无效'}")
    
    # 演示错误用法：尝试用公钥签名
    try:
        print("\n尝试用公钥签名:")
        sign_message(public_key, original_message)
    except TypeError as e:
        print(f"预期错误: {str(e)}")

if __name__ == "__main__":
    main()
    
