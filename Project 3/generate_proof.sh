#!/bin/bash

# 步骤1: 编译Circom电路
echo "编译Poseidon2电路..."
circom poseidon2.circom --r1cs --wasm --sym
# 生成文件:
# - poseidon2.r1cs: 电路约束系统
# - poseidon2_js/: 包含WASM和生成见证的代码
# - poseidon2.sym: 符号表文件

# 步骤2: 准备输入数据
echo "准备输入数据..."
cat > input.json << EOF
{
    "expectedHash": 123456789,  // 替换为实际计算的哈希值
    "preimage": [987654321, 1122334455]  // 替换为实际的原象
}
EOF

# 步骤3: 生成见证(witness)
echo "生成见证..."
cd poseidon2_js
node generate_witness.js poseidon2.wasm ../input.json ../witness.wtns
cd ..

# 步骤4: 下载或生成Powers of Tau信任设置
echo "检查Powers of Tau文件..."
if [ ! -f "pot12_final.ptau" ]; then
    echo "下载Powers of Tau文件..."
    wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau -O pot12_final.ptau
fi

# 步骤5: 进行电路特定的信任设置
echo "进行Groth16信任设置..."
snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey

# 步骤6: 贡献到信任设置(可选但推荐)
echo "贡献到信任设置..."
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_0001.zkey \
    --name="First contribution" -v \
    --entropy="$(head -c 100 /dev/urandom | sha256sum | cut -d ' ' -f 1)"

# 步骤7: 导出验证密钥
echo "导出验证密钥..."
snarkjs zkey export verificationkey poseidon2_0001.zkey verification_key.json

# 步骤8: 生成证明
echo "生成零知识证明..."
snarkjs groth16 prove poseidon2_0001.zkey witness.wtns proof.json public.json

# 步骤9: 验证证明
echo "验证证明..."
snarkjs groth16 verify verification_key.json public.json proof.json

# 步骤10: 生成Solidity验证合约(可选，用于区块链上验证)
echo "生成Solidity验证合约..."
snarkjs zkey export solidityverifier poseidon2_0001.zkey verifier.sol
    
