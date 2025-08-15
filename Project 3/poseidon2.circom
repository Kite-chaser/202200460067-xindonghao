include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/comparators.circom";

// 选择参数配置 (n,t,d) = (256,3,5)
// 参考文档1的Table1，对应参数:
// - 哈希输出长度: 256 bits
// - 状态元素数量: 3
// - S-box指数: 5

template Poseidon2Hash() {
    // 定义输入输出信号
    signal private input preimage[2];  // 隐私输入：原象 (t-1=2个元素)
    signal output hash[1];             // 公开输出：哈希结果
    
    // 初始化状态：容量部分初始为0，速率部分为输入
    signal state[3];
    state[0] = preimage[0];
    state[1] = preimage[1];
    state[2] = 0;  // 容量元素初始为0
    
    // 轮常量 - 实际应用中应使用文档1中指定的官方常量
    // 这里仅为示例，实际部署需替换为正确的轮常量
    signal roundConstants[8][3];
    for (var r = 0; r < 8; r++) {
        for (var i = 0; i < 3; i++) {
            roundConstants[r][i] = (r + i) * 1234567;  // 示例值
        }
    }
    
    // 混合矩阵 - 实际应用中应使用文档1中指定的官方矩阵
    signal mixMatrix[3][3] = [
        [1, 2, 3],
        [4, 5, 6],
        [7, 8, 9]   // 示例矩阵，实际需替换
    ];
    
    // 完整轮数和部分轮数配置
    const FULL_ROUNDS = 8;
    const HALF_FULL_ROUNDS = FULL_ROUNDS / 2;
    const PARTIAL_ROUNDS = 4;
    
    // 前半部分完整轮
    for (var r = 0; r < HALF_FULL_ROUNDS; r++) {
        // AddRoundConstant
        for (var i = 0; i < 3; i++) {
            state[i] += roundConstants[r][i];
        }
        
        // SubWords - 所有元素都应用S-box
        for (var i = 0; i < 3; i++) {
            state[i] = state[i]^5;  // 使用d=5的S-box
        }
        
        // MixLayer - 线性混合
        signal newState[3];
        for (var i = 0; i < 3; i++) {
            newState[i] = 0;
            for (var j = 0; j < 3; j++) {
                newState[i] += state[j] * mixMatrix[i][j];
            }
        }
        for (var i = 0; i < 3; i++) {
            state[i] = newState[i];
        }
    }
    
    // 部分轮 - 只对一个元素应用S-box
    for (var r = 0; r < PARTIAL_ROUNDS; r++) {
        // AddRoundConstant
        for (var i = 0; i < 3; i++) {
            state[i] += roundConstants[HALF_FULL_ROUNDS + r][i];
        }
        
        // SubWords - 只对第一个元素应用S-box
        state[0] = state[0]^5;
        
        // MixLayer
        signal newState[3];
        for (var i = 0; i < 3; i++) {
            newState[i] = 0;
            for (var j = 0; j < 3; j++) {
                newState[i] += state[j] * mixMatrix[i][j];
            }
        }
        for (var i = 0; i < 3; i++) {
            state[i] = newState[i];
        }
    }
    
    // 后半部分完整轮
    for (var r = 0; r < HALF_FULL_ROUNDS; r++) {
        // AddRoundConstant
        for (var i = 0; i < 3; i++) {
            state[i] += roundConstants[HALF_FULL_ROUNDS + PARTIAL_ROUNDS + r][i];
        }
        
        // SubWords - 所有元素都应用S-box
        for (var i = 0; i < 3; i++) {
            state[i] = state[i]^5;
        }
        
        // MixLayer
        signal newState[3];
        for (var i = 0; i < 3; i++) {
            newState[i] = 0;
            for (var j = 0; j < 3; j++) {
                newState[i] += state[j] * mixMatrix[i][j];
            }
        }
        for (var i = 0; i < 3; i++) {
            state[i] = newState[i];
        }
    }
    
    // 输出哈希结果（取容量部分）
    hash[0] = state[2];
}

// 主组件：将哈希结果约束为公开输入
template Poseidon2Circuit() {
    signal input expectedHash;  // 公开输入：预期的哈希值
    signal private input preimage[2];  // 隐私输入：原象
    
    // 计算哈希值
    component hasher = Poseidon2Hash();
    hasher.preimage[0] <== preimage[0];
    hasher.preimage[1] <== preimage[1];
    
    // 约束计算得到的哈希值与预期哈希值相等
    expectedHash === hasher.hash[0];
}

// 实例化电路
component main = Poseidon2Circuit();
