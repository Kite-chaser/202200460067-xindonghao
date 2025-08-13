import hashlib
from gmssl import sm3
from typing import List, Tuple, Optional, Union

# SM3哈希算法实现（使用gmssl库）
class SM3:
    @staticmethod
    def hash(data: bytes) -> bytes:
        """计算SM3哈希值"""
        return bytes.fromhex(sm3.sm3_hash(list(data)))

    @staticmethod
    def hash_int(n: int) -> bytes:
        """将整数转换为字节并计算哈希"""
        return SM3.hash(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))


# RFC6962 Merkle树实现
class RFC6962MerkleTree:
    def __init__(self, leaves: List[bytes]):
        """初始化Merkle树"""
        self.leaves = sorted(leaves)
        self.leaf_count = len(self.leaves)
        self.tree = self._build_tree()
        self.root = self.tree[0] if self.tree else b''

    def _build_tree(self) -> List[bytes]:
        """构建Merkle树"""
        if self.leaf_count == 0:
            return []
        
        # 计算叶子节点的哈希
        tree = [SM3.hash(leaf) for leaf in self.leaves]
        
        # 构建上层节点
        level_size = self.leaf_count
        level_start = 0
        
        while level_size > 1:
            next_level_size = (level_size + 1) // 2  # 向上取整
            for i in range(next_level_size):
                left = tree[level_start + 2 * i]
                # 如果没有右节点，使用左节点作为右节点
                right = tree[level_start + 2 * i + 1] if 2 * i + 1 < level_size else left
                # RFC6962规定父节点哈希为Hash(left || right)
                parent = SM3.hash(left + right)
                tree.append(parent)
            
            level_start += level_size
            level_size = next_level_size
            
        return tree

    def get_root(self) -> bytes:
        """获取Merkle树根哈希"""
        return self.root

    def get_leaf_index(self, leaf: bytes) -> Optional[int]:
        """查找叶子节点在列表中的索引"""
        try:
            return self.leaves.index(leaf)
        except ValueError:
            return None

    def generate_inclusion_proof(self, leaf: bytes) -> Tuple[Optional[List[bytes]], Optional[int]]:
        """生成存在性证明"""
        index = self.get_leaf_index(leaf)
        if index is None:
            return None, None
            
        proof = []
        current_index = index
        level_size = self.leaf_count
        level_start = 0
        
        while level_size > 1:
            # 计算兄弟节点索引
            is_right = current_index % 2 == 1
            sibling_index = current_index - 1 if is_right else current_index + 1
            
            # 如果兄弟节点超出范围，使用当前节点作为兄弟节点
            if sibling_index < level_size:
                sibling_hash = self.tree[level_start + sibling_index]
                proof.append(sibling_hash)
            else:
                proof.append(self.tree[level_start + current_index])
            
            # 移动到上一层
            current_index = current_index // 2
            level_start += level_size
            level_size = (level_size + 1) // 2
            
        return proof, index

    @staticmethod
    def verify_inclusion_proof(leaf: bytes, proof: List[bytes], index: int, root: bytes) -> bool:
        """验证存在性证明"""
        current_hash = SM3.hash(leaf)
        current_index = index
        
        for sibling_hash in proof:
            if current_index % 2 == 1:
                # 当前节点是右节点，左节点是兄弟节点
                current_hash = SM3.hash(sibling_hash + current_hash)
            else:
                # 当前节点是左节点，右节点是兄弟节点
                current_hash = SM3.hash(current_hash + sibling_hash)
            current_index = current_index // 2
            
        return current_hash == root

    def generate_exclusion_proof(self, leaf: bytes) -> Tuple[Optional[List[bytes]], Optional[bytes], Optional[bytes]]:
        """生成不存在性证明"""
        # 如果叶子存在，直接返回
        if self.get_leaf_index(leaf) is not None:
            return None, None, None
            
        # 找到叶子应该插入的位置
        left_neighbor = None
        right_neighbor = None
        
        # 二分查找找到左右邻居
        low, high = 0, len(self.leaves) - 1
        while low <= high:
            mid = (low + high) // 2
            if self.leaves[mid] < leaf:
                left_neighbor = self.leaves[mid]
                low = mid + 1
            else:
                right_neighbor = self.leaves[mid]
                high = mid - 1
        
        # 生成左右邻居的存在性证明
        proof = []
        if left_neighbor is not None:
            left_proof, _ = self.generate_inclusion_proof(left_neighbor)
            if left_proof:
                proof.extend(left_proof)
        
        if right_neighbor is not None:
            right_proof, _ = self.generate_inclusion_proof(right_neighbor)
            if right_proof:
                proof.extend(right_proof)
        
        return proof, left_neighbor, right_neighbor

    def verify_exclusion_proof(self, leaf: bytes, proof: List[bytes], left_neighbor: Optional[bytes], 
                             right_neighbor: Optional[bytes]) -> bool:
        """验证不存在性证明"""
        # 检查叶子是否存在
        if self.get_leaf_index(leaf) is not None:
            return False
            
        # 验证左邻居存在且小于目标叶子
        if left_neighbor is not None:
            if left_neighbor >= leaf:
                return False
            left_index = self.get_leaf_index(left_neighbor)
            if left_index is None:
                return False
            # 估算左证明长度
            left_proof_len = (left_index.bit_length() + 3) // 4  # 简单估算
            left_proof = proof[:left_proof_len] if left_proof_len <= len(proof) else proof
            if not self.verify_inclusion_proof(left_neighbor, left_proof, left_index, self.root):
                return False
        
        # 验证右邻居存在且大于目标叶子
        if right_neighbor is not None:
            if right_neighbor <= leaf:
                return False
            right_index = self.get_leaf_index(right_neighbor)
            if right_index is None:
                return False
            # 估算右证明长度
            left_proof_len = (self.get_leaf_index(left_neighbor).bit_length() + 3) // 4 if left_neighbor else 0
            right_proof = proof[left_proof_len:] if left_proof_len <= len(proof) else []
            if not self.verify_inclusion_proof(right_neighbor, right_proof, right_index, self.root):
                return False
        
        # 验证左右邻居是相邻的
        if left_neighbor is not None and right_neighbor is not None:
            left_idx = self.get_leaf_index(left_neighbor)
            right_idx = self.get_leaf_index(right_neighbor)
            if left_idx is None or right_idx is None or right_idx != left_idx + 1:
                return False
                
        return True


# 测试代码
def test_merkle_tree():
    # 生成10万个测试叶子节点
    print("生成10万个叶子节点...")
    num_leaves = 100000
    leaves = [f"leaf_{i}".encode('utf-8') for i in range(num_leaves)]
    
    # 创建Merkle树
    print("构建Merkle树...")
    merkle_tree = RFC6962MerkleTree(leaves)
    root = merkle_tree.get_root()
    print(f"Merkle树根哈希: {root.hex()}")
    
    # 测试存在性证明
    test_leaf = leaves[42]  # 选择一个存在的叶子
    proof, index = merkle_tree.generate_inclusion_proof(test_leaf)
    if proof is not None and index is not None:
        valid = RFC6962MerkleTree.verify_inclusion_proof(test_leaf, proof, index, root)
        print(f"存在性证明验证结果: {'成功' if valid else '失败'}")
    else:
        print("存在性证明生成失败")
    
    # 测试不存在性证明
    non_existent_leaf = b"non_existent_leaf_12345"
    ex_proof, left, right = merkle_tree.generate_exclusion_proof(non_existent_leaf)
    if ex_proof is not None:
        valid = merkle_tree.verify_exclusion_proof(non_existent_leaf, ex_proof, left, right)
        print(f"不存在性证明验证结果: {'成功' if valid else '失败'}")
    else:
        print("不存在性证明生成失败")


if __name__ == "__main__":
    test_merkle_tree()
