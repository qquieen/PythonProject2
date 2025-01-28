# 文件名: group_manager.py
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class GroupManager:
    def __init__(self, node):
        self.node = node
        self.groups = {}  # {group_id: {'members': [], 'aes_key': bytes, 'aes_iv': bytes}}
        self.current_group = None

    def create_group(self, members):
        """创建新群组并分发密钥"""
        group_id = hashlib.sha256(os.urandom(32)).hexdigest()[:8]
        aes_key, aes_iv = self.node.crypt._generate_aes_key()

        # 用各成员公钥加密群组密钥
        encrypted_keys = {}
        for member_ip, member_pub_key in members.items():
            encrypted_key = member_pub_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_keys[member_ip] = encrypted_key.hex()

        # 通过U盘分发加密后的群组密钥（模拟实现）
        with open(f"{self.node.key_dir}/group_{group_id}.json", "w") as f:
            json.dump({
                'group_id': group_id,
                'encrypted_keys': encrypted_keys,
                'aes_iv': aes_iv.hex()
            }, f)

        self.groups[group_id] = {
            'members': list(members.keys()),
            'aes_key': aes_key,
            'aes_iv': aes_iv
        }
        return group_id

    def send_group_message(self, group_id, message):
        """发送群组加密消息"""
        if group_id not in self.groups:
            raise ValueError("群组不存在")

        key = self.groups[group_id]['aes_key']
        iv = self.groups[group_id]['aes_iv']
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

        # 群发消息（简易版广播）
        for member in self.groups[group_id]['members']:
            if member in self.node.peers:
                self.node.peers[member].sendall(f"GROUP|{group_id}|".encode() + ciphertext)


# 在SecureP2PNode类中添加以下方法
class SecureP2PNode:
    def __init__(self, host, port, key_dir):
        # ...原有代码...
        self.group_manager = GroupManager(self)
        self.file_crypt = FileCrypt()

    def handle_group_message(self, ciphertext, group_id):
        """处理群组消息"""
        key = self.groups[group_id]['aes_key']
        iv = self.groups[group_id]['aes_iv']
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def send_file(self, peer_host, peer_port, file_path):
        """安全发送文件"""
        peer_address = (peer_host, peer_port)
        if peer_address not in self.crypt.session_keys:
            print("请先建立安全会话")
            return

        aes_key, aes_iv = self.crypt.session_keys[peer_address]
        threading.Thread(target=self.file_crypt.stream_encrypt,
                         args=(self.peers[peer_address], file_path, aes_key, aes_iv)).start()