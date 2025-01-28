# 文件名: nat_traversal.py
import stun


class NATTraverser:
    def __init__(self):
        self.public_ip = None
        self.public_port = None

    def detect_nat_type(self):
        """检测NAT类型并获取公网地址"""
        nat_type, self.public_ip, self.public_port = stun.get_ip_info()
        return {
            "nat_type": nat_type.name,
            "public_ip": self.public_ip,
            "public_port": self.public_port
        }


# 修改P2P节点连接逻辑
class SecureP2PNode:
    def connect_to_peer(self, peer_host, peer_port):
        # 优先尝试直连公网地址
        if self.nat_traverser.public_ip:
            super().connect_to_peer(self.nat_traverser.public_ip, self.nat_traverser.public_port)

        # 失败时使用中继模式（需额外实现）


# 修改message_encryption.py中的加密方法
class MessageCrypt:
    def __init__(self, private_key, public_key):
        # ...原有代码...
        self.hmac_key = os.urandom(32)  # 独立HMAC密钥

    def _generate_hmac(self, ciphertext):
        """生成HMAC签名"""
        h = hmac.HMAC(self.hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(ciphertext)
        return h.finalize()

    def encrypt_message(self, peer_address, plaintext):
        ciphertext = ...  # 原有加密流程
        signature = self._generate_hmac(ciphertext)
        return ciphertext + signature  # 密文||签名

    def decrypt_message(self, peer_address, data):
        ciphertext = data[:-32]  # 分离密文和签名
        received_signature = data[-32:]

        # 验证HMAC
        expected_signature = self._generate_hmac(ciphertext)
        if not hmac.compare_digest(received_signature, expected_signature):
            raise SecurityWarning("消息完整性校验失败")

        # ...原有解密流程...





class SecureP2PNode:
    def _robust_send(self, sock, data, retries=3):
        """带重试机制的发送"""
        for attempt in range(retries):
            try:
                return sock.sendall(data)
            except (BrokenPipeError, ConnectionResetError):
                if attempt < retries - 1:
                    self._reconnect(sock)
                else:
                    raise

    def _reconnect(self, sock):
        """智能重连策略"""
        peer_addr = sock.getpeername()
        print(f"尝试重新连接到 {peer_addr}")
        sock.close()
        self.connect_to_peer(*peer_addr)