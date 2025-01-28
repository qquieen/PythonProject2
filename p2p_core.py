# 文件名: p2p_core.py
import socket
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import hashlib
import os


class SecureP2PNode:
    def __init__(self, host, port, key_dir):
        # 初始化网络参数
        self.host = host
        self.port = port
        self.key_dir = key_dir
        self.peers = {}

        # 加载密钥
        self.load_keys()

        # 启动TCP服务器
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)

        # 启动监听线程
        threading.Thread(target=self.accept_connections, daemon=True).start()

    def load_keys(self):
        """从U盘加载RSA密钥对"""
        # 加载私钥
        with open(os.path.join(self.key_dir, "private.pem"), "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        # 加载公钥
        with open(os.path.join(self.key_dir, "public.pem"), "rb") as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )

    def get_key_fingerprint(self):
        """生成公钥指纹用于验证"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(pem).hexdigest()[:8]

    def connect_to_peer(self, peer_host, peer_port):
        """主动连接其他节点并验证"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_host, peer_port))

            # 交换公钥指纹进行验证
            sock.sendall(f"FINGERPRINT|{self.get_key_fingerprint()}".encode())
            response = sock.recv(1024).decode()

            if response.startswith("FINGERPRINT|"):
                remote_fingerprint = response.split("|")[1]
                print(f"请通过电话确认对方指纹: {remote_fingerprint} (本地指纹: {self.get_key_fingerprint()})")
                if input("是否确认有效？(y/n) ") == "y":
                    self.peers[(peer_host, peer_port)] = sock
                    threading.Thread(target=self.handle_peer, args=(sock,)).start()
                    return True
            sock.close()
            return False
        except Exception as e:
            print(f"连接失败: {e}")
            return False

    def accept_connections(self):
        """接受并处理新连接"""
        while True:
            client, addr = self.sock.accept()
            threading.Thread(target=self.handle_peer, args=(client,)).start()

    def handle_peer(self, sock):
        """处理节点通信"""
        try:
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                # 基础消息处理（后续扩展）
                print(f"收到原始消息: {data.decode()}")
        except ConnectionResetError:
            sock.close()


# 使用示例
if __name__ == "__main__":
    node = SecureP2PNode("0.0.0.0", 5000, "./keys")
    node.connect_to_peer("192.168.1.100", 5000)