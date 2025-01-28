# 文件名: message_encryption.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import json


class MessageCrypt:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.session_keys = {}  # 存储各节点的AES会话密钥 {peer_address: (key, iv)}

    def _generate_aes_key(self):
        """生成随机的AES-256密钥和IV"""
        key = os.urandom(32)
        iv = os.urandom(16)
        return key, iv

    def establish_secure_session(self, peer_sock, peer_address):
        """建立安全会话（密钥交换）"""
        # 生成AES会话密钥
        aes_key, aes_iv = self._generate_aes_key()

        # 用对方公钥加密AES密钥
        encrypted_key = self.public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 发送加密后的密钥包
        key_package = json.dumps({
            'type': 'key_exchange',
            'key': encrypted_key.hex(),
            'iv': aes_iv.hex()
        }).encode()
        peer_sock.sendall(len(key_package).to_bytes(4, 'big') + key_package)

        # 存储会话密钥
        self.session_keys[peer_address] = (aes_key, aes_iv)

    def encrypt_message(self, peer_address, plaintext):
        """加密文本消息"""
        if peer_address not in self.session_keys:
            raise ValueError("安全会话未建立")

        key, iv = self.session_keys[peer_address]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        return ciphertext

    def decrypt_message(self, peer_address, ciphertext):
        """解密消息"""
        if peer_address not in self.session_keys:
            raise ValueError("安全会话未建立")

        key, iv = self.session_keys[peer_address]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


# 修改SecureP2PNode类的handle_peer方法
class SecureP2PNode:
    def __init__(self, host, port, key_dir):
        # ...原有初始化代码...
        self.crypt = MessageCrypt(self.private_key, self.public_key)

    def handle_peer(self, sock):
        """处理加密通信"""
        peer_address = sock.getpeername()
        try:
            # 接收密钥交换包
            raw_length = sock.recv(4)
            if not raw_length:
                return
            length = int.from_bytes(raw_length, 'big')
            key_data = json.loads(sock.recv(length).decode())

            if key_data['type'] == 'key_exchange':
                # 解密AES密钥
                encrypted_key = bytes.fromhex(key_data['key'])
                aes_key = self.private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                aes_iv = bytes.fromhex(key_data['iv'])
                self.crypt.session_keys[peer_address] = (aes_key, aes_iv)

                # 开始接收加密消息
                while True:
                    encrypted_msg = sock.recv(1024)
                    if not encrypted_msg:
                        break
                    plaintext = self.crypt.decrypt_message(peer_address, encrypted_msg)
                    print(f"解密消息: {plaintext.decode()}")
        except Exception as e:
            print(f"通信错误: {e}")
        finally:
            sock.close()

    def send_secure_message(self, peer_host, peer_port, message):
        """发送加密消息"""
        peer_address = (peer_host, peer_port)
        if peer_address not in self.crypt.session_keys:
            print("请先建立安全会话")
            return

        ciphertext = self.crypt.encrypt_message(peer_address, message)
        self.peers[peer_address].sendall(ciphertext)


# 文件名: file_transfer.py
CHUNK_SIZE = 4096  # 不影响分块逻辑，仅控制内存占用


class FileCrypt:
    @staticmethod
    def encrypt_file(src_path, dest_path, aes_key, aes_iv):
        """流式加密文件"""
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(src_path, 'rb') as fin, open(dest_path, 'wb') as fout:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(encryptor.update(chunk))
            fout.write(encryptor.finalize())

    @staticmethod
    def stream_encrypt(sock, file_path, aes_key, aes_iv):
        """网络流式加密传输"""
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    sock.sendall(encryptor.finalize())
                    break
                sock.sendall(encryptor.update(chunk))