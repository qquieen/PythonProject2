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