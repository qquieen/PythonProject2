from p2p_core import SecureP2PNode

if __name__ == "__main__":
    # 用户输入配置
    host = input("请输入本机IP（默认127.0.0.1）：") or "127.0.0.1"
    port = int(input("请输入监听端口（默认5000）：") or 5000)
    key_dir = "./keys"

    # 启动节点
    node = SecureP2PNode(host, port, key_dir)
    print(f"节点已启动，监听 {host}:{port}")

    # 连接其他节点
    peer_host = input("请输入对方IP：")
    peer_port = int(input("请输入对方端口："))
    if node.connect_to_peer(peer_host, peer_port):
        print("连接成功！")

    # 发送消息测试
    while True:
        message = input("输入消息（或输入'quit'退出）：")
        if message == "quit":
            break
        node.send_secure_message(peer_host, peer_port, message)