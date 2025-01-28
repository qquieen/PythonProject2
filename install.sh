#!/bin/bash
# 依赖安装
apt-get install -y python3-pip openssl
pip3 install cryptography pyinstaller pystun3

# 密钥生成目录
mkdir -p /opt/secure_chat/keys
chmod 700 /opt/secure_chat/keys

# 生成桌面快捷方式
cat <<EOF > /usr/share/applications/secure-chat.desktop
[Desktop Entry]
Name=安全聊天室
Exec=/opt/secure_chat/secure_chat
Icon=/opt/secure_chat/icon.png
Type=Application
EOF