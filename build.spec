# 文件名: build.spec
a = Analysis(['main.py'],
             pathex=['/project'],
             binaries=[],
             datas=[('ui/*.ui', 'ui'), ('keys/*.pem', 'keys')],
             hiddenimports=['cryptography.hazmat.backends.openssl'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='secure_chat',
          debug=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=False,  # 设置为True可查看控制台日志
          icon='icon.ico')