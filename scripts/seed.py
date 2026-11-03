import sys, os, json, math, wave, struct
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app import create_app, UID, NOW, B64, derive, SHA
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOGIN='DemoLogin123!'
PHRASE='vault-demo-phrase'
def seed(app):
 db=app.state.db
 for name in ['alice','bob']:
  email=f'{name}@securevault.local'
  if db.execute('SELECT 1 FROM users WHERE email=?',(email,)).fetchone():continue
  salt=B64(os.urandom(16));private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
  ps=B64(os.urandom(16));nonce=os.urandom(12)
  raw=private.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
  cipher=AESGCM(derive(PHRASE,ps)).encrypt(nonce,raw,b'securevault:user-private-key:v1')
  pub=private.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
  db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?)',(UID(),email,salt,B64(derive(LOGIN,salt,3)),B64(pub),ps,B64(nonce),B64(cipher),NOW()))
 db.commit()
 sample=Path(__file__).resolve().parents[1]/'samples';sample.mkdir(exist_ok=True)
 (sample/'welcome.txt').write_text('SecureVault — original version\n\nThis file was encrypted before it reached object storage.\nEvery verified download must match its original SHA-256 checksum.\n')
 (sample/'welcome-v2.txt').write_text('SecureVault — updated version\n\nThis is version two. Restore version one to demonstrate immutable history.\n')
 with wave.open(str(sample/'demo-audio.wav'),'wb') as w:
  w.setnchannels(1);w.setsampwidth(2);w.setframerate(22050)
  w.writeframes(b''.join(struct.pack('<h',int(5000*math.sin(2*math.pi*(440 if t<22050 else 660)*t/22050))) for t in range(44100)))
 print('Demo accounts ready: alice@securevault.local / bob@securevault.local')
 print('Login: '+LOGIN+' | Encryption passphrase: '+PHRASE)
 print('Upload samples/ files in the web app to demonstrate browser encryption.')
if __name__=='__main__':seed(create_app())
