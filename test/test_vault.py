import base64, hashlib, json, os, sys, uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app import create_app, B64, UNB64, derive
from scripts.seed import seed, PHRASE, LOGIN

def payload(raw, recipients, mime='text/plain'):
 dek=os.urandom(32);aes=AESGCM(dek);blob=str(uuid.uuid4());iv=os.urandom(12);mi=os.urandom(12)
 meta={'sha256':hashlib.sha256(raw).hexdigest(),'size':len(raw),'mime':mime,'name':'test.txt'}
 env={r['id']:B64(serialization.load_der_public_key(UNB64(r['public_key'])).encrypt(dek,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))) for r in recipients}
 return dict(blob_id=blob,data_nonce=B64(iv),meta_nonce=B64(mi),meta_cipher=B64(aes.encrypt(mi,json.dumps(meta).encode(),(blob+':meta').encode())),ciphertext=B64(aes.encrypt(iv,raw,(blob+':data').encode())),envelopes=env,name='test.txt',mime=mime),dek

def test_complete_flow(tmp_path):
 app=create_app(tmp_path);seed(app);a=TestClient(app);b=TestClient(app)
 assert a.post('/api/auth/login',json={'email':'alice@securevault.local','password':'wrong-pass-123'}).status_code==401
 alice=a.post('/api/auth/login',json={'email':'alice@securevault.local','password':LOGIN}).json()['user']
 bob=b.post('/api/auth/login',json={'email':'bob@securevault.local','password':LOGIN}).json()['user']
 raw=b'original private file';p,dek=payload(raw,[alice]);r=a.post('/api/files',json=p);assert r.status_code==201,r.text
 fid=r.json()['id'];v1=r.json()['version_id'];url=f'/api/files/{fid}/versions/{v1}/download'
 assert b.post(url,json={'passphrase':PHRASE}).status_code==403
 assert a.post(url,json={'passphrase':'bad'}).status_code==400
 r=a.post(url,json={'passphrase':PHRASE});assert r.content==raw and r.headers['x-checksum-sha256']==hashlib.sha256(raw).hexdigest()
 pub=serialization.load_der_public_key(UNB64(bob['public_key']));wrapped=B64(pub.encrypt(dek,padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))
 assert a.post(f'/api/files/{fid}/share',json={'user_id':bob['id'],'role':'viewer','envelopes':{v1:wrapped}}).status_code==200
 assert b.post(url,json={'passphrase':PHRASE}).content==raw
 p2,_=payload(b'new content',[alice,bob]);assert b.post(f'/api/files/{fid}/versions',json=p2).status_code==403
 assert a.post(f'/api/files/{fid}/versions',json=p2).status_code==201
 assert a.post(f'/api/files/{fid}/versions/{v1}/restore',json={}).status_code==200
 detail=a.get(f'/api/files/{fid}').json();assert len(detail['versions'])==3
 restored=detail['current_version_id'];assert b.post(f'/api/files/{fid}/versions/{restored}/download',json={'passphrase':PHRASE}).content==raw
 assert a.delete(f'/api/files/{fid}/share/{bob["id"]}').status_code==200
 assert b.post(url,json={'passphrase':PHRASE}).status_code==403
 assert a.get('/api/audit/verify').json()['valid']
 path=tmp_path/'objects'/p['blob_id'];cipher=bytearray(path.read_bytes());cipher[0]^=1;path.write_bytes(cipher)
 assert a.post(url,json={'passphrase':PHRASE}).status_code==422
 assert a.get('/api/audit/verify').json()['valid']
 app.state.db.execute("UPDATE audit SET action='CORRUPTED' WHERE id=1");app.state.db.commit()
 assert not a.get('/api/audit/verify').json()['valid']

def test_media_and_nonce_validation(tmp_path):
 app=create_app(tmp_path);seed(app);c=TestClient(app);alice=c.post('/api/auth/login',json={'email':'alice@securevault.local','password':LOGIN}).json()['user']
 for mime in ['audio/wav','video/mp4']:
  raw=os.urandom(2048);p,_=payload(raw,[alice],mime);r=c.post('/api/files',json=p);assert r.status_code==201
  d=c.post(f'/api/files/{r.json()["id"]}/versions/{r.json()["version_id"]}/download',json={'passphrase':PHRASE});assert d.content==raw and d.headers['x-file-mime']==mime
 p,_=payload(b'x',[alice]);p['meta_nonce']=p['data_nonce'];assert c.post('/api/files',json=p).status_code==400
 assert c.post('/api/files',json={},headers={'origin':'https://evil.example'}).status_code==403

def test_browser_crypto_interoperates_with_python(tmp_path):
 import subprocess
 result=subprocess.run(['node','test/browser_crypto.mjs'],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,check=True)
 fixture=json.loads(result.stdout)
 app=create_app(tmp_path);c=TestClient(app)
 u=c.post('/api/auth/register',json={'email':'browser@example.com','password':'BrowserLogin123!'}).json()['user']
 assert c.post('/api/keys',json=fixture['alice']).status_code==200
 p=fixture['payload'];p['envelopes']={u['id']:p['envelopes']['alice']}
 r=c.post('/api/files',json=p);assert r.status_code==201,r.text
 d=c.post(f'/api/files/{r.json()["id"]}/versions/{r.json()["version_id"]}/download',json={'passphrase':'browser-test-phrase'})
 assert d.content==b'browser encrypted payload' and d.headers['x-checksum-sha256']==fixture['checksum']
 bob=fixture['bob'];der=AESGCM(derive('recipient-phrase',bob['private_salt'])).decrypt(UNB64(bob['private_nonce']),UNB64(bob['private_cipher']),b'securevault:user-private-key:v1')
 private=serialization.load_der_private_key(der,None)
 dek=private.decrypt(UNB64(fixture['envelopes']['version']),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
 assert AESGCM(dek).decrypt(UNB64(p['data_nonce']),UNB64(p['ciphertext']),(p['blob_id']+':data').encode())==b'browser encrypted payload'

def test_checkpoint_detects_tail_deletion(tmp_path):
 app=create_app(tmp_path);seed(app);c=TestClient(app)
 c.post('/api/auth/login',json={'email':'alice@securevault.local','password':LOGIN})
 app.state.db.execute('DELETE FROM audit');app.state.db.commit()
 c.post('/api/auth/login',json={'email':'alice@securevault.local','password':LOGIN})
 assert not c.get('/api/audit/verify').json()['valid']

def test_restore_recovers_version_mime(tmp_path):
 app=create_app(tmp_path);seed(app);c=TestClient(app)
 alice=c.post('/api/auth/login',json={'email':'alice@securevault.local','password':LOGIN}).json()['user']
 p,_=payload(b'first',[alice],'text/plain');r=c.post('/api/files',json=p).json();fid=r['id'];vid=r['version_id']
 p,_=payload(b'second',[alice],'audio/wav');assert c.post(f'/api/files/{fid}/versions',json=p).status_code==201
 assert c.post(f'/api/files/{fid}/versions/{vid}/restore',json={}).status_code==200
 assert c.get(f'/api/files/{fid}').json()['mime']=='text/plain'

def test_concurrent_denials_preserve_audit(tmp_path):
 from concurrent.futures import ThreadPoolExecutor
 app=create_app(tmp_path);seed(app);a=TestClient(app);b=TestClient(app)
 alice=a.post('/api/auth/login',json={'email':'alice@securevault.local','password':LOGIN}).json()['user']
 b.post('/api/auth/login',json={'email':'bob@securevault.local','password':LOGIN})
 p,_=payload(b'private',[alice]);fid=a.post('/api/files',json=p).json()['id']
 with ThreadPoolExecutor(max_workers=8) as pool:
  statuses=list(pool.map(lambda _:b.get(f'/api/files/{fid}').status_code,range(16)))
 assert statuses==[403]*16
 assert a.get('/api/audit/verify').json()['valid']

def test_existing_database_migrates_without_losing_content(tmp_path):
 app=create_app(tmp_path);seed(app);c=TestClient(app)
 alice=c.post('/api/auth/login',json={'email':'alice@securevault.local','password':LOGIN}).json()['user']
 p,_=payload(b'keep this file',[alice]);r=c.post('/api/files',json=p).json()
 head=(tmp_path/'audit-head.json').read_bytes()
 app.state.db.execute('ALTER TABLE versions DROP COLUMN mime');app.state.db.commit();app.state.db.close()
 migrated=create_app(tmp_path);new=TestClient(migrated);new.cookies.update(c.cookies)
 assert new.get(f'/api/files/{r["id"]}').json()['mime']=='text/plain'
 assert (tmp_path/'audit-head.json').read_bytes()==head
 response=new.post(f'/api/files/{r["id"]}/versions/{r["version_id"]}/download',json={'passphrase':PHRASE})
 assert response.content==b'keep this file'
 assert new.get('/api/audit/verify').json()['valid']

def inbox_clients(tmp_path):
 app=create_app(tmp_path);seed(app)
 owner=TestClient(app);other=TestClient(app);guest=TestClient(app)
 alice=owner.post('/api/auth/login',json={'email':'alice@securevault.local','password':LOGIN}).json()['user']
 other.post('/api/auth/login',json={'email':'bob@securevault.local','password':LOGIN})
 return app,owner,other,guest,alice

def request_link(owner,maximum=10):
 r=owner.post('/api/inbox/requests',json={'title':'Project documents','hours':1,'max_files':maximum})
 assert r.status_code==201,r.text
 result=r.json();return result['id'],result['path'].split('#')[1]

def submit_guest(guest,token,alice,raw=b'guest confidential document'):
 p,_=payload(raw,[alice]);p.update(token=token,sender_label='External sender')
 response=guest.post('/api/drop/upload',json=p)
 assert response.status_code==201,response.text
 return response.json()['receipt_id'],p

def test_upload_only_inbox_full_flow(tmp_path):
 app,owner,other,guest,alice=inbox_clients(tmp_path)
 rid,token=request_link(owner)
 assert guest.get('/drop/').status_code==200
 info=guest.post('/api/drop/info',json={'token':token}).json()
 assert info['public_key']==alice['public_key'] and 'private_cipher' not in info
 assert guest.get('/api/files').status_code==401
 assert guest.get('/api/inbox').status_code==401
 assert guest.post('/api/inbox/requests',json={'title':'x'}).status_code==401
 sid,p=submit_guest(guest,token,alice)
 assert guest.get('/api/inbox/submissions/'+sid).status_code in [401,404]
 assert owner.get('/api/files').json()==[]
 assert other.get('/api/inbox').json()['submissions']==[]
 assert owner.get('/api/inbox').json()['submissions'][0]['state']=='pending'
 for action in ['preview','accept','reject']:
  assert other.post(f'/api/inbox/submissions/{sid}/{action}',json={'passphrase':PHRASE}).status_code==404
 assert other.post(f'/api/inbox/requests/{rid}/close').status_code==404
 preview=owner.post(f'/api/inbox/submissions/{sid}/preview',json={'passphrase':PHRASE})
 assert preview.content==b'guest confidential document'
 assert preview.headers['x-checksum-sha256']==hashlib.sha256(preview.content).hexdigest()
 assert owner.get('/api/files').json()==[]
 r=owner.post(f'/api/inbox/submissions/{sid}/accept',json={'passphrase':PHRASE})
 assert r.status_code==200,r.text
 accepted=r.json()
 assert owner.post(f'/api/inbox/submissions/{sid}/accept',json={'passphrase':PHRASE}).status_code==409
 assert owner.get('/api/inbox').json()['submissions'][0]['state']=='accepted'
 assert owner.post(f'/api/files/{accepted["file_id"]}/versions/{accepted["version_id"]}/download',json={'passphrase':PHRASE}).content==b'guest confidential document'
 assert other.get('/api/files/'+accepted['file_id']).status_code==403
 assert owner.get('/api/audit/verify').json()['valid']
 assert any(e['action']=='INBOX_SUBMITTED' for e in owner.get('/api/audit').json())
 assert not any(e['action']=='INBOX_SUBMITTED' for e in other.get('/api/audit').json())
 stored=app.state.db.execute('SELECT token_hash FROM inbox_requests WHERE id=?',(rid,)).fetchone()[0]
 assert stored!=token and token not in json.dumps(owner.get('/api/inbox').json())

def test_inbox_expiry_closure_quotas_and_rejection(tmp_path):
 app,owner,other,guest,alice=inbox_clients(tmp_path)
 rid,token=request_link(owner,1);sid,_=submit_guest(guest,token,alice)
 p,_=payload(b'another',[alice]);p['token']=token
 assert guest.post('/api/drop/upload',json=p).status_code==410
 assert owner.post(f'/api/inbox/submissions/{sid}/reject').status_code==200
 assert owner.get('/api/files').json()==[]
 assert owner.post(f'/api/inbox/submissions/{sid}/accept',json={'passphrase':PHRASE}).status_code==409
 # Rejection does not reset a public link's abuse limit.
 assert guest.post('/api/drop/info',json={'token':token}).status_code==410
 rid,token=request_link(owner);sid,_=submit_guest(guest,token,alice)
 assert owner.post(f'/api/inbox/requests/{rid}/close').status_code==200
 assert guest.post('/api/drop/info',json={'token':token}).status_code==410
 # Closing a link leaves already-received submissions available to the owner.
 assert owner.post(f'/api/inbox/submissions/{sid}/accept',json={'passphrase':PHRASE}).status_code==200
 rid,token=request_link(owner)
 app.state.db.execute('UPDATE inbox_requests SET expires_at=0 WHERE id=?',(rid,));app.state.db.commit()
 assert guest.post('/api/drop/info',json={'token':token}).status_code==410
 assert guest.post('/api/drop/info',json={'token':'x'*43}).status_code==404
 assert guest.post('/api/drop/info',json=[]).status_code==400

def test_inbox_integrity_is_rechecked_on_accept(tmp_path):
 app,owner,other,guest,alice=inbox_clients(tmp_path)
 _,token=request_link(owner);sid,p=submit_guest(guest,token,alice)
 assert owner.post(f'/api/inbox/submissions/{sid}/preview',json={'passphrase':'incorrect'}).status_code==400
 assert owner.post(f'/api/inbox/submissions/{sid}/preview',json={'passphrase':PHRASE}).status_code==200
 path=tmp_path/'objects'/p['blob_id'];raw=bytearray(path.read_bytes());raw[0]^=1;path.write_bytes(raw)
 assert owner.post(f'/api/inbox/submissions/{sid}/accept',json={'passphrase':PHRASE}).status_code==422
 assert owner.get('/api/files').json()==[]
 assert owner.get('/api/inbox').json()['submissions'][0]['state']=='pending'
 assert owner.get('/api/audit/verify').json()['valid']

def test_inbox_limit_is_atomic_and_invalid_uploads_do_not_consume_it(tmp_path):
 from concurrent.futures import ThreadPoolExecutor
 app,owner,other,guest,alice=inbox_clients(tmp_path)
 _,token=request_link(owner,1)
 p,_=payload(b'first',[alice]);p['token']=token
 invalid={**p,'envelopes':{}}
 assert guest.post('/api/drop/upload',json=invalid).status_code==400
 q,_=payload(b'second',[alice]);q['token']=token
 with ThreadPoolExecutor(max_workers=2) as pool:
  results=list(pool.map(lambda v:guest.post('/api/drop/upload',json=v).status_code,[p,q]))
 assert sorted(results)==[201,410]
 assert len(owner.get('/api/inbox').json()['submissions'])==1
 assert owner.get('/api/audit/verify').json()['valid']

def test_signed_in_user_can_submit_to_another_owners_inbox(tmp_path):
 app,owner,bob,guest,alice=inbox_clients(tmp_path)
 _,token=request_link(owner)
 bob_before=bob.get('/api/me').json()['user']['id']
 assert bob.get('/drop/').status_code==200
 info=bob.post('/api/drop/info',json={'token':token}).json()
 assert info['owner_id']==alice['id']
 sid,_=submit_guest(bob,token,alice,b'signed-in Bob submission')
 assert bob.get('/api/me').json()['user']['id']==bob_before
 assert bob.get('/api/inbox').json()['submissions']==[]
 assert bob.get('/api/files').json()==[]
 assert owner.get('/api/inbox').json()['submissions'][0]['id']==sid
 assert bob.post(f'/api/inbox/submissions/{sid}/preview',json={'passphrase':PHRASE}).status_code==404
 accepted=owner.post(f'/api/inbox/submissions/{sid}/accept',json={'passphrase':PHRASE})
 assert accepted.status_code==200,accepted.text
 file=accepted.json()
 assert owner.post(f'/api/files/{file["file_id"]}/versions/{file["version_id"]}/download',json={'passphrase':PHRASE}).content==b'signed-in Bob submission'
 assert bob.get('/api/files/'+file['file_id']).status_code==403

def test_reusable_inbox_link_accepts_multiple_visits_and_signed_in_senders(tmp_path):
 app,owner,bob,guest,alice=inbox_clients(tmp_path)
 rid,token=request_link(owner,4)
 info=guest.post('/api/drop/info',json={'token':token}).json()
 assert info['remaining']==4 and info['remaining_bytes']==100*1024*1024
 first,_=submit_guest(guest,token,alice,b'first visit')
 second,_=submit_guest(guest,token,alice,b'another file on same link')
 third,_=submit_guest(bob,token,alice,b'signed-in sender on same link')
 assert owner.post(f'/api/inbox/submissions/{first}/accept',json={'passphrase':PHRASE}).status_code==200
 assert owner.post(f'/api/inbox/submissions/{second}/reject').status_code==200
 remaining=guest.post('/api/drop/info',json={'token':token}).json()
 assert remaining['remaining']==1
 assert remaining['remaining_bytes']==100*1024*1024-len(b'first visit')-len(b'another file on same link')-len(b'signed-in sender on same link')
 fourth,_=submit_guest(guest,token,alice,b'last slot on later visit')
 assert guest.post('/api/drop/info',json={'token':token}).status_code==410
 assert len(owner.get('/api/inbox').json()['submissions'])==4
 assert bob.get('/api/files').json()==[]
 assert owner.get('/api/audit/verify').json()['valid']
