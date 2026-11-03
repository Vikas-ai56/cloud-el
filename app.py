"""SecureVault local demo: browser encryption, SQLite identity, API decryption."""
import base64
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles

ROOT = Path(__file__).parent
MAX = 25 * 1024 * 1024
B64 = lambda b: base64.b64encode(b).decode()
UNB64 = lambda s: base64.b64decode(s, validate=True)
SHA = lambda b: hashlib.sha256(b).hexdigest()
NOW = lambda: datetime.now(timezone.utc).isoformat()
UID = lambda: str(uuid.uuid4())

def derive(passphrase, salt, passes=2):
    return Argon2id(salt=UNB64(salt), length=32, iterations=passes, lanes=1, memory_cost=16384).derive(passphrase.encode())

def create_app(data_dir=None):
    app = FastAPI(title='SecureVault', docs_url='/api/docs')
    data = Path(data_dir or os.environ.get('DATA_DIR', ROOT / 'data'))
    objects = data / 'objects'
    objects.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(data / 'securevault.sqlite', check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.executescript('''
    PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_salt TEXT,password_hash TEXT,public_key TEXT,private_salt TEXT,private_nonce TEXT,private_cipher TEXT,created_at TEXT);
    CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id),expires_at REAL);
    CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY,owner_id TEXT REFERENCES users(id),name TEXT,mime TEXT,current_version_id TEXT,deleted INTEGER DEFAULT 0,created_at TEXT);
    CREATE TABLE IF NOT EXISTS versions(id TEXT PRIMARY KEY,file_id TEXT REFERENCES files(id),number INTEGER,blob_id TEXT,data_nonce TEXT,meta_nonce TEXT,meta_cipher TEXT,byte_size INTEGER,created_by TEXT REFERENCES users(id),created_at TEXT,restored_from TEXT,UNIQUE(file_id,number));
    CREATE TABLE IF NOT EXISTS permissions(file_id TEXT REFERENCES files(id),user_id TEXT REFERENCES users(id),role TEXT CHECK(role IN ('viewer','editor')),PRIMARY KEY(file_id,user_id));
    CREATE TABLE IF NOT EXISTS envelopes(version_id TEXT REFERENCES versions(id),user_id TEXT REFERENCES users(id),wrapped_dek TEXT,PRIMARY KEY(version_id,user_id));
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,actor_id TEXT,action TEXT,file_id TEXT,version_id TEXT,details TEXT,prev_hash TEXT,hash TEXT);
    ''')
    if 'mime' not in {r[1] for r in db.execute('PRAGMA table_info(versions)')}:
        db.execute('ALTER TABLE versions ADD COLUMN mime TEXT')
        db.execute('UPDATE versions SET mime=(SELECT mime FROM files WHERE files.id=versions.file_id)')
        db.commit()
    lock = threading.RLock()
    head = data / 'audit-head.json'
    if not head.exists() and not db.execute('SELECT 1 FROM audit').fetchone():
        head.write_text(json.dumps({'id': 0, 'hash': '0' * 64}))
    def one(sql, args=()):
        with lock:
            row = db.execute(sql, args).fetchone()
            return dict(row) if row else None
    def allrows(sql, args=()):
        with lock:
            return [dict(r) for r in db.execute(sql, args).fetchall()]
    def audit(actor, action, file=None, version=None, details=None):
        with lock:
            last = one('SELECT id,hash FROM audit ORDER BY id DESC LIMIT 1')
            try:
                trusted = json.loads(head.read_text()) == {'id': last['id'] if last else 0, 'hash': last['hash'] if last else '0' * 64}
            except (OSError, ValueError):
                trusted = False
            event = dict(ts=NOW(), actor_id=actor, action=action, file_id=file, version_id=version,
                         details=json.dumps(details or {}, separators=(',', ':')), prev_hash=last['hash'] if last else '0' * 64)
            digest = SHA(json.dumps(event, separators=(',', ':')).encode())
            cur = db.execute('INSERT INTO audit(ts,actor_id,action,file_id,version_id,details,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)', (*event.values(), digest))
            db.commit()
            if trusted:
                tmp = head.with_suffix('.tmp')
                tmp.write_text(json.dumps({'id': cur.lastrowid, 'hash': digest}))
                tmp.replace(head)
    def verify():
        rows = allrows('SELECT * FROM audit ORDER BY id')
        prev = '0' * 64
        for row in rows:
            event = {k: row[k] for k in ['ts','actor_id','action','file_id','version_id','details','prev_hash']}
            if row['prev_hash'] != prev or row['hash'] != SHA(json.dumps(event,separators=(',', ':')).encode()):
                return dict(valid=False,checked=len(rows),broken_at=row['id'],reason='Hash chain mismatch')
            prev = row['hash']
        try:
            checkpoint = json.loads(head.read_text())
        except (OSError, ValueError):
            checkpoint = None
        if checkpoint != {'id': rows[-1]['id'] if rows else 0, 'hash': prev}:
            return dict(valid=False,checked=len(rows),reason='External checkpoint mismatch')
        return dict(valid=True,checked=len(rows),head=prev)
    def public(u):
        return {k: u.get(k) for k in ['id','email','public_key','private_salt','private_nonce','private_cipher']}
    def user(req):
        token = req.cookies.get('sv_session', '')
        u = one('SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?', (SHA(token.encode()),time.time()))
        if not u: raise HTTPException(401,'Please sign in')
        return u
    def access(u, fid, write=False, owner=False):
        f = one('SELECT * FROM files WHERE id=? AND deleted=0',(fid,))
        if not f: raise HTTPException(404,'File not found')
        grant = one('SELECT role FROM permissions WHERE file_id=? AND user_id=?',(fid,u['id']))
        role = 'owner' if f['owner_id']==u['id'] else grant['role'] if grant else None
        if not role or (write and role=='viewer') or (owner and role!='owner'):
            audit(u['id'],'ACCESS_DENIED',fid)
            raise HTTPException(403,'Your role does not allow this action')
        return dict(f,role=role)
    def recipients(f):
        return allrows('SELECT id,email,public_key FROM users WHERE id=? OR id IN (SELECT user_id FROM permissions WHERE file_id=?)',(f['owner_id'],f['id']))
    async def body(req):
        chunks=[]; size=0
        async for chunk in req.stream():
            size+=len(chunk)
            if size>MAX*1.5: raise HTTPException(413,'Maximum file size is 25 MB')
            chunks.append(chunk)
        try: return json.loads(b''.join(chunks) or b'{}')
        except ValueError: raise HTTPException(400,'Invalid JSON')
    @app.middleware('http')
    async def guard(req, call_next):
        if req.method not in ('GET','HEAD') and req.headers.get('origin'):
            from urllib.parse import urlparse
            if urlparse(req.headers['origin']).netloc != req.headers.get('host'):
                return JSONResponse({'error':'Cross-origin request rejected'},403)
        response=await call_next(req)
        response.headers['Cache-Control']='no-store'
        response.headers['X-Content-Type-Options']='nosniff'
        return response
    @app.exception_handler(HTTPException)
    async def error(req, exc): return JSONResponse({'error':exc.detail},exc.status_code)
    @app.get('/api/health')
    def health(): return {'ok':True}
    @app.post('/api/auth/{action}')
    async def auth(action: str, req: Request):
        b=await body(req)
        with lock:
            if action=='logout':
                db.execute('DELETE FROM sessions WHERE token_hash=?',(SHA(req.cookies.get('sv_session','').encode()),));db.commit()
                r=JSONResponse({'ok':True});r.delete_cookie('sv_session');return r
            email=str(b.get('email','')).strip().lower();password=str(b.get('password',''))
            if '@' not in email or not 10<=len(password)<=256: raise HTTPException(400,'Use an email and a password of 10–256 characters')
            u=one('SELECT * FROM users WHERE email=?',(email,))
            if action=='register':
                if u: raise HTTPException(409,'Account already exists')
                salt=B64(os.urandom(16)); uid=UID()
                db.execute('INSERT INTO users(id,email,password_salt,password_hash,created_at) VALUES(?,?,?,?,?)',(uid,email,salt,B64(derive(password,salt,3)),NOW()))
                audit(uid,'REGISTER');u=one('SELECT * FROM users WHERE id=?',(uid,))
            elif action!='login': raise HTTPException(404,'Not found')
            elif not u or not secrets.compare_digest(B64(derive(password,u['password_salt'],3)),u['password_hash']): raise HTTPException(401,'Email or password is incorrect')
            token=secrets.token_hex(32)
            db.execute('INSERT INTO sessions VALUES(?,?,?)',(SHA(token.encode()),u['id'],time.time()+86400))
            audit(u['id'],'LOGIN')
            r=JSONResponse({'user':public(u)});r.set_cookie('sv_session',token,httponly=True,samesite='strict',max_age=86400);return r
    @app.get('/api/me')
    def me(req:Request): return {'user':public(user(req))}
    @app.post('/api/keys')
    async def keys(req:Request):
        b=await body(req)
        with lock:
            u=user(req)
            if u['public_key']: raise HTTPException(409,'Keys already exist')
            fields=['public_key','private_salt','private_nonce','private_cipher']
            if any(not isinstance(b.get(k),str) or len(b[k])>15000 for k in fields): raise HTTPException(400,'Invalid key material')
            try:
                serialization.load_der_public_key(UNB64(b['public_key']))
                assert len(UNB64(b['private_salt']))==16 and len(UNB64(b['private_nonce']))==12
            except Exception: raise HTTPException(400,'Invalid encryption keys')
            db.execute('UPDATE users SET public_key=?,private_salt=?,private_nonce=?,private_cipher=? WHERE id=?',(*[b[k] for k in fields],u['id']))
            audit(u['id'],'KEY_SETUP');return {'user':public(one('SELECT * FROM users WHERE id=?',(u['id'],)))}
    @app.get('/api/users')
    def lookup(req:Request,email:str):
        user(req);u=one('SELECT id,email,public_key FROM users WHERE email=?',(email.lower(),))
        if not u or not u['public_key']: raise HTTPException(404,'Recipient must register and set up encryption first')
        return u
    @app.get('/api/audit/verify')
    def verify_route(req:Request):
        user(req)
        with lock:return verify()
    @app.get('/api/audit')
    def events(req:Request):
        u=user(req)
        return allrows("SELECT a.*,u.email actor FROM audit a LEFT JOIN users u ON u.id=a.actor_id WHERE a.actor_id=? OR a.file_id IN (SELECT id FROM files WHERE owner_id=? UNION SELECT file_id FROM permissions WHERE user_id=?) OR json_extract(a.details,'$.inbox_owner')=? ORDER BY a.id DESC LIMIT 150",(u['id'],u['id'],u['id'],u['id']))
    @app.get('/api/files')
    def listing(req:Request):
        u=user(req)
        return allrows('''SELECT f.*,v.number,v.byte_size,v.created_at updated_at,u.email owner,CASE WHEN f.owner_id=? THEN 'owner' ELSE p.role END role FROM files f JOIN versions v ON v.id=f.current_version_id JOIN users u ON u.id=f.owner_id LEFT JOIN permissions p ON p.file_id=f.id AND p.user_id=? WHERE f.deleted=0 AND (f.owner_id=? OR p.user_id=?) ORDER BY v.created_at DESC''',(u['id'],)*4)
    @app.get('/api/files/{fid}')
    def detail(fid:str,req:Request):
        u=user(req);f=access(u,fid)
        return dict(f,versions=allrows('SELECT v.*,e.wrapped_dek,u.email creator FROM versions v JOIN envelopes e ON e.version_id=v.id AND e.user_id=? JOIN users u ON u.id=v.created_by WHERE v.file_id=? ORDER BY v.number DESC',(u['id'],fid)),grants=allrows('SELECT p.*,u.email FROM permissions p JOIN users u ON u.id=p.user_id WHERE file_id=?',(fid,)),recipients=recipients(f))
    @app.post('/api/files')
    @app.post('/api/files/{fid}/versions')
    async def upload(req:Request,fid:str=None):
        b=await body(req)
        with lock:
            u=user(req);f=access(u,fid,write=True) if fid else None
            if not u['public_key']:raise HTTPException(400,'Set up encryption keys first')
            try:
                blob=str(uuid.UUID(b['blob_id']));cipher=UNB64(b['ciphertext'])
                assert 16<=len(cipher)<=MAX+16 and len(UNB64(b['data_nonce']))==12 and len(UNB64(b['meta_nonce']))==12
                assert b['data_nonce']!=b['meta_nonce'] and len(b['meta_cipher'])<16000
                allowed=recipients(f) if f else [u]
                assert all(len(UNB64(b['envelopes'][r['id']]))==256 for r in allowed)
            except Exception:raise HTTPException(400,'Invalid encrypted upload or missing recipient key; refresh and retry')
            vid=UID();fid=fid or UID();now=NOW();n=one('SELECT COALESCE(MAX(number),0)+1 n FROM versions WHERE file_id=?',(fid,))['n']
            path=objects/blob
            try:
                with path.open('xb') as out:out.write(cipher)
            except FileExistsError:raise HTTPException(409,'Object already exists')
            try:
                if not f:db.execute('INSERT INTO files(id,owner_id,name,mime,created_at) VALUES(?,?,?,?,?)',(fid,u['id'],str(b.get('name','Untitled'))[:255],str(b.get('mime','application/octet-stream'))[:150],now))
                db.execute('INSERT INTO versions(id,file_id,number,blob_id,data_nonce,meta_nonce,meta_cipher,byte_size,created_by,created_at,restored_from,mime) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(vid,fid,n,blob,b['data_nonce'],b['meta_nonce'],b['meta_cipher'],len(cipher)-16,u['id'],now,None,str(b.get('mime','application/octet-stream'))[:150]))
                for r in allowed:db.execute('INSERT INTO envelopes VALUES(?,?,?)',(vid,r['id'],b['envelopes'][r['id']]))
                db.execute('UPDATE files SET current_version_id=?,mime=? WHERE id=?',(vid,str(b.get('mime','application/octet-stream'))[:150],fid))
                audit(u['id'],'UPLOAD',fid,vid,{'number':n,'bytes':len(cipher)-16})
            except Exception:db.rollback();path.unlink(missing_ok=True);raise
            return JSONResponse({'id':fid,'version_id':vid},201)
    @app.patch('/api/files/{fid}')
    async def rename(fid:str,req:Request):
        b=await body(req)
        with lock:
            u=user(req);access(u,fid,write=True);name=str(b.get('name','')).strip()[:255]
            if not name:raise HTTPException(400,'Name required')
            db.execute('UPDATE files SET name=? WHERE id=?',(name,fid));audit(u['id'],'RENAME',fid);return {'ok':True}
    @app.delete('/api/files/{fid}')
    def delete(fid:str,req:Request):
        with lock:
            u=user(req);access(u,fid,owner=True);db.execute('UPDATE files SET deleted=1 WHERE id=?',(fid,));audit(u['id'],'DELETE',fid);return {'ok':True}
    @app.post('/api/files/{fid}/share')
    async def share(fid:str,req:Request):
        b=await body(req)
        with lock:
            u=user(req);f=access(u,fid,owner=True);target=one('SELECT * FROM users WHERE id=?',(b.get('user_id'),))
            if not target or not target['public_key'] or target['id']==f['owner_id'] or b.get('role') not in ['editor','viewer']:raise HTTPException(400,'Invalid recipient or role')
            versions=allrows('SELECT id FROM versions WHERE file_id=?',(fid,))
            try:assert all(len(UNB64(b['envelopes'][v['id']]))==256 for v in versions)
            except Exception:raise HTTPException(400,'A wrapped key is required for every version')
            db.execute('INSERT INTO permissions VALUES(?,?,?) ON CONFLICT(file_id,user_id) DO UPDATE SET role=excluded.role',(fid,target['id'],b['role']))
            for v in versions:db.execute('INSERT OR REPLACE INTO envelopes VALUES(?,?,?)',(v['id'],target['id'],b['envelopes'][v['id']]))
            audit(u['id'],'SHARE',fid,details={'recipient':target['email'],'role':b['role']});return {'ok':True}
    @app.delete('/api/files/{fid}/share/{uid}')
    def revoke(fid:str,uid:str,req:Request):
        with lock:
            u=user(req);access(u,fid,owner=True)
            db.execute('DELETE FROM permissions WHERE file_id=? AND user_id=?',(fid,uid))
            db.execute('DELETE FROM envelopes WHERE user_id=? AND version_id IN (SELECT id FROM versions WHERE file_id=?)',(uid,fid))
            audit(u['id'],'REVOKE',fid,details={'user':uid});return {'ok':True}
    @app.post('/api/files/{fid}/versions/{vid}/restore')
    def restore(fid:str,vid:str,req:Request):
        with lock:
            u=user(req);access(u,fid,write=True);v=one('SELECT * FROM versions WHERE id=? AND file_id=?',(vid,fid))
            if not v:raise HTTPException(404,'Version not found')
            new=UID();n=one('SELECT MAX(number)+1 n FROM versions WHERE file_id=?',(fid,))['n']
            db.execute('INSERT INTO versions(id,file_id,number,blob_id,data_nonce,meta_nonce,meta_cipher,byte_size,created_by,created_at,restored_from,mime) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(new,fid,n,v['blob_id'],v['data_nonce'],v['meta_nonce'],v['meta_cipher'],v['byte_size'],u['id'],NOW(),vid,v['mime']))
            db.execute('INSERT INTO envelopes SELECT ?,user_id,wrapped_dek FROM envelopes WHERE version_id=?',(new,vid))
            db.execute('UPDATE files SET current_version_id=?,mime=? WHERE id=?',(new,v['mime'],fid));audit(u['id'],'RESTORE',fid,new,{'from':v['number']});return {'version_id':new}
    @app.post('/api/files/{fid}/versions/{vid}/download')
    async def download(fid:str,vid:str,req:Request):
        b=await body(req)
        with lock:
            u=user(req);f=access(u,fid);v=one('SELECT v.*,e.wrapped_dek FROM versions v JOIN envelopes e ON e.version_id=v.id AND e.user_id=? WHERE v.id=? AND v.file_id=?',(u['id'],vid,fid))
            if not v:raise HTTPException(404,'Version key not found')
            try:
                phrase=b.get('passphrase','')
                assert isinstance(phrase,str) and 1<=len(phrase)<=256
                kek=derive(phrase,u['private_salt'])
                der=AESGCM(kek).decrypt(UNB64(u['private_nonce']),UNB64(u['private_cipher']),b'securevault:user-private-key:v1')
                private=serialization.load_der_private_key(der,password=None)
                dek=private.decrypt(UNB64(v['wrapped_dek']),padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
            except Exception:
                audit(u['id'],'UNLOCK_FAILED',fid,vid);raise HTTPException(400,'Encryption passphrase is incorrect')
            try:
                aes=AESGCM(dek)
                meta=json.loads(aes.decrypt(UNB64(v['meta_nonce']),UNB64(v['meta_cipher']),(v['blob_id']+':meta').encode()))
                plain=aes.decrypt(UNB64(v['data_nonce']),(objects/v['blob_id']).read_bytes(),(v['blob_id']+':data').encode())
                assert SHA(plain)==meta['sha256'] and len(plain)==meta['size']
            except Exception:
                audit(u['id'],'INTEGRITY_FAILED',fid,vid);raise HTTPException(422,'Integrity verification failed. No plaintext was returned.')
            audit(u['id'],'DOWNLOAD_VERIFIED',fid,vid,{'bytes':len(plain)})
            from urllib.parse import quote
            return Response(plain,media_type='application/octet-stream',headers={'X-Checksum-SHA256':meta['sha256'],'X-File-Mime':meta['mime'],'X-File-Name':quote(f['name']),'X-Integrity':'AES-GCM + SHA-256 verified'})
    @app.get('/api/files/{fid}/ciphertext')
    def inspect(fid:str,req:Request):
        u=user(req);f=access(u,fid,owner=True);v=one('SELECT * FROM versions WHERE id=?',(f['current_version_id'],));raw=(objects/v['blob_id']).read_bytes()
        return {'object_key':v['blob_id'],'encrypted_bytes':len(raw),'first_96_bytes_hex':raw[:96].hex(),'envelopes':one('SELECT COUNT(*) n FROM envelopes WHERE version_id=?',(v['id'],))['n']}
    from inbox import register_inbox
    register_inbox(app, db, lock, objects, user, body, audit, derive, NOW, ROOT)
    vendor=ROOT/'public/vendor'
    if vendor.exists():app.mount('/vendor',StaticFiles(directory=vendor),name='vendor')
    app.mount('/',StaticFiles(directory=ROOT/'public',html=True),name='web')
    app.state.db=db;app.state.data=data;app.state.verify=verify;app.state.audit=audit
    return app

if __name__=='__main__':
    app=create_app()
    import uvicorn
    uvicorn.run(app,host='127.0.0.1',port=int(os.environ.get('PORT',3000)))
