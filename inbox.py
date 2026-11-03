"""Upload-only capability links and owner-reviewed encrypted submissions."""
import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from urllib.parse import quote

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, Request
from fastapi.responses import FileResponse, Response


def register_inbox(app, db, lock, objects, user, body, audit, derive, now, root):
    limit = 25 * 1024 * 1024
    decode = lambda s: base64.b64decode(s, validate=True)
    digest = lambda b: hashlib.sha256(b).hexdigest()
    db.executescript('''
    CREATE TABLE IF NOT EXISTS inbox_requests(
        id TEXT PRIMARY KEY,owner_id TEXT NOT NULL REFERENCES users(id),token_hash TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,created_at TEXT NOT NULL,expires_at REAL NOT NULL,
        closed INTEGER NOT NULL DEFAULT 0,max_files INTEGER NOT NULL DEFAULT 10);
    CREATE TABLE IF NOT EXISTS inbox_submissions(
        id TEXT PRIMARY KEY,request_id TEXT NOT NULL REFERENCES inbox_requests(id),
        name TEXT NOT NULL,mime TEXT NOT NULL,byte_size INTEGER NOT NULL,blob_id TEXT UNIQUE NOT NULL,
        data_nonce TEXT NOT NULL,meta_nonce TEXT NOT NULL,meta_cipher TEXT NOT NULL,
        wrapped_dek TEXT NOT NULL,sender_label TEXT NOT NULL,created_at TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending',file_id TEXT);
    ''')

    def one(sql, args=()):
        row = db.execute(sql, args).fetchone()
        return dict(row) if row else None

    def rows(sql, args=()):
        return [dict(r) for r in db.execute(sql, args).fetchall()]

    async def read_body(req):
        value = await body(req)
        if not isinstance(value, dict):
            raise HTTPException(400, 'Expected a JSON object')
        return value

    def request_for(token):
        if not isinstance(token, str) or not 20 <= len(token) <= 100:
            raise HTTPException(404, 'Upload link not found')
        r = one('SELECT r.*,u.public_key,u.email FROM inbox_requests r JOIN users u ON u.id=r.owner_id WHERE token_hash=?', (digest(token.encode()),))
        if not r:
            raise HTTPException(404, 'Upload link not found')
        if r['closed'] or r['expires_at'] <= time.time():
            raise HTTPException(410, 'This upload link is closed or expired')
        usage = one('SELECT COUNT(*) count,COALESCE(SUM(byte_size),0) bytes FROM inbox_submissions WHERE request_id=?', (r['id'],))
        if usage['count'] >= r['max_files'] or usage['bytes'] >= 100 * 1024 * 1024:
            raise HTTPException(410, 'This upload link has reached its limit')
        return r, usage

    def submission_for(uid, sid):
        s = one('SELECT s.*,r.owner_id,r.title FROM inbox_submissions s JOIN inbox_requests r ON r.id=s.request_id WHERE s.id=? AND r.owner_id=?', (sid, uid))
        if not s:
            raise HTTPException(404, 'Submission not found')
        if s['state'] != 'pending':
            raise HTTPException(409, 'This submission has already been reviewed')
        return s

    def decrypt(u, s, passphrase):
        try:
            if not isinstance(passphrase, str) or not 1 <= len(passphrase) <= 256:
                raise ValueError()
            kek = derive(passphrase, u['private_salt'])
            der = AESGCM(kek).decrypt(decode(u['private_nonce']), decode(u['private_cipher']), b'securevault:user-private-key:v1')
            private = serialization.load_der_private_key(der, password=None)
        except Exception:
            raise HTTPException(400, 'Encryption passphrase is incorrect')
        try:
            dek = private.decrypt(decode(s['wrapped_dek']), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            aes = AESGCM(dek)
            meta = json.loads(aes.decrypt(decode(s['meta_nonce']), decode(s['meta_cipher']), (s['blob_id'] + ':meta').encode()))
            plain = aes.decrypt(decode(s['data_nonce']), (objects / s['blob_id']).read_bytes(), (s['blob_id'] + ':data').encode())
            if digest(plain) != meta['sha256'] or len(plain) != meta['size']:
                raise ValueError()
            if not isinstance(meta.get('mime'), str) or len(meta['mime']) > 150 or any(ord(c) < 32 or ord(c) > 126 for c in meta['mime']):
                raise ValueError()
            return plain, meta
        except Exception:
            audit(u['id'], 'INBOX_INTEGRITY_FAILED', details={'submission': s['id']})
            raise HTTPException(422, 'Submission integrity verification failed. Nothing was accepted.')

    @app.get('/drop/')
    def drop_page():
        return FileResponse(root / 'public' / 'index.html')

    @app.post('/api/drop/info')
    async def info(req: Request):
        b = await read_body(req)
        with lock:
            r, usage = request_for(b.get('token'))
            return dict(title=r['title'], recipient=r['email'], owner_id=r['owner_id'], public_key=r['public_key'], expires_at=r['expires_at'], remaining=r['max_files']-usage['count'], remaining_bytes=100*1024*1024-usage['bytes'], max_bytes=limit)

    @app.post('/api/drop/upload', status_code=201)
    async def external_upload(req: Request):
        b = await read_body(req)
        with lock:
            r, usage = request_for(b.get('token'))
            try:
                blob = str(uuid.UUID(b['blob_id']))
                cipher = decode(b['ciphertext'])
                dn, mn = decode(b['data_nonce']), decode(b['meta_nonce'])
                if not 16 <= len(cipher) <= limit + 16 or len(dn) != 12 or len(mn) != 12 or dn == mn:
                    raise ValueError()
                meta = decode(b['meta_cipher'])
                if not 16 <= len(meta) <= 12000:
                    raise ValueError()
                wrapped = b['envelopes'][r['owner_id']]
                if len(decode(wrapped)) != 256:
                    raise ValueError()
                name = str(b.get('name', 'Untitled')).strip()[:255] or 'Untitled'
                mime = str(b.get('mime', 'application/octet-stream'))[:150]
                sender = str(b.get('sender_label', '')).strip()[:120]
            except (KeyError, ValueError, TypeError):
                raise HTTPException(400, 'Invalid encrypted submission')
            if usage['bytes'] + len(cipher) - 16 > 100 * 1024 * 1024:
                raise HTTPException(413, 'This inbox has reached its storage limit')
            path = objects / blob
            try:
                with path.open('xb') as stream:
                    stream.write(cipher)
            except FileExistsError:
                raise HTTPException(409, 'Object already exists')
            sid = str(uuid.uuid4())
            try:
                db.execute('''INSERT INTO inbox_submissions(id,request_id,name,mime,byte_size,blob_id,data_nonce,meta_nonce,meta_cipher,wrapped_dek,sender_label,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                           (sid,r['id'],name,mime,len(cipher)-16,blob,b['data_nonce'],b['meta_nonce'],b['meta_cipher'],wrapped,sender,now()))
                audit('external', 'INBOX_SUBMITTED', details={'submission':sid,'request':r['id'],'inbox_owner':r['owner_id'],'source':'unauthenticated_upload'})
            except Exception:
                db.rollback()
                path.unlink(missing_ok=True)
                raise
            return {'receipt_id':sid,'message':'Encrypted submission received for owner review'}

    @app.post('/api/inbox/requests', status_code=201)
    async def create_request(req: Request):
        b = await read_body(req)
        with lock:
            u = user(req)
            if not u['public_key']:
                raise HTTPException(400, 'Set up encryption keys first')
            title = str(b.get('title', '')).strip()[:120]
            try:
                hours = int(b.get('hours',24)); maximum = int(b.get('max_files',10))
                if not title or not 1 <= hours <= 168 or not 1 <= maximum <= 20:
                    raise ValueError()
            except (ValueError, TypeError):
                raise HTTPException(400, 'Use a title, 1–168 hours, and 1–20 submissions')
            token = secrets.token_urlsafe(32); rid = str(uuid.uuid4()); expires = time.time()+hours*3600
            db.execute('INSERT INTO inbox_requests(id,owner_id,token_hash,title,created_at,expires_at,max_files) VALUES(?,?,?,?,?,?,?)', (rid,u['id'],digest(token.encode()),title,now(),expires,maximum))
            audit(u['id'], 'INBOX_CREATED', details={'request':rid,'title':title})
            return {'id':rid,'path':'/drop/#'+token,'expires_at':expires}

    @app.get('/api/inbox')
    def list_inbox(req: Request):
        with lock:
            u = user(req)
            requests = rows('SELECT r.*,COUNT(s.id) received,COALESCE(SUM(s.byte_size),0) received_bytes FROM inbox_requests r LEFT JOIN inbox_submissions s ON s.request_id=r.id WHERE r.owner_id=? GROUP BY r.id ORDER BY r.created_at DESC', (u['id'],))
            for r in requests:
                r.pop('token_hash')
                r['active'] = not r['closed'] and r['expires_at'] > time.time() and r['received'] < r['max_files'] and r['received_bytes'] < 100 * 1024 * 1024
            submissions = rows('SELECT s.id,s.request_id,s.name,s.mime,s.byte_size,s.sender_label,s.created_at,s.state,s.file_id,r.title FROM inbox_submissions s JOIN inbox_requests r ON r.id=s.request_id WHERE r.owner_id=? ORDER BY s.created_at DESC', (u['id'],))
            return {'requests':requests,'submissions':submissions}

    @app.post('/api/inbox/requests/{rid}/close')
    def close_request(rid: str, req: Request):
        with lock:
            u = user(req)
            if not one('SELECT id FROM inbox_requests WHERE id=? AND owner_id=?',(rid,u['id'])):
                raise HTTPException(404,'Upload request not found')
            db.execute('UPDATE inbox_requests SET closed=1 WHERE id=?',(rid,))
            audit(u['id'],'INBOX_CLOSED',details={'request':rid})
            return {'ok':True}

    @app.post('/api/inbox/submissions/{sid}/preview')
    @app.post('/api/inbox/submissions/{sid}/accept')
    async def review_submission(sid: str, req: Request):
        b = await read_body(req)
        with lock:
            u = user(req); s = submission_for(u['id'], sid)
            plain, meta = decrypt(u, s, b.get('passphrase'))
            if req.url.path.endswith('/preview'):
                audit(u['id'],'INBOX_PREVIEWED',details={'submission':sid})
                return Response(plain, media_type='application/octet-stream',headers={'X-Checksum-SHA256':meta['sha256'],'X-File-Mime':meta['mime'],'X-File-Name':quote(s['name'])})
            fid, vid = str(uuid.uuid4()), str(uuid.uuid4())
            try:
                db.execute('INSERT INTO files(id,owner_id,name,mime,current_version_id,created_at) VALUES(?,?,?,?,?,?)',(fid,u['id'],s['name'],meta['mime'],vid,now()))
                db.execute('INSERT INTO versions(id,file_id,number,blob_id,data_nonce,meta_nonce,meta_cipher,byte_size,created_by,created_at,restored_from,mime) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(vid,fid,1,s['blob_id'],s['data_nonce'],s['meta_nonce'],s['meta_cipher'],len(plain),u['id'],now(),None,meta['mime']))
                db.execute('INSERT INTO envelopes VALUES(?,?,?)',(vid,u['id'],s['wrapped_dek']))
                db.execute("UPDATE inbox_submissions SET state='accepted',file_id=? WHERE id=?",(fid,sid))
                audit(u['id'],'INBOX_ACCEPTED',fid,vid,{'submission':sid,'source':'external_submission'})
            except Exception:
                db.rollback()
                raise
            return {'file_id':fid,'version_id':vid}

    @app.post('/api/inbox/submissions/{sid}/reject')
    def reject_submission(sid: str, req: Request):
        with lock:
            u = user(req); submission_for(u['id'],sid)
            db.execute("UPDATE inbox_submissions SET state='rejected' WHERE id=?",(sid,))
            audit(u['id'],'INBOX_REJECTED',details={'submission':sid})
            return {'ok':True}
