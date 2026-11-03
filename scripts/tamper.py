"""Explicit local demo tool. Restart/reset only with a separate DATA_DIR for disposable demos."""
import argparse, sqlite3, os
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('kind',choices=['object','audit']);p.add_argument('--file-id');p.add_argument('--data-dir',default=os.environ.get('DATA_DIR','data'));a=p.parse_args()
data=Path(a.data_dir);db=sqlite3.connect(data/'securevault.sqlite')
if a.kind=='object':
 row=db.execute('SELECT v.blob_id FROM files f JOIN versions v ON v.id=f.current_version_id WHERE f.id=?',(a.file_id,)).fetchone()
 if not row:raise SystemExit('Supply an existing --file-id')
 path=data/'objects'/row[0];raw=bytearray(path.read_bytes());raw[0]^=1;path.write_bytes(raw);print('Changed one ciphertext byte. Decryption must now fail.')
else:
 db.execute("UPDATE audit SET action='ALTERED_EVENT' WHERE id=(SELECT MIN(id) FROM audit)");db.commit();print('Altered one audit event. Verify the chain in the UI.')
