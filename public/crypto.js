import { argon2idAsync } from './vendor/argon2.js';
const enc=new TextEncoder(),sub=crypto.subtle;
export const b64=b=>{let s='';for(const x of new Uint8Array(b))s+=String.fromCharCode(x);return btoa(s);};
export const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
export const hash=async b=>Array.from(new Uint8Array(await sub.digest('SHA-256',b)),x=>x.toString(16).padStart(2,'0')).join('');
const nonce=()=>crypto.getRandomValues(new Uint8Array(12));
async function kek(pass,salt){const raw=await argon2idAsync(enc.encode(pass),bytes(salt),{m:16384,t:2,p:1,dkLen:32});const k=await sub.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt']);raw.fill(0);return k;}
export async function setupKeys(pass){
 const pair=await sub.generateKey({name:'RSA-OAEP',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['encrypt','decrypt']);
 const salt=b64(crypto.getRandomValues(new Uint8Array(16))),iv=nonce(),key=await kek(pass,salt);
 const cipher=await sub.encrypt({name:'AES-GCM',iv,additionalData:enc.encode('securevault:user-private-key:v1')},key,await sub.exportKey('pkcs8',pair.privateKey));
 return {public_key:b64(await sub.exportKey('spki',pair.publicKey)),private_salt:salt,private_nonce:b64(iv),private_cipher:b64(cipher)};
}
export async function unlock(user,pass){
 const key=await kek(pass,user.private_salt);
 const raw=await sub.decrypt({name:'AES-GCM',iv:bytes(user.private_nonce),additionalData:enc.encode('securevault:user-private-key:v1')},key,bytes(user.private_cipher));
 return sub.importKey('pkcs8',raw,{name:'RSA-OAEP',hash:'SHA-256'},false,['decrypt']);
}
async function wrap(raw,pub){const k=await sub.importKey('spki',bytes(pub),{name:'RSA-OAEP',hash:'SHA-256'},false,['encrypt']);return b64(await sub.encrypt('RSA-OAEP',k,raw));}
export async function encryptFile(file,recipients){
 const raw=await file.arrayBuffer(),sha256=await hash(raw),dek=crypto.getRandomValues(new Uint8Array(32));
 const key=await sub.importKey('raw',dek,'AES-GCM',false,['encrypt']),blob_id=crypto.randomUUID(),iv=nonce(),mi=nonce();
 const meta={name:file.name,mime:file.type||'application/octet-stream',size:raw.byteLength,sha256};
 const cipher=await sub.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(blob_id+':data')},key,raw);
 const mc=await sub.encrypt({name:'AES-GCM',iv:mi,additionalData:enc.encode(blob_id+':meta')},key,enc.encode(JSON.stringify(meta)));
 const envelopes={};for(const r of recipients)envelopes[r.id]=await wrap(dek,r.public_key);dek.fill(0);
 return {name:file.name,mime:meta.mime,blob_id,data_nonce:b64(iv),meta_nonce:b64(mi),meta_cipher:b64(mc),ciphertext:b64(cipher),envelopes,sha256};
}
export async function rewrap(versions,privateKey,publicKey){const out={};for(const v of versions){const raw=await sub.decrypt('RSA-OAEP',privateKey,bytes(v.wrapped_dek));out[v.id]=await wrap(raw,publicKey);new Uint8Array(raw).fill(0);}return out;}
