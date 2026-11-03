import {icon} from './ui.js';
import {encryptFile,hash} from './crypto.js';
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const size=n=>n<1048576?`${(n/1024).toFixed(1)} KB`:`${(n/1048576).toFixed(1)} MB`;
const date=s=>new Date(s).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});

export async function publicDrop(api){
 const root=$('#app'),token=location.hash.slice(1);
 function frame(content){root.innerHTML=`<main class="drop-page"><a class="drop-brand" href="/"><span class="logo">${icon('vault')}</span>SecureVault</a><section class="card pad">${content}</section><p class="muted small">Reusable upload-only link · Encrypted in your browser · 25 MiB per file</p></main>`;}
 frame('<p>Checking upload link…</p>');
 try{
  let info=await api('/drop/info','POST',{token});
  frame(`<div class="eyebrow">SECURE FILE REQUEST</div><h1>${esc(info.title)}</h1><p class="muted">Send files to <strong>${esc(info.recipient)}</strong>. You can submit several files now and return to this same link later, whether you are signed in or not.</p><div class="note">Expires ${date(info.expires_at*1000)} · <strong>${info.remaining} file slots remaining</strong> · ${size(info.remaining_bytes)} available</div><form id="drop-upload"><label>Your name or email <span class="muted">(optional)</span></label><input name="sender" maxlength="120" placeholder="So the recipient knows who sent it"><label>Choose one or more files</label><div class="drop"><div class="drop-icon">${icon('upload')}</div><p class="small muted">Select several files together, or submit more later</p><input type="file" name="file" multiple required aria-label="Choose files"></div><div id="drop-selection" class="drop-selection" aria-live="polite"></div><p class="small muted">Each file uses one submission slot. Files are encrypted separately for the recipient. This link lets you upload; it does not let you browse their vault.</p><div class="progress" role="status"></div><div class="error" role="alert"></div><button type="submit" class="primary" style="width:100%">Encrypt & submit files →</button></form>`);
  const form=$('#drop-upload');
  form.elements.file.onchange=()=>{
   const selected=Array.from(form.elements.file.files);
   $('#drop-selection').innerHTML=selected.map(f=>`<div class="drop-file"><span>${icon('document')} ${esc(f.name)}</span><small>${size(f.size)}</small></div>`).join('');
   form.querySelector('button[type=submit]').textContent=selected.length?`Encrypt & submit ${selected.length} file${selected.length===1?'':'s'} →`:'Encrypt & submit files →';
  };
  form.onsubmit=async e=>{
   e.preventDefault();const selected=Array.from(form.elements.file.files),button=form.querySelector('button[type=submit]'),error=form.querySelector('.error'),progress=form.querySelector('.progress');
   error.textContent='';
   if(!selected.length)return;
   const oversized=selected.find(f=>f.size>info.max_bytes);
   if(oversized){error.textContent=`${oversized.name} is larger than 25 MiB. Choose smaller files.`;return;}
   button.disabled=true;
   try{
    info=await api('/drop/info','POST',{token});
    if(selected.length>info.remaining)throw Error(`This link has ${info.remaining} file slots left. Select fewer files.`);
    if(selected.reduce((sum,f)=>sum+f.size,0)>info.remaining_bytes)throw Error('The selected files exceed the remaining storage allowance for this link.');
   }catch(err){error.textContent=err.message;button.disabled=false;return;}
   form.elements.file.disabled=true;form.elements.sender.disabled=true;
   const sender=form.elements.sender.value,results=[];
   for(let i=0;i<selected.length;i++){
    const file=selected[i];
    try{
     progress.textContent=`Encrypting ${i+1} of ${selected.length}: ${file.name}`;
     const encrypted=await encryptFile(file,[{id:info.owner_id,public_key:info.public_key}]);
     progress.textContent=`Submitting ${i+1} of ${selected.length}: ${file.name}`;
     const result=await api('/drop/upload','POST',{...encrypted,token,sender_label:sender});
     results.push({name:file.name,state:'received',receipt:result.receipt_id});
    }catch(err){
     results.push({name:file.name,state:'unconfirmed',reason:err.message});
     for(const remaining of selected.slice(i+1))results.push({name:remaining.name,state:'not-sent'});
     break;
    }
   }
   const count=results.filter(r=>r.state==='received').length,complete=count===selected.length;
   frame(`<span class="chip ${complete?'':'editor'}">${count} ENCRYPTED FILE${count===1?'':'S'} RECEIVED</span><h1>${complete?(count===1?'Your file is with the recipient.':'Your files are with the recipient.'):'Some files need attention.'}</h1><p>${count} file${count===1?' is':'s are'} waiting for the owner’s review. Each successful file has its own receipt.</p><div class="submission-results">${results.map(r=>`<div class="submission-result" data-upload-status="${r.state}"><strong>${esc(r.name)}</strong><span class="chip ${r.state==='received'?'':'bad'}">${r.state==='received'?'Received':r.state==='not-sent'?'Not sent':'Not confirmed'}</span>${r.receipt?`<div class="hash mono">${esc(r.receipt)}</div>`:r.reason?`<p class="small muted">${esc(r.reason)}. If a network error occurred, ask the recipient whether it arrived before sending it again.</p>`:'<p class="small muted">This file was not attempted after the earlier failure.</p>'}</div>`).join('')}</div><p class="small muted">Receipts identify submissions; they do not grant download access. You can reuse this same link until it expires, is closed, or reaches its limits.</p><button id="another">Submit more files</button>`);
   $('#another').onclick=()=>publicDrop(api);
  };
 }catch(err){frame(`<span class="chip bad">LINK UNAVAILABLE</span><h1>This inbox isn’t accepting files.</h1><p class="muted">${esc(err.message)}</p>`);}
}

export async function renderInbox(ctx){
 const {api,shell,show,toast,detail,keySetup,me}=ctx;
 const data=await api('/inbox'),pending=data.submissions.filter(s=>s.state==='pending');
 shell(`<div class="heading"><div><div class="eyebrow">PRIVATE FILE COLLECTION</div><h1>Secure upload inbox<span class="title-dot">.</span></h1><p>Receive encrypted files from anyone. Review them before they enter your vault.</p></div><button class="primary" id="new-request">${icon('plus')} Create upload link</button></div><div class="stats"><div class="stat"><div class="stat-icon">${icon('inbox')}</div><div><strong>${pending.length}</strong><span>Waiting for review</span></div></div><div class="stat"><div class="stat-icon">${icon('share')}</div><div><strong>${data.requests.filter(r=>r.active).length}</strong><span>Active upload links</span></div></div><div class="stat"><div class="stat-icon">${icon('shield')}</div><div><strong>${data.submissions.filter(s=>s.state==='accepted').length}</strong><span>Accepted into vault</span></div></div></div><div class="card"><div class="card-head"><h3>Received submissions</h3><button id="inbox-refresh">${icon('refresh')} Refresh</button></div>${data.submissions.length?`<div class="wrap"><table><thead><tr><th>File</th><th>Request / sender</th><th>Status</th><th></th></tr></thead><tbody>${data.submissions.map(s=>`<tr><td><strong>${esc(s.name)}</strong><div class="muted small">${size(s.byte_size)} · ${date(s.created_at)}</div></td><td>${esc(s.title)}<div class="muted small">${s.sender_label?esc(s.sender_label)+' · unverified sender label':'Anonymous sender'}</div></td><td><span class="chip ${s.state==='rejected'?'bad':s.state==='pending'?'editor':''}">${esc(s.state)}</span></td><td><div class="actions">${s.state==='pending'?`<button data-review="${s.id}">Verify & review</button><button class="danger" data-reject="${s.id}">Reject</button>`:s.state==='accepted'?`<button data-open-inbox="${s.file_id}">Open in vault →</button>`:''}</div></td></tr>`).join('')}</tbody></table></div>`:`<div class="empty"><div class="empty-icon">${icon('inbox')}</div><strong>Your inbox is ready</strong>Create an upload link and send it to someone. Their encrypted submissions will appear here.</div>`}</div><div class="card"><div class="card-head"><h3>Your upload links</h3></div>${data.requests.length?data.requests.map(r=>`<div class="pad inbox-request"><span class="inbox-request-icon">${icon('inbox')}</span><div><strong>${esc(r.title)}</strong><p class="small muted">${r.received} / ${r.max_files} submissions · Expires ${date(r.expires_at*1000)}</p></div><span class="chip ${r.active?'':'viewer'}">${r.active?'active':r.closed?'closed':'expired / full'}</span>${!r.closed?`<button data-close-request="${r.id}">Close link</button>`:''}</div>`).join(''):'<div class="pad muted">No upload links yet.</div>'}</div><div class="note">Submissions are encrypted for your public key and kept outside your file list until accepted. Verification confirms integrity; it does not scan files for malware.</div>`);
 $('#inbox-refresh').onclick=()=>renderInbox(ctx);
 document.querySelectorAll('[data-open-inbox]').forEach(b=>b.onclick=()=>detail(b.dataset.openInbox));
 document.querySelectorAll('[data-close-request]').forEach(b=>b.onclick=async()=>{try{await api(`/inbox/requests/${b.dataset.closeRequest}/close`,'POST',{});toast('Upload link closed');await renderInbox(ctx);}catch(e){toast(e.message);}});
 document.querySelectorAll('[data-reject]').forEach(b=>b.onclick=()=>{
  show('Reject submission?',`<p>This file will stay outside your vault. The sender won’t receive access to it.</p><button class="danger" id="confirm-reject">Reject submission</button>`);
  $('#confirm-reject').onclick=async()=>{try{await api(`/inbox/submissions/${b.dataset.reject}/reject`,'POST',{});$('#modal').close();await renderInbox(ctx);}catch(e){toast(e.message);}};
 });
 $('#new-request').onclick=()=>{
  if(!me.public_key)return keySetup();
  show('Create an upload-only link',`<p class="muted small">Anyone with this link can submit encrypted files to you. They cannot list or download vault contents.</p><form id="request-form"><label>Request title</label><input name="title" maxlength="120" required placeholder="e.g. Documents for project review"><label>Link expires after</label><select name="hours"><option value="1">1 hour</option><option value="24" selected>24 hours</option><option value="168">7 days</option></select><label>File slots across all visits</label><input name="max_files" type="number" min="1" max="20" value="10" required><p class="small muted">25 MiB per file · 100 MiB total per link. Every file uses one slot; the link can be reused until these limits or its expiry are reached.</p><div class="error" role="alert"></div><div class="modal-actions"><button type="submit" class="primary">Create link</button></div></form>`);
  $('#request-form').onsubmit=async e=>{e.preventDefault();const form=e.target,button=form.querySelector('button');button.disabled=true;
   try{const result=await api('/inbox/requests','POST',Object.fromEntries(new FormData(form))),link=location.origin+result.path;
    show('Your upload link is ready',`<p>Copy this link now. SecureVault stores its fingerprint, so this is the only time the complete link is displayed.</p><input id="created-link" readonly value="${esc(link)}" aria-label="Upload link"><div class="modal-actions"><button class="primary" id="copy-link">Copy link</button><a href="${esc(link)}" target="_blank" rel="noopener noreferrer"><button>Open upload page ↗</button></a></div><p class="small muted">Share this link only with intended senders. You can close it from your inbox.</p>`);
    $('#copy-link').onclick=async()=>{try{await navigator.clipboard.writeText(link);toast('Upload link copied');}catch{$('#created-link').select();toast('Select and copy the link above');}};
    await renderInbox(ctx);
   }catch(err){form.querySelector('.error').textContent=err.message;button.disabled=false;}
  };
 };
 document.querySelectorAll('[data-review]').forEach(b=>b.onclick=()=>review(ctx,data.submissions.find(s=>s.id===b.dataset.review)));
}

function review(ctx,s){
 const {show,api,toast}=ctx;
 show('Verify submission',`<p><strong>${esc(s.name)}</strong> · ${size(s.byte_size)}</p><p class="small muted">Enter your encryption passphrase to verify and preview this submission. Acceptance requires a second integrity check.</p><form id="inbox-review"><label>Encryption passphrase</label><input name="passphrase" type="password" required autocomplete="off"><div class="error" role="alert"></div><div class="modal-actions"><button class="primary" type="submit">Verify & preview</button></div></form>`);
 $('#inbox-review').onsubmit=async e=>{
  e.preventDefault();const form=e.target,button=form.querySelector('button');button.disabled=true;let phrase=form.elements.passphrase.value;
  try{
   const response=await fetch(`/api/inbox/submissions/${s.id}/preview`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({passphrase:phrase})});
   if(!response.ok)throw Error((await response.json()).error);
   const bytes=await response.arrayBuffer(),checksum=await hash(bytes);
   if(checksum!==response.headers.get('X-Checksum-SHA256'))throw Error('Browser checksum mismatch. File blocked.');
   const mime=response.headers.get('X-File-Mime'),url=URL.createObjectURL(new Blob([bytes],{type:mime}));
   const preview=mime.startsWith('audio/')?`<audio controls src="${url}"></audio>`:mime.startsWith('video/')?`<video controls src="${url}"></video>`:mime.startsWith('image/')?`<img src="${url}" style="max-width:100%;max-height:280px">`:mime.startsWith('text/')?`<pre>${esc(new TextDecoder().decode(bytes))}</pre>`:'<p class="muted">Preview unavailable for this format. You can download the verified file to review it.</p>';
   show(s.name,`<span class="chip">INTEGRITY VERIFIED</span><p class="small muted">${esc(s.sender_label||'Anonymous')} · Sender identity is not verified. Open only files you trust.</p>${preview}<label>SHA-256 verified in API and browser</label><div class="hash mono">${checksum}</div><div class="error" id="accept-error" role="alert"></div><div class="modal-actions"><a href="${url}" download="${esc(s.name)}"><button>Download to review</button></a><button class="primary" id="accept-inbox">Accept into vault</button></div>`);
   $('#modal').addEventListener('close',()=>{phrase='';URL.revokeObjectURL(url);$('#modal').replaceChildren();},{once:true});
   $('#accept-inbox').onclick=async()=>{const accept=$('#accept-inbox');accept.disabled=true;try{await api(`/inbox/submissions/${s.id}/accept`,'POST',{passphrase:phrase});$('#modal').close();toast('Verified file accepted into your vault');await renderInbox(ctx);}catch(err){$('#accept-error').textContent=err.message;accept.disabled=false;}};
  }catch(err){phrase='';form.querySelector('.error').textContent=err.message;button.disabled=false;}
 };
}
