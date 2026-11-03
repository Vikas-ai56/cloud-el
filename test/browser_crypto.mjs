import {setupKeys,encryptFile,unlock,rewrap,hash} from '../public/crypto.js';
const alice=await setupKeys('browser-test-phrase'),bob=await setupKeys('recipient-phrase');
const original=new File(['browser encrypted payload'],'browser.txt',{type:'text/plain'});
const payload=await encryptFile(original,[{id:'alice',public_key:alice.public_key}]);
const privateKey=await unlock(alice,'browser-test-phrase');
const envelopes=await rewrap([{id:'version',wrapped_dek:payload.envelopes.alice}],privateKey,bob.public_key);
let rejected=false;try{await unlock(alice,'incorrect');}catch{rejected=true;}
if(!rejected)throw Error('Wrong passphrase accepted');
console.log(JSON.stringify({alice,bob,payload,envelopes,checksum:await hash(await original.arrayBuffer())}));
