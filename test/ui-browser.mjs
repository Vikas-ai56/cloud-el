// UI regression check; run against an isolated, seeded server.
import assert from 'node:assert/strict';
import {mkdir,readFile} from 'node:fs/promises';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE||'playwright');
const base=process.env.TEST_BASE_URL||'http://127.0.0.1:3012';
const screenshots=process.env.SCREENSHOT_DIR||'/private/tmp/securevault-ui-screenshots';
await mkdir(screenshots,{recursive:true});
const browser=await chromium.launch({headless:true});const errors=[];
try{
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),p=await context.newPage();
 p.on('pageerror',e=>errors.push(e.message));
 await p.goto(base);await p.locator('#login-email').waitFor();
 await p.screenshot({path:screenshots+'/01-login.png',fullPage:true});
 await p.locator('#reveal-password').click();assert.equal(await p.locator('#login-password').getAttribute('type'),'text');await p.locator('#reveal-password').click();
 await p.locator('#auth button[type=submit]').click();await p.locator('#upload').waitFor();
 async function upload(name,mime,buffer){await p.locator('#upload').click();await p.locator('#upload-form input[type=file]').setInputFiles({name,mimeType:mime,buffer});await p.locator('#upload-form button[type=submit]').click();await p.locator('#modal').waitFor({state:'hidden'});await p.getByRole('button',{name}).first().waitFor();}
 await upload('Project brief.txt','text/plain',Buffer.from('A private workspace for the project team.'));
 await upload('Artwork.png','image/png',Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl2nQAAAABJRU5ErkJggg==','base64'));
 await upload('Team voice note.wav','audio/wav',await readFile('samples/demo-audio.wav'));
 await upload('Product walkthrough.mp4','video/mp4',await readFile('samples/demo-video.mp4'));
 await p.locator('[data-filter=document]').click();assert.equal(await p.locator('#rows tr').count(),1);
 await p.locator('[data-filter=image]').click();assert.equal(await p.locator('#rows tr').count(),1);
 await p.locator('[data-filter=media]').click();assert.equal(await p.locator('#rows tr').count(),2);
 await p.locator('[data-filter=all]').click();await p.locator('#search').fill('nothing matches');await p.getByText('No matching objects',{exact:true}).waitFor();
 await p.locator('#search').fill('');await p.locator('#sort').selectOption('name');
 assert.equal(await p.locator('#rows tr').first().locator('strong').textContent(),'Artwork.png');
 await p.screenshot({path:screenshots+'/02-object-browser.png',fullPage:true});
 await p.getByRole('button',{name:'Project brief.txt',exact:false}).first().click();await p.locator('#new-version').waitFor();
 await p.locator('#new-version').click();await p.locator('#upload-form input[type=file]').setInputFiles({name:'Project brief.txt',mimeType:'text/plain',buffer:Buffer.from('A second immutable snapshot.')});await p.locator('#upload-form button[type=submit]').click();await p.locator('#modal').waitFor({state:'hidden'});
 await p.locator('[data-restore]').first().click();await p.getByText('Version 3',{exact:true}).waitFor();
 await p.locator('#share').click();await p.locator('#share-form input[name=email]').fill('bob@securevault.local');await p.locator('#share-form input[name=passphrase]').fill('vault-demo-phrase');await p.locator('#share-form button[type=submit]').click();await p.locator('#modal').waitFor({state:'hidden'});await p.locator('[data-revoke]').waitFor();
 await p.screenshot({path:screenshots+'/03-file-details.png',fullPage:true});
 await p.locator('[data-download]').first().click();await p.locator('#download-form input').fill('vault-demo-phrase');await p.locator('#download-form button[type=submit]').click();await p.getByText('A private workspace for the project team.',{exact:true}).waitFor();await p.locator('#close').click();
 await p.locator('[data-nav=audit]').click();await p.getByText('Chain verified',{exact:true}).waitFor();await p.screenshot({path:screenshots+'/04-audit.png',fullPage:true});
 await p.locator('[data-nav=inbox]').click();await p.locator('#new-request').click();await p.locator('#request-form input[name=title]').fill('Project handoff');await p.locator('#request-form button[type=submit]').click();const link=await p.locator('#created-link').inputValue();await p.locator('#close').click();
 const guestContext=await browser.newContext({viewport:{width:390,height:844}}),guest=await guestContext.newPage();guest.on('pageerror',e=>errors.push(e.message));await guest.goto(link);await guest.locator('#drop-upload').waitFor();await guest.screenshot({path:screenshots+'/05-public-upload-mobile.png',fullPage:true});
 assert.ok(await guest.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
 await guest.locator('input[type=file]').setInputFiles({name:'Handoff notes.txt',mimeType:'text/plain',buffer:Buffer.from('Files for the owner, from an external uploader.')});await guest.locator('#drop-upload button[type=submit]').click();await guest.getByText('Your file is with the recipient.',{exact:true}).waitFor();
 await p.locator('#inbox-refresh').click();await p.locator('[data-review]').first().waitFor();await p.screenshot({path:screenshots+'/06-inbox.png',fullPage:true});
 await p.setViewportSize({width:390,height:844});await p.locator('[data-nav=files]').click();await p.locator('#rows').waitFor();
 assert.ok(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'File browser overflows mobile viewport');
 await p.screenshot({path:screenshots+'/07-object-browser-mobile.png',fullPage:true});
 await p.locator('#logout').click();await p.locator('#auth').waitFor();await p.screenshot({path:screenshots+'/08-login-mobile.png',fullPage:true});
 assert.deepEqual(errors,[]);console.log('UI checks passed: login, upload, filters, sorting, version restore, sharing, verified download, audit, inbox, public uploader, mobile overflow. Screenshots: '+screenshots);
}finally{await browser.close();}
