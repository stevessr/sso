'use strict';
const input=document.getElementById('mfa-code'),message=document.getElementById('mfa-error');
async function submitMfa(){
 const button=document.getElementById('mfa-submit');button.disabled=true;message.textContent='';
 try{
  const response=await fetch('/mfa/verify',{method:'POST',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},body:JSON.stringify({code:input.value.trim()})});
  const body=await response.json();if(!response.ok)throw Error(body.error||'验证失败');
  if(typeof body.next!=='string'||!body.next.startsWith('/')||body.next.startsWith('//'))throw Error('非法跳转地址');
  location.assign(body.next);
 }catch(error){message.textContent=error.message;input.value='';button.disabled=false}
}
document.getElementById('mfa-submit').onclick=submitMfa;
input.addEventListener('keydown',event=>{if(event.key==='Enter')submitMfa()});
input.focus();

const webauthnB64Url={
 decode(value){
  const source=value.replace(/-/g,'+').replace(/_/g,'/');
  const binary=atob(source.padEnd(Math.ceil(source.length/4)*4,'='));
  return Uint8Array.from(binary,c=>c.charCodeAt(0));
 },
 encode(value){
  const bytes=new Uint8Array(value);let binary='';
  for(const b of bytes)binary+=String.fromCharCode(b);
  return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
 }
};
document.getElementById('mfa-passkey').onclick=async()=>{
 const button=document.getElementById('mfa-passkey');
 button.disabled=true;message.textContent='';
 try{
  if(!navigator.credentials?.get)throw Error('当前浏览器不支持 Passkey');
  const start=await fetch('/passkeys/stepup/start',{method:'POST',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},body:'{}'});
  const challenge=await start.json();if(!start.ok)throw Error(challenge.error||'验证开始失败');
  const options=challenge.options.publicKey;
  options.challenge=webauthnB64Url.decode(options.challenge);
  for(const c of options.allowCredentials||[])c.id=webauthnB64Url.decode(c.id);
  const assertion=await navigator.credentials.get({publicKey:options});
  if(!assertion)throw Error('未完成身份验证');
  let credential;
  if(typeof assertion.toJSON==='function')credential=assertion.toJSON();
  else credential={
   id:assertion.id,rawId:webauthnB64Url.encode(assertion.rawId),type:assertion.type,
   clientExtensionResults:assertion.getClientExtensionResults(),
   response:{authenticatorData:webauthnB64Url.encode(assertion.response.authenticatorData),
    clientDataJSON:webauthnB64Url.encode(assertion.response.clientDataJSON),
    signature:webauthnB64Url.encode(assertion.response.signature),
    userHandle:assertion.response.userHandle?webauthnB64Url.encode(assertion.response.userHandle):null}
  };
  const response=await fetch('/passkeys/stepup/finish',{method:'POST',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({request_id:challenge.request_id,credential})});
  const result=await response.json();if(!response.ok)throw Error(result.error||'Passkey 验证失败');
  if(!result.next?.startsWith('/')||result.next.startsWith('//'))throw Error('无效重定向');
  location.assign(result.next);
 }catch(e){message.textContent=e.message;button.disabled=false}
};
