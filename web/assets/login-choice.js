'use strict';
const field=document.getElementById('account'),error=document.getElementById('login-error');
const base64={
 from(value){const b=value.replace(/-/g,'+').replace(/_/g,'/');
   return Uint8Array.from(atob(b.padEnd(Math.ceil(b.length/4)*4,'=')),c=>c.charCodeAt(0))},
 to(buffer){let binary='';for(const v of new Uint8Array(buffer))binary+=String.fromCharCode(v);
   return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}
};
async function send(path,body){
 const response=await fetch(path,{method:'POST',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
 const data=await response.json();
 if(!response.ok)throw Error(data.error||'验证失败');
 return data;
}
function assertionJson(credential){
 if(typeof credential.toJSON==='function')return credential.toJSON();
 return {id:credential.id,type:credential.type,rawId:base64.to(credential.rawId),
  clientExtensionResults:credential.getClientExtensionResults(),
  response:{clientDataJSON:base64.to(credential.response.clientDataJSON),
   authenticatorData:base64.to(credential.response.authenticatorData),
   signature:base64.to(credential.response.signature),
   userHandle:credential.response.userHandle?base64.to(credential.response.userHandle):null}};
}
document.getElementById('passkey-submit').onclick=async()=>{
 error.textContent='';
 const button=document.getElementById('passkey-submit');button.disabled=true;
 try{
  if(!navigator.credentials?.get)throw Error('该浏览器不支持 WebAuthn');
  if(!field.value.trim())throw Error('请输入账户 ID');
  const start=await send('/passkeys/login/start',{user_id:field.value.trim()});
  const options=start.options.publicKey;
  options.challenge=base64.from(options.challenge);
  for(const credential of options.allowCredentials||[])credential.id=base64.from(credential.id);
  const response=await navigator.credentials.get({publicKey:options});
  if(!response)throw Error('未完成 Passkey 验证');
  await send('/passkeys/login/finish',{request_id:start.request_id,credential:assertionJson(response)});
  // The existing authorization URL contains the validated PKCE request and
  // now sees an authenticated first-party session.
  location.reload();
 }catch(e){error.textContent=e.message;button.disabled=false}
};
(async()=>{
 try{
  const response=await fetch('/auth/providers',{credentials:'same-origin'});
  if(!response.ok)throw Error('无法获取登录提供商');
  const providers=await response.json(),area=document.getElementById('provider-buttons');
  for(const provider of providers){
   const link=document.createElement('a');link.className='button tonal';
   link.textContent=provider.label;
   const url=new URL(location.href);
   url.searchParams.set('provider',provider.id);
   link.href=url.pathname+url.search;
   area.append(link);
  }
  if(!providers.length)area.textContent='没有配置第三方登录提供商。';
 }catch(e){error.textContent=e.message}
})();