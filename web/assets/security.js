'use strict';
// Browser WebAuthn JSON adapter. No credential private keys are exposed here;
// browser/platform authenticators execute every cryptographic operation.
(() => {
const byId=id=>document.getElementById(id);
const status=message=>{const out=byId('totp-setup-output');if(out)out.textContent=message};
const b64decode=text=>{
 const base=text.replace(/-/g,'+').replace(/_/g,'/');
 const binary=atob(base.padEnd(Math.ceil(base.length/4)*4,'='));
 return Uint8Array.from(binary,ch=>ch.charCodeAt(0));
};
const b64encode=value=>{
 const bytes=new Uint8Array(value);
 let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);
 return btoa(binary).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
};
const creation=options=>{
 const key=options.publicKey;
 key.challenge=b64decode(key.challenge);
 key.user.id=b64decode(key.user.id);
 for(const c of key.excludeCredentials||[])c.id=b64decode(c.id);
 return {publicKey:key};
};
const request=options=>{
 const key=options.publicKey;
 key.challenge=b64decode(key.challenge);
 for(const c of key.allowCredentials||[])c.id=b64decode(c.id);
 return {publicKey:key};
};
const serialize=credential=>{
 if(typeof credential.toJSON==='function')return credential.toJSON();
 const response=credential.response;
 const common={id:credential.id,rawId:b64encode(credential.rawId),type:credential.type,
   clientExtensionResults:credential.getClientExtensionResults()};
 if(response.attestationObject){
   return {...common,response:{attestationObject:b64encode(response.attestationObject),
     clientDataJSON:b64encode(response.clientDataJSON),transports:response.getTransports?.()||[]}};
 }
 return {...common,response:{authenticatorData:b64encode(response.authenticatorData),
   clientDataJSON:b64encode(response.clientDataJSON),signature:b64encode(response.signature),
   userHandle:response.userHandle?b64encode(response.userHandle):null}};
};
async function post(path,data){
 const r=await fetch(path,{method:'POST',credentials:'same-origin',
   headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
 const json=await r.json();if(!r.ok)throw Error(json.error||'请求失败');return json;
}
async function passkeys(){
 const target=byId('passkey-list');target.replaceChildren();
 const r=await fetch('/me/passkeys',{credentials:'same-origin'});
 if(!r.ok){target.textContent='登录后可以添加通行密钥。';return}
 const keys=await r.json();
 if(!keys.length){target.textContent='当前账户尚无 Passkey。';return}
 for(const key of keys){
  const box=document.createElement('div');box.className='item';
  const title=document.createElement('span');title.textContent=key.label+' · '+new Date(key.created*1000).toLocaleDateString();
  const del=document.createElement('button');del.textContent='删除';del.className='danger';
  del.onclick=async()=>{
   if(!confirm('删除该 Passkey？请确认还有其他可用的登录方式。'))return;
   const r=await fetch('/me/passkeys/'+encodeURIComponent(key.id),{method:'DELETE',credentials:'same-origin'});
   if(!r.ok){status('删除失败');return}await passkeys();
  };
  box.append(title,del);target.append(box);
 }
}
byId('passkey-enroll').onclick=async()=>{
 try {
  if(!navigator.credentials?.create)throw Error('当前浏览器不支持 WebAuthn');
  const challenge=await post('/passkeys/register/start',{});
  const credential=await navigator.credentials.create(creation(challenge.options));
  if(!credential)throw Error('未创建凭据');
  await post('/passkeys/register/finish',{request_id:challenge.request_id,
    credential:serialize(credential),label:'Passkey'});
  status('Passkey 已添加，可以用于登录。');await passkeys();
 }catch(e){status('Passkey 注册失败：'+e.message)}
};
byId('passkey-login').onclick=async()=>{
 try{
  if(!navigator.credentials?.get)throw Error('当前浏览器不支持 WebAuthn');
  const user_id=byId('passkey-user-id').value.trim();
  if(!user_id)throw Error('需要账户 ID。');
  const challenge=await post('/passkeys/login/start',{user_id});
  const credential=await navigator.credentials.get(request(challenge.options));
  if(!credential)throw Error('未完成 Passkey 验证');
  const result=await post('/passkeys/login/finish',{request_id:challenge.request_id,
    credential:serialize(credential)});
  if(result.ok)location.assign(result.next||'/');
 }catch(e){status('Passkey 登录失败：'+e.message)}
};
byId('totp-start').onclick=async()=>{
 try{
  const v=await post('/mfa/enroll/start',{});
  status('请将以下密钥添加到身份验证器，然后输入当前动态码以启用。\n\n密钥：'+v.secret+
    '\n\nOTPAuth URI：\n'+v.otpauth_uri+'\n\n十分钟内有效。');
 }catch(e){status('创建失败：'+e.message)}
};
byId('totp-confirm').onclick=async()=>{
 try{
  const v=await post('/mfa/enroll/confirm',{code:byId('totp-code').value.trim()});
  status('TOTP 已启用。\n以下恢复码只显示这一次，请离线保存：\n\n'+v.recovery_codes.join('\n'));
  byId('totp-code').value='';
 }catch(e){status('启用失败：'+e.message)}
};
byId('totp-status').onclick=async()=>{
 try{
  const response=await fetch('/mfa/status',{credentials:'same-origin'});
  const v=await response.json();if(!response.ok)throw Error(v.error||'请先登录');
  status('TOTP：'+(v.enabled?'已启用':'未启用')+'；当前会话：'+(v.verified?'已验证':'需要验证')+
     '；可用恢复码：'+v.recovery_remaining);
 }catch(e){status(e.message)}
};
byId('totp-disable').onclick=async()=>{
 if(!confirm('停用双重验证会使所有已登录设备退出，确定继续吗？'))return;
 try{
  const v=await post('/mfa/disable',{code:byId('totp-code').value.trim()});
  if(v.disabled)location.assign('/');
 }catch(e){status('停用失败：'+e.message)}
};
fetch('/me',{credentials:'same-origin'}).then(async response=>{
 if(response.ok){const profile=await response.json();byId('passkey-user-id').value=profile.id||''}
}).catch(()=>{});
passkeys().catch(()=>{});
})();