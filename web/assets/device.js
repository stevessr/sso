'use strict';
const $=id=>document.getElementById(id);
const initial=new URL(location.href).searchParams.get('user_code');
if(initial) $('user-code').value=initial;
const code=()=>$('user-code').value.toUpperCase().replace(/[\s-]/g,'').replace(/^(.{4})(.{4})$/,'$1-$2');
let verifiedCode='';
async function json(url,options){
 const r=await fetch(url,{credentials:'same-origin',...options});
 const body=await r.json().catch(()=>({}));
 if(!r.ok)throw Object.assign(Error(body.error||'无法验证请求'),{status:r.status});
 return body;
}
$('lookup').onclick=async()=>{
 $('feedback').textContent='';$('request').hidden=true;$('sign-in').hidden=true;
 const value=code();
 if(!/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/.test(value)){
  $('feedback').textContent='请输入设备上的八位验证码';return;
 }
 try{
  const data=await json('/oauth/device/request?user_code='+encodeURIComponent(value));
  verifiedCode=value;
  $('client').textContent=data.client_name+' ('+data.client_id+')';
  const labels={profile:'基本资料',email:'电子邮箱',offline_access:'长期离线访问（刷新令牌）'};
  $('scopes').textContent=data.scope.split(/\s+/).map(x=>labels[x]||x).join('、');
  $('request').hidden=false;
 }catch(e){
  $('feedback').textContent=e.status===401||e.status===403?'请先登录并完成二次验证，再重新查询设备码':e.message;
  if(e.status===401||e.status===403){
   $('sign-in').hidden=false;
   json('/auth/providers').then(providers=>{
    $('providers').replaceChildren();
    for(const p of providers){
     const a=document.createElement('a');a.className='provider';a.textContent=p.label;
     a.href='/login/'+encodeURIComponent(p.id);a.target='_blank';a.rel='noopener';
     $('providers').append(a);
    }
   }).catch(()=>{});
  }
 }
};
for(const decision of ['allow','deny']){
 $(decision).onclick=async()=>{
  if(!verifiedCode)return;
  $('allow').disabled=true;$('deny').disabled=true;
  try{
   await json('/oauth/device/decision',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({user_code:verifiedCode,decision})});
   $('feedback').textContent=decision==='allow'?'授权成功，可以返回发起请求的设备':'已拒绝该设备的访问请求';
   $('request').hidden=true;verifiedCode='';
  }catch(e){$('feedback').textContent=e.message}
  finally{$('allow').disabled=false;$('deny').disabled=false}
 };
}
if(initial)$('lookup').click();
