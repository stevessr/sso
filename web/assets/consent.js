
'use strict';
const q=new URLSearchParams(location.search), id=q.get('request');
const byId=name=>document.getElementById(name);
function error(message){byId('message').textContent=message}
async function load(){
 if(!id||id.length>256){error('授权请求参数无效');return}
 try{
 const r=await fetch('/oauth/consent/request?request='+encodeURIComponent(id),{credentials:'same-origin',cache:'no-store'});
 const v=await r.json();if(!r.ok)throw Error(v.error||'授权请求已失效');
 byId('app').textContent=v.client_name;
 byId('client-id').textContent=v.client_id;
 byId('redirect').textContent=v.redirect_uri;
 const scope=byId('scopes');scope.replaceChildren();
 for(const name of v.scope.split(/\s+/).filter(Boolean)){const chip=document.createElement('span');chip.textContent=name==='email'?'读取已验证邮箱':name==='profile'?'读取个人资料':name==='offline_access'?'允许应用离线续期访问（最长 30 天，令牌轮换）':name;scope.append(chip)}
 byId('request-value').value=id;byId('allow').disabled=false;byId('deny').disabled=false;
 }catch(e){error(e.message)}
}
load();
