
'use strict';
const el=id=>document.getElementById(id);
let providers=[];
function toast(s){const n=el('status');n.textContent=s;n.hidden=false;clearTimeout(toast.t);toast.t=setTimeout(()=>n.hidden=true,5000)}
function auth(){const t=el('admin-token').value.trim();if(!t)throw Error('请输入管理员令牌');return t}
async function api(path,opt={},token){const headers=new Headers(opt.headers||{});if(token)headers.set('Authorization','Bearer '+token);if(opt.body&&typeof opt.body==='string'&&!headers.has('Content-Type'))headers.set('Content-Type','application/json');const res=await fetch(path,{...opt,headers,credentials:'same-origin'});const json=await res.json().catch(()=>({error:'invalid server response'}));if(!res.ok)throw Error(json.error||'HTTP '+res.status);return json}
function show(id,obj){el(id).textContent=JSON.stringify(obj,null,2)}
async function refreshProfile(){try{const me=await api('/me');el('user').textContent=me.name+' · '+me.id;el('logout').hidden=false;const linked=await api('/me/links');const parent=el('links');parent.replaceChildren();for(const v of linked){const box=document.createElement('div');box.className='item row';const label=document.createElement('span');label.textContent=v.provider+' · '+v.subject;const btn=document.createElement('button');btn.className='danger';btn.textContent='解绑';btn.onclick=async()=>{if(!confirm('解绑 '+v.provider+'？至少保留一种登录方式。'))return;try{await api('/me/unlink/'+encodeURIComponent(v.provider),{method:'POST'});refreshProfile()}catch(e){toast(e.message)}};box.append(label,btn);parent.append(box)}renderProviders(true);await refreshApps();await refreshMyClients()}
catch(_){el('user').textContent='尚未登录';el('links').replaceChildren();el('apps').replaceChildren();el('my-clients').replaceChildren();el('logout').hidden=true;renderProviders(false)}}
function renderProviders(link){const p=el('providers');p.replaceChildren();for(const prov of providers){if(link){const form=document.createElement('form');form.method='POST';form.action='/me/link/'+encodeURIComponent(prov.id);const btn=document.createElement('button');btn.className='tonal';btn.textContent='绑定 '+prov.label;form.append(btn);p.append(form)}else{const a=document.createElement('a');a.className='button tonal';a.textContent='登录 '+prov.label;a.href='/login/'+encodeURIComponent(prov.id);p.append(a)}}}
async function loadProviders(){try{providers=await api('/auth/providers');const select=el('mapping-provider');select.replaceChildren();for(const p of providers){const op=document.createElement('option');op.value=p.id;op.textContent=p.label;select.append(op)}renderFlow()}catch(e){toast(e.message)}}

async function refreshApps(){
 const apps=await api('/me/apps');
 const parent=el('apps');parent.replaceChildren();
 if(!apps.length){const p=document.createElement('p');p.className='small';p.textContent='尚未授权任何客户端';parent.append(p);return}
 for(const app of apps){
   const node=document.createElement('div');node.className='item';
   const header=document.createElement('div');header.className='row';
   const title=document.createElement('b');title.textContent=app.name;
   const status=document.createElement('span');status.className='pill';
   status.textContent=app.blocked_until>Date.now()/1000?'临时停用至 '+new Date(app.blocked_until*1000).toLocaleString():app.active_tokens+' 个有效令牌';
   header.append(title,status);node.append(header);
   const desc=document.createElement('p');desc.className='small';desc.textContent=app.id+' · 授权记录 '+app.grant_count;node.append(desc);
   const revoke=document.createElement('button');revoke.className='danger';revoke.textContent='撤销全部令牌';
   revoke.onclick=async()=>{
     if(!confirm('撤销 '+app.name+' 的全部访问令牌？此操作不可恢复。'))return;
     try{const result=await api('/me/apps/'+encodeURIComponent(app.id)+'/revoke',{method:'POST'});
       toast('已吊销 '+result.revoked+' 个令牌');await refreshApps()}catch(e){toast(e.message)}
   };
   node.append(revoke);parent.append(node)
 }
}
async function refreshMyClients(){
 const clients=await api('/me/clients');
 const parent=el('my-clients');parent.replaceChildren();
 if(!clients.length){const p=document.createElement('p');p.className='small';p.textContent='尚未注册客户端';parent.append(p);return}
 for(const c of clients){
   const node=document.createElement('div');node.className='item';
   const label=document.createElement('b');label.textContent=c.name;
   const detail=document.createElement('p');detail.className='small';detail.textContent=c.id+' · '+(c.enabled?'已启用':'已停用')+(c.public_client?' · 公共客户端':' · 机密客户端');
   const actions=document.createElement('div');actions.className='actions';
   const toggle=document.createElement('button');toggle.className=c.enabled?'danger':'tonal';
   toggle.textContent=c.enabled?'停用并吊销所有令牌':'重新启用';
   toggle.onclick=async()=>{
     if(c.enabled&&!confirm('停用 '+c.name+'？已签发令牌将永久失效。'))return;
     try{await api('/me/clients/'+encodeURIComponent(c.id)+(c.enabled?'/disable':'/enable'),{method:'POST'});
       toast('已更新我的客户端');await refreshMyClients()}catch(e){toast(e.message)}
   };
   actions.append(toggle);
   if(!c.public_client){
     const rotate=document.createElement('button');rotate.className='outline';rotate.textContent='轮换客户端密钥';
     rotate.onclick=async()=>{
       if(!confirm('轮换密钥会使该应用所有旧令牌失效，继续？'))return;
       try{const result=await api('/me/clients/'+encodeURIComponent(c.id)+'/rotate',{method:'POST'});
         show('client-output',result);toast('新密钥已生成，请立即保存')}catch(e){toast(e.message)}
     };
     actions.append(rotate)
   }
   node.append(label,detail,actions);parent.append(node)
 }
}
function registrationPayload(){
 return {client_name:el('client-name').value,
   redirect_uris:el('client-redirects').value.split('\\n').map(s=>s.trim()).filter(Boolean),
   public_client:el('client-public').checked}
}
function renderClientControls(clients){
 const parent=el('client-controls');parent.replaceChildren();
 for(const c of clients){
   const node=document.createElement('div');node.className='item';
   const label=document.createElement('b');label.textContent=c.name;
   const id=document.createElement('p');id.className='small';id.textContent=c.id+(c.enabled?' · 已启用':' · 已停用');
   node.append(label,id);
   const actions=document.createElement('div');actions.className='actions';
   const toggle=document.createElement('button');toggle.className=c.enabled?'danger':'tonal';
   toggle.textContent=c.enabled?'停用并吊销令牌':'重新启用';
   toggle.onclick=async()=>{try{
      if(c.enabled&&!confirm('停用 '+c.name+'？全部旧令牌将永久失效。'))return;
      await api('/admin/clients/'+encodeURIComponent(c.id)+(c.enabled?'/disable':'/enable'),{method:'POST'},auth());
      toast('客户端状态已更新');await refreshAdmin()
   }catch(e){toast(e.message)}};
   const rotate=document.createElement('button');rotate.className='outline';rotate.textContent='轮换密钥';
   rotate.onclick=async()=>{try{
      if(!confirm('轮换 '+c.name+' 的客户端密钥？旧令牌全部失效。'))return;
      const data=await api('/admin/clients/'+encodeURIComponent(c.id)+'/rotate',{method:'POST'},auth());
      show('client-output',data);toast('新密钥已生成，请立即保存（只显示一次）')
   }catch(e){toast(e.message)}};
   actions.append(toggle,rotate);node.append(actions);parent.append(node)
 }
}
function renderPolicyControls(policies){
 const parent=el('policy-controls');parent.replaceChildren();
 for(const p of policies){
   const node=document.createElement('div');node.className='item';
   const label=document.createElement('div');label.textContent=p.source_client+' → '+p.target_client+' · '+p.action+
     (p.action==='suspend'?' · '+p.duration_seconds+' 秒':'');
   const remove=document.createElement('button');remove.className='danger';remove.textContent='删除规则';
   remove.onclick=async()=>{try{
     if(!confirm('删除该应用联动规则？'))return;
     await api('/admin/policies/'+encodeURIComponent(p.id),{method:'DELETE'},auth());
     toast('规则已删除');await refreshAdmin()
   }catch(e){toast(e.message)}};
   node.append(label,remove);parent.append(node)
 }
}

async function refreshAdmin(){const t=auth();const clients=await api('/admin/clients',{},t);const policies=await api('/admin/policies',{},t);show('clients-output',clients);show('policies-output',policies);renderClientControls(clients);renderPolicyControls(policies);if(providers.length)await loadMapping()}
async function loadMapping(){const id=el('mapping-provider').value;if(!id)return;const m=await api('/admin/mappings/'+encodeURIComponent(id),{},auth());el('mapping-fields').value=JSON.stringify(m.fields,null,2);el('mapping-script').value=m.script;renderFlow()}
function readMap(){return{fields:JSON.parse(el('mapping-fields').value),script:el('mapping-script').value}}
function renderFlow(){const svg=el('flow');svg.replaceChildren();let fields;try{fields=JSON.parse(el('mapping-fields').value)}catch(_){fields={}}const NS='http://www.w3.org/2000/svg';const node=(tag,attrs,text)=>{const n=document.createElementNS(NS,tag);for(const [k,v] of Object.entries(attrs))n.setAttribute(k,String(v));if(text)n.textContent=text;svg.append(n);return n};const items=Object.entries(fields).filter(([k,v])=>['name','email','avatar'].includes(k)&&typeof v==='string').slice(0,3);items.forEach(([target,source],i)=>{const y=32+i*72;node('rect',{x:15,y,width:182,height:48,rx:12,class:'node'});node('text',{x:27,y:y+29},source.substring(0,23));node('path',{d:'M197 '+(y+24)+' C250 '+(y+24)+', 265 '+(y+24)+', 323 '+(y+24),class:'edge'});node('circle',{cx:260,cy:y+24,r:4,class:'dot'});node('rect',{x:323,y,width:176,height:48,rx:12,class:'node'});node('text',{x:336,y:y+29},target)});if(!items.length)node('text',{x:26,y:40},'添加 JSON 字段映射以生成流图')}
el('mapping-fields').addEventListener('input',renderFlow);
el('mapping-provider').onchange=()=>loadMapping().catch(e=>toast(e.message));
el('admin-refresh').onclick=()=>refreshAdmin().catch(e=>toast(e.message));
el('client-own-create').onclick=async()=>{try{
 const data=await api('/me/clients',{method:'POST',body:JSON.stringify(registrationPayload())});
 show('client-output',data);toast('已注册个人客户端，请立即保存密钥');await refreshMyClients()
}catch(e){toast(e.message)}};
el('client-create').onclick=async()=>{try{const token=el('registration-token').value.trim()||auth();const payload=registrationPayload();const data=await api('/connect/register',{method:'POST',body:JSON.stringify(payload)},token);show('client-output',data);toast('注册成功，立即保存唯一返回的密钥')}catch(e){toast(e.message)}};
el('policy-create').onclick=async()=>{try{await api('/admin/policies',{method:'POST',body:JSON.stringify({source_client:el('source-client').value.trim(),target_client:el('target-client').value.trim(),action:el('policy-action').value,duration_seconds:Number(el('policy-duration').value)})},auth());await refreshAdmin();toast('已创建联动规则')}catch(e){toast(e.message)}};
el('mapping-preview').onclick=async()=>{try{const data=await api('/admin/mappings/'+encodeURIComponent(el('mapping-provider').value)+'/preview',{method:'POST',body:JSON.stringify({...readMap(),raw:JSON.parse(el('mapping-raw').value)})},auth());show('mapping-output',data)}catch(e){toast(e.message)}};
el('mapping-save').onclick=async()=>{try{await api('/admin/mappings/'+encodeURIComponent(el('mapping-provider').value),{method:'PUT',body:JSON.stringify(readMap())},auth());toast('映射规则已保存')}catch(e){toast(e.message)}};
el('logout').onclick=async()=>{try{await api('/session/logout',{method:'POST'});refreshProfile()}catch(e){toast(e.message)}};
el('background-upload').onclick=async()=>{try{const file=el('background').files[0];if(!file)throw Error('请选择背景图片');const res=await fetch('/admin/background',{method:'POST',headers:{'Authorization':'Bearer '+auth(),'Content-Type':file.type},body:file});const obj=await res.json();if(!res.ok)throw Error(obj.error||'上传失败');applySeed(obj.seed);applyMonet(obj.palette);document.body.classList.add('has-wallpaper');el('theme-note').textContent='Material HCT 动态色板已从图片生成';toast('背景图已更新')}catch(e){toast(e.message)}};
function applySeed(seed){if(/^#[0-9a-f]{6}$/i.test(seed)){document.documentElement.style.setProperty('--seed',seed);document.documentElement.style.setProperty('--primary',seed)}}
function materialColor(value){
 if(typeof value==='number')return '#'+(value & 0xffffff).toString(16).padStart(6,'0');
 if(typeof value==='string'){
   if(/^#[0-9a-f]{6}$/i.test(value))return value;
   if(/^#[0-9a-f]{8}$/i.test(value))return '#'+value.slice(-6);
   if(/^0x[0-9a-f]{8}$/i.test(value))return '#'+value.slice(-6);
 }
 return null
}
function applyMonet(theme){
 const scheme=theme?.schemes?.[matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'];
 if(!scheme)return;
 const mappings={'primary':['primary'],'on-primary':['on_primary','onPrimary'],'surface':['surface'],
   'surface-container':['surface_container','surfaceContainer'],
   'surface-high':['surface_container_high','surfaceContainerHigh'],
   'text':['on_surface','onSurface'],'outline':['outline']};
 for(const [css,keys] of Object.entries(mappings)){
   const v=keys.map(k=>materialColor(scheme[k])).find(Boolean);
   if(v)document.documentElement.style.setProperty('--'+css,v)
 }
}
async function theme(){
 try{
   const r=await fetch('/admin/background');if(r.ok){
     document.body.classList.add('has-wallpaper');
     applySeed(r.headers.get('x-theme-seed')||'#6750a4')
   }
   const p=await fetch('/theme');if(p.ok)applyMonet(await p.json())
 }catch(_){}
}
async function cryptoWasm(){try{const w=await import('/wasm/sso_frontend_crypto.js');await w.default();return w}catch(_){throw Error('WASM 加密包尚未构建；请运行 wasm-pack build frontend-crypto --target web --out-dir ../web/wasm --release')}}
el('draft-encrypt').onclick=async()=>{try{const w=await cryptoWasm();const data=JSON.stringify(readMap());el('draft-payload').value=w.encrypt_text(data,el('draft-pass').value);toast('草稿已在 WASM 中加密，请复制密文备份')}catch(e){toast(String(e))}};
el('draft-decrypt').onclick=async()=>{try{const w=await cryptoWasm();const obj=JSON.parse(w.decrypt_text(el('draft-payload').value.trim(),el('draft-pass').value));if(typeof obj.script!=='string'||!obj.fields||typeof obj.fields!=='object')throw Error('解密结构无效');el('mapping-fields').value=JSON.stringify(obj.fields,null,2);el('mapping-script').value=obj.script;renderFlow();toast('本地草稿已解密，不会自动保存到服务端')}catch(e){toast(String(e))}};
loadProviders().then(refreshProfile);theme();renderFlow();
