'use strict';
// Admin-only Cloudflare Zero Trust Access inventory and explicit app linking.
// API tokens remain exclusively on the server; never expose them to this script.
(()=>{
 const id=x=>document.getElementById(x);
 const node=(tag,cls,txt)=>{
   const el=document.createElement(tag);
   if(cls)el.className=cls;
   if(txt!==undefined)el.textContent=String(txt);
   return el;
 };
 let currentApps=[];
 let currentLinks=[];
 let revokeEnabled=false;

 function renderLinks(){
   const target=id('cf-links');target.replaceChildren();
   if(!currentLinks.length){
     target.append(node('p','small','没有关联的 SSO 客户端'));return;
   }
   for(const l of currentLinks){
     const box=node('div','item');
     box.append(node('b','',l.client_name||l.client_id),
                node('p','small',l.client_id+' ↔ '+l.access_app_id));
     const remove=node('button','outline','取消关联');
     remove.onclick=async()=>{
       if(!confirm('只删除本地关联关系，不会修改 Cloudflare Access 策略。继续？'))return;
       remove.disabled=true;
       try{await api('/admin/cloudflare/links/'+encodeURIComponent(l.client_id),
                     {method:'DELETE'},auth());
         toast('已取消本地关联');await refresh();
       }catch(e){toast(e.message)}
       finally{remove.disabled=false}
     };
     box.append(remove);target.append(box);
   }
 }
 function renderApps(){
   const target=id('cf-apps');target.replaceChildren();
   if(!currentApps.length){target.append(node('p','small','没有 Access 应用'));return}
   for(const app of currentApps){
     const box=node('div','item');
     box.append(node('b','',app.name||app.id),
                node('p','small',[app.id,app.domain,app.type].filter(Boolean).join(' · ')));
     const select=node('button','tonal','填写此应用 ID');
     select.onclick=()=>{id('cf-app-id').value=app.id};
     box.append(select);
     const linked=currentLinks.some(l=>l.access_app_id===app.id);
     if(revokeEnabled&&linked){
       const revoke=node('button','danger','吊销此 Access 应用的全部令牌');
       revoke.onclick=async()=>{
         const typed=prompt('高风险操作：将强制退出此 Cloudflare Access 应用的全部用户。\n请输入完整 Access 应用 ID 确认：');
         if(typed!==app.id)return;
         if(!confirm('最终确认：吊销 '+(app.name||app.id)+' 的全部 Cloudflare Access 令牌？不可撤回。'))return;
         revoke.disabled=true;
         try{
           const result=await api('/admin/cloudflare/apps/'+encodeURIComponent(app.id)+'/revoke-tokens',{
             method:'POST',
             body:JSON.stringify({confirm_app_id:typed,confirmation:'REVOKE_ALL_ACCESS_TOKENS'})
           },auth());
           toast('Cloudflare 吊销请求成功；操作编号 '+result.operation_id);
         }catch(e){toast(e.message)}
         finally{revoke.disabled=false}
       };
       box.append(revoke);
     }
     target.append(box);
   }
 }
 async function refresh(){
   const token=auth();
   const s=await api('/admin/cloudflare/status',{},token);
   revokeEnabled=!!s.revoke_enabled;
   id('cf-status').textContent=!s.configured
     ? '未配置 Cloudflare。请在服务端设置账户 ID 和 API Token。'
     : '已连接账户 '+s.account_id+' · '+(revokeEnabled
         ? '危险操作已启用（仅限已关联应用，影响所有用户）'
         : '只读模式；应用令牌吊销已关闭');
   if(!s.configured){
     currentApps=[];currentLinks=[];renderApps();renderLinks();return;
   }
   const page=Math.min(100,Math.max(1,Number(id('cf-page').value)||1));
   const [apps,groups,policies,links,clients]=await Promise.allSettled([
     api('/admin/cloudflare/apps?page='+page,{},token),
     api('/admin/cloudflare/groups?page='+page,{},token),
     api('/admin/cloudflare/policies?page='+page,{},token),
     api('/admin/cloudflare/links',{},token),
     api('/admin/clients',{},token)
   ]);
   if(apps.status==='rejected')throw apps.reason;
   currentApps=apps.value.items||[];
   currentLinks=links.status==='fulfilled'?links.value:[];
   renderApps();renderLinks();
   id('cf-inventory-count').textContent=
     'Access 应用：本页 '+currentApps.length+' 条（第 '+page+' 页，每页最多 50 条）。';
   id('cf-groups').textContent=groups.status==='fulfilled'
     ?JSON.stringify(groups.value.items,null,2):'无读取群组的权限或 API 请求失败';
   id('cf-policies').textContent=policies.status==='fulfilled'
     ?JSON.stringify(policies.value.items,null,2):'无读取策略的权限或 API 请求失败';
   const select=id('cf-client-id');select.replaceChildren();
   if(clients.status==='fulfilled'){
     for(const c of clients.value){
       const opt=node('option','',c.name+' · '+c.id);opt.value=c.id;select.append(opt);
     }
   }
 }
 id('cf-refresh').onclick=()=>refresh().catch(e=>{id('cf-status').textContent=e.message;toast(e.message)});
 id('cf-link').onclick=async()=>{
   const client=id('cf-client-id').value;
   const app=id('cf-app-id').value.trim();
   if(!client||!app){toast('请选择 SSO 客户端并填写 Access 应用 ID');return}
   try{
     await api('/admin/cloudflare/links/'+encodeURIComponent(client),{
       method:'PUT',body:JSON.stringify({access_app_id:app})
     },auth());
     toast('已关联；没有修改 Cloudflare Access 策略');await refresh();
   }catch(e){toast(e.message)}
 };
})();
