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
