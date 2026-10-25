(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const url = new URL(window.location.href);
  const onAdmin = url.pathname === '/admin';
  const onAccount = url.pathname === '/account';
  const onLogin = !onAdmin && !onAccount;
  let meta = { providers: [] }, adminToken = '', clientList = [], mappings = [];

  function notice(value) { $('toast').textContent = String(value); }
  function textNode(tag, content, className) {
    const el = document.createElement(tag);
    el.textContent = content ?? '';
    if (className) el.className = className;
    return el;
  }
  async function request(path, options = {}, admin = false) {
    const headers = { ...(options.headers || {}) };
    if (admin) headers.Authorization = `Bearer ${adminToken}`;
    if (options.body instanceof FormData) { /* Let the browser set the multipart boundary. */ }
    else if (options.body && !(options.body instanceof URLSearchParams)) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, { cache: 'no-store', credentials: 'same-origin', ...options, headers });
    if (!response.ok) {
      let reason;
      try { reason = (await response.json()).error; } catch { reason = await response.text(); }
      throw new Error(`${response.status}: ${reason || 'request_failed'}`);
    }
    return response.status === 204 ? null : response.json();
  }
  function providerButtons(containerId, { link = false, returnTo = '/account' } = {}) {
    const container = $(containerId);
    container.replaceChildren();
    for (const provider of meta.providers) {
      const a = document.createElement('a');
      const path = new URL(`/auth/${encodeURIComponent(provider.id)}/start`, location.origin);
      path.searchParams.set('return_to', link ? '/account' : returnTo);
      if (link) path.searchParams.set('link', 'true');
      a.href = path.pathname + path.search;
      const dot = textNode('span', provider.label[0]?.toUpperCase() ?? '?', 'provider-dot');
      a.append(dot, textNode('span', provider.label));
      container.append(a);
    }
    if (!meta.providers.length) container.append(textNode('p', '尚未配置身份提供商，请通过环境变量添加 Google、Telegram、X 或其他 OIDC 提供商。', 'muted'));
  }
  async function renderAccount() {
    $('page-title').textContent = '一个身份，连接所有应用。';
    $('page-subtitle').textContent = '管理已绑定的上游账号与访问入口。';
    providerButtons('link-providers', { link: true });
    try {
      const user = await request('/api/me');
      $('account-overview').replaceChildren(textNode('strong', user.name), textNode('p', user.email || user.id, 'muted'));
      const linked = await request('/api/me/identities');
      const container = $('identities'); container.replaceChildren();
      for (const id of linked.identities) {
        const item = textNode('div', '', 'item');
        const wrapper = document.createElement('div');
        wrapper.append(textNode('div', id.provider, 'title'), textNode('span', id.subject, 'description'));
        const button = textNode('button', '解绑', 'small outline');
        button.disabled = linked.identities.length < 2;
        button.addEventListener('click', async () => {
          if (!confirm(`确定解除 ${id.provider} 的身份绑定吗？`)) return;
          try { await request(`/api/me/identities/${encodeURIComponent(id.id)}`, { method: 'DELETE' }); await renderAccount(); notice('解绑完成'); }
          catch (err) { notice(err.message); }
        });
        item.append(wrapper, button);container.append(item);
      }
      await renderApps();
    } catch {
      $('account-overview').replaceChildren(textNode('p', '你尚未登录，请先选择一个提供商。'));
      $('identities').replaceChildren(); $('account-apps').replaceChildren();
      $('logout').disabled = true; $('export-encrypted').disabled = true;
      providerButtons('link-providers', { returnTo: '/account' });
      // Unauthenticated account pages must start login, not identity binding.
      [...$('link-providers').querySelectorAll('a')].forEach(a => a.href = a.href.replace('&link=true', ''));
    }
  }
  async function renderApps() {
    const apps = await request('/api/me/apps');
    const holder = $('account-apps'); holder.replaceChildren();
    if (!apps.apps.length) { holder.append(textNode('p', '暂无已授权应用。', 'muted')); return; }
    for (const app of apps.apps) {
      const row = textNode('div', '', 'item');
      const info = document.createElement('div');
      info.append(textNode('div',app.name,'title'),textNode('span',app.allowed?'允许访问':'已暂停访问','description'));
      const actions = textNode('div','','button-row');
      const revoke = textNode('button','吊销令牌','small outline');
      revoke.onclick=async()=>{if(!confirm(`吊销 ${app.name} 的访问令牌？`))return;try{await request(`/api/me/apps/${encodeURIComponent(app.id)}/revoke`,{method:'POST'});notice('令牌已吊销');await renderApps();}catch(err){notice(err.message);}};
      const block=textNode('button',app.allowed?'暂停访问':'解除本人禁用','small secondary');
      block.onclick=async()=>{try{await request(`/api/me/apps/${encodeURIComponent(app.id)}/block`,{method:'POST',body:JSON.stringify({blocked:app.allowed})});await renderApps();notice('应用访问状态已更新');}catch(err){notice(err.message);}};
      actions.append(revoke,block);row.append(info,actions);holder.append(row);
    }
  }
  async function renderLogin() {
    $('page-title').textContent = '身份，不应被应用边界限制。';
    $('page-subtitle').textContent = '通过受信任的身份提供商继续登录。';
    const next = url.searchParams.get('return_to') || '/account';
    const safe = next === '/account' || (next.startsWith('/oauth/authorize?') && !next.includes('\n')) ? next : '/account';
    providerButtons('login-providers', { returnTo: safe });
    try { const user = await request('/api/me'); notice(`当前已登录：${user.name}，可以在“账户”中管理绑定。`); } catch {}
  }
  function setOptions(id, records, getId, getName) {
    const el = $(id); el.replaceChildren();
    for (const record of records) {
      const option = document.createElement('option');
      option.value = getId(record); option.textContent = getName(record); el.append(option);
    }
  }
  async function refreshAdmin() {
    const [clients, rules, maps] = await Promise.all([
      request('/admin/api/clients', {}, true), request('/admin/api/rules', {}, true), request('/admin/api/mappings', {}, true)
    ]);
    clientList = clients.clients; mappings = maps.mappings;
    $('admin-content').hidden = false;
    $('stat-clients').textContent = clientList.length;
    $('stat-rules').textContent = rules.rules.length;
    $('stat-mappings').textContent = mappings.length;
    setOptions('rule-source', clientList, c => c.id, c => c.name);
    setOptions('rule-target', clientList, c => c.id, c => c.name);
    setOptions('map-client', clientList, c => c.id, c => c.name);
    setOptions('map-provider', meta.providers, p => p.id, p => p.label);
    const list = $('clients'); list.replaceChildren();
    for (const c of clientList) {
      const item = textNode('div', '', 'item');
      const wrapper = document.createElement('div');
      wrapper.append(textNode('div', c.name, 'title'), textNode('span', `${c.auth_method} · ${c.id}`, 'description'));
      item.append(wrapper); list.append(item);
    }
    if (!clientList.length) list.append(textNode('p', '暂时没有客户端。使用已配置的注册令牌调用 /connect/register。', 'muted'));
    const ruleList = $('rules'); ruleList.replaceChildren();
    for (const rule of rules.rules) {
      const item = textNode('div', '', 'item');
      const wrapper = document.createElement('div');
      const name = id => clientList.find(c => c.id === id)?.name || id;
      wrapper.append(textNode('div', `${name(rule.trigger_client)} → ${name(rule.target_client)}`, 'title'),
        textNode('span', `${rule.action}${rule.duration_seconds ? ` / ${rule.duration_seconds}s` : ''}`, 'description'));
      const remove=textNode('button','删除','small outline');
      remove.onclick=async()=>{if(!confirm('删除此联动规则？'))return;try{await request(`/admin/api/rules/${encodeURIComponent(rule.id)}`,{method:'DELETE'},true);await refreshAdmin();notice('规则已删除');}catch(err){notice(err.message);}};
      item.append(wrapper,remove);ruleList.append(item);
    }
    if (!rules.rules.length) ruleList.append(textNode('p', '尚未设置应用联动规则。', 'muted'));
    selectMapping();
  }
  function readMapping() {
    const rules = JSON.parse($('map-rules').value);
    if (!Array.isArray(rules)) throw new Error('映射规则必须是 JSON 数组');
    return { provider: $('map-provider').value, client_id: $('map-client').value, rules, script: $('map-script').value };
  }
  function renderFlow(rules) {
    const left = $('flow-input'), right = $('flow-output'), arrows = $('flow-arrows');
    left.replaceChildren();right.replaceChildren();arrows.replaceChildren();
    for (const rule of rules) {
      left.append(textNode('span', rule.from, 'flow-pill'));
      right.append(textNode('span', rule.to, 'flow-pill'));
      arrows.append(textNode('span', '→'));
    }
    if (!rules.length) {
      left.append(textNode('span', '原字段', 'flow-pill'));
      right.append(textNode('span', '原字段', 'flow-pill'));
      arrows.append(textNode('span', '→'));
    }
  }
  function selectMapping() {
    const mapping = mappings.find(m => m.provider === $('map-provider').value && m.client_id === $('map-client').value);
    if (mapping) { $('map-rules').value = JSON.stringify(mapping.rules, null, 2); $('map-script').value = mapping.script; }
    try { renderFlow(readMapping().rules); } catch {}
  }
  async function adminActions() {
    $('page-title').textContent = '集中管理，不牺牲自主权。';
    $('page-subtitle').textContent = '每个身份，每次授权，每条应用策略都可控制。';
    $('admin-connect').addEventListener('click', async () => {
      adminToken = $('admin-key').value;
      try { await refreshAdmin(); $('admin-key').value = ''; notice('管理连接已建立'); }
      catch (err) { adminToken = ''; $('admin-content').hidden = true; notice(err.message); }
    });
    $('add-rule').addEventListener('click', async () => {
      const time = $('rule-duration').value.trim();
      const input = { trigger_client: $('rule-source').value, target_client: $('rule-target').value, action: $('rule-action').value, duration_seconds: time ? Number(time) : null };
      try { await request('/admin/api/rules', { method: 'POST', body: JSON.stringify(input) }, true); await refreshAdmin(); notice('规则保存成功'); }
      catch (err) { notice(err.message); }
    });
    $('map-provider').addEventListener('change', selectMapping);
    $('map-client').addEventListener('change', selectMapping);
    $('map-rules').addEventListener('input', () => { try { renderFlow(readMapping().rules); } catch {} });
    $('preview-map').addEventListener('click', async () => {
      try {
        const mapping = readMapping();
        const result = await request('/admin/api/mappings/preview', { method: 'POST', body: JSON.stringify({ source: JSON.parse($('map-input').value), rules: mapping.rules, script: mapping.script }) }, true);
        $('map-result').textContent = JSON.stringify(result.output, null, 2);
        notice('预览完成');
      } catch (err) { notice(err.message); }
    });
    $('save-map').addEventListener('click', async () => {
      try { await request('/admin/api/mappings', { method: 'POST', body: JSON.stringify(readMapping()) }, true); await refreshAdmin(); notice('字段映射已保存'); }
      catch (err) { notice(err.message); }
    });
    $('upload-background').addEventListener('click', async () => {
      const file = $('background-file').files?.[0];
      if (!file) { notice('请选择图片'); return; }
      if (file.size > 5 * 1024 * 1024) { notice('图片超过 5 MiB'); return; }
      const body = new FormData(); body.append('file', file);
      try { await request('/admin/api/branding', { method: 'POST', body }, true);
        await applyImageSeed(URL.createObjectURL(file));
        $('wallpaper').style.backgroundImage = `url('/branding/background?v=${Date.now()}')`;
        notice('背景上传成功，已从背景提取主题色。');
      } catch (err) { notice(err.message); }
    });
  }
  // A small color-frequency sample is used until the optional Material Color Utilities
  // build output is present. The bundled HCT implementation takes precedence.
  async function applyImageSeed(src) {
    const img = new Image();img.src = src;
    await img.decode();
    const canvas = document.createElement('canvas'); canvas.width = 64;canvas.height = 64;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return;
    ctx.drawImage(img, 0, 0, 64, 64);
    const values = ctx.getImageData(0,0,64,64).data;
    const buckets = new Map();
    for (let i=0; i<values.length; i+=4) {
      const [r,g,b,a] = [values[i],values[i+1],values[i+2],values[i+3]];
      if (a < 200 || (r+g+b)/3 < 45 || (r+g+b)/3 > 245) continue;
      const max = Math.max(r,g,b), min=Math.min(r,g,b);
      const saturation = max === 0 ? 0 : (max-min)/max;
      if (saturation < .12) continue;
      const key = [r>>4,g>>4,b>>4].join('-');
      const previous = buckets.get(key) || { count:0,r:0,g:0,b:0 };
      previous.count += 1; previous.score = (previous.score || 0) + 1 + saturation*2; previous.r += r; previous.g += g; previous.b += b;
      buckets.set(key,previous);
    }
    const best = [...buckets.values()].sort((a,b)=>b.score-a.score)[0];
    const seed = best ? [best.r/best.count,best.g/best.count,best.b/best.count].map(v=>Math.max(0,Math.min(255,Math.round(v)))) : [103,80,164];
    // Colors above are weighted; stabilize from the average quantized bucket.
    const rgb = best ? [best.r,best.g,best.b].map(v=>Math.round(Math.min(255,v/best.count))) : seed;
    await applySeed(rgb);
  }
  async function applySeed(rgb) {
    let hex = '#'+rgb.map(v=>v.toString(16).padStart(2,'0')).join('');
    try {
      const module = await import('/assets/monet.bundle.js');
      if (module.applyMonetTheme) { module.applyMonetTheme(hex); palette(hex);return; }
    } catch { /* The optional HCT bundle has not been built yet. */ }
    const [r,g,b] = rgb.map(v=>v/255), max=Math.max(r,g,b), min=Math.min(r,g,b);
    let hue = 260;const delta=max-min;
    if (delta>0) { hue=(max===r?(g-b)/delta+(g<b?6:0):max===g?(b-r)/delta+2:(r-g)/delta+4)*60; }
    const root = document.documentElement;
    root.style.setProperty('--primary',`hsl(${hue} 45% 40%)`);
    root.style.setProperty('--primary-container',`hsl(${hue} 75% 92%)`);
    root.style.setProperty('--on-primary-container',`hsl(${hue} 60% 20%)`);
    root.style.setProperty('--secondary-container',`hsl(${(hue+16)%360} 38% 90%)`);
    palette(hex);
  }
  function palette(seed) {
    const swatches=$('seed-swatches');if (!swatches) return;
    swatches.replaceChildren();
    for (const color of [seed,'var(--primary)','var(--primary-container)','var(--secondary-container)','var(--surface-container)']) {
      const item=document.createElement('span');item.style.backgroundColor=color;item.title=color;swatches.append(item);
    }
  }
  async function encryptedExport() {
    try {
      const passphrase = prompt('设置加密文件口令（至少 12 位）。口令不会发送到服务端。');
      if (!passphrase || passphrase.length < 12) { notice('需要至少 12 位口令'); return; }
      const [profile,linked] = await Promise.all([request('/api/me'),request('/api/me/identities')]);
      const wasm = await import('/assets/crypto/crypto_wasm.js');
      await wasm.default();
      const encrypted = wasm.encrypt(JSON.stringify({ profile, identities: linked.identities }), passphrase);
      const blob = new Blob([encrypted],{type:'application/json'});
      const link = document.createElement('a');link.href=URL.createObjectURL(blob);link.download='sso-account-encrypted.json';link.click();
      URL.revokeObjectURL(link.href);notice('WASM AES-256-GCM 加密导出完成。');
    } catch (err) { notice(`WASM 加密组件未准备好或加密失败：${err.message}。请先运行 wasm-pack build。`); }
  }
  async function initialize() {
    $('login-page').hidden=!onLogin;$('account-page').hidden=!onAccount;$('admin-page').hidden=!onAdmin;
    try { meta = await request('/api/meta'); } catch (err) { notice(`读取服务配置失败：${err.message}`); }
    if (onAdmin) await adminActions();
    else if (onAccount) await renderAccount();
    else await renderLogin();
    $('logout').addEventListener('click', async ()=>{
      try { await request('/api/me/logout',{method:'POST'});location.href='/login'; } catch (err) { notice(err.message); }
    });
    $('export-encrypted').addEventListener('click',encryptedExport);
    const img=new Image();img.src='/branding/background';
    img.onload=()=>{ $('wallpaper').style.backgroundImage="url('/branding/background')"; applyImageSeed(img.src).catch(()=>{}); };
  }
  initialize().catch(err=>notice(err.message));
})();
