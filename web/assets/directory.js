'use strict';
// Keycloak-style admin directory. Admin bearer token stays in page memory.
(() => {
  const id = key => document.getElementById(key);
  let offset = 0;
  const date = ts => ts ? new Date(ts * 1000).toLocaleString() : '未知';
  function node(tag, text, className) {
    const e = document.createElement(tag);
    if (text !== undefined) e.textContent = String(text);
    if (className) e.className = className;
    return e;
  }
  async function load() {
    const term = id('directory-query').value.trim();
    if (term.length > 100) throw Error('搜索条件过长');
    const payload = await api('/admin/users?' + new URLSearchParams({
      q: term, limit: '30', offset: String(offset)
    }), {}, auth());
    const list = id('directory-results');
    list.replaceChildren();
    if (!payload.users.length) list.append(node('p', '没有匹配用户', 'small'));
    for (const user of payload.users) {
      const card = node('div', undefined, 'item');
      const head = node('div', undefined, 'row');
      head.append(node('b', user.name), node('span', user.enabled ? '已启用' : '已禁用', 'pill'));
      card.append(head);
      card.append(node('p', (user.email || '无邮箱') + ' · ' + user.id, 'small'));
      card.append(node('p', user.identities + ' 个登录身份 · ' + user.sessions
        + ' 个登录会话 · 创建于 ' + date(user.created), 'small'));
      const actions = node('div', undefined, 'actions');
      const detail = node('button', '查看身份 / 会话', 'tonal');
      detail.onclick = () => showDetails(user.id).catch(e => toast(e.message));
      const status = node('button', user.enabled ? '禁用账户并吊销全部授权' : '恢复账户',
        user.enabled ? 'danger' : 'outline');
      status.onclick = async () => {
        const warning = user.enabled
          ? '禁用 ' + user.name + '？将退出所有设备、吊销所有 OAuth 访问及刷新令牌。重新启用也无法恢复旧令牌。'
          : '恢复 ' + user.name + '？需要重新登录才能获得新授权。';
        if (!confirm(warning)) return;
        try {
          const action = user.enabled ? 'disable' : 'enable';
          const result = await api('/admin/users/' + encodeURIComponent(user.id) + '/' + action,
            { method: 'POST' }, auth());
          toast(user.enabled
            ? '已禁用：撤销 ' + result.revoked_sessions + ' 个会话及 ' + result.revoked_access + ' 个访问令牌'
            : '账户已恢复；旧授权仍不可用');
          await load();
          id('directory-detail').replaceChildren();
        } catch (e) { toast(e.message); }
      };
      actions.append(detail, status);
      card.append(actions);
      list.append(card);
    }
    id('directory-page').textContent = String(offset + 1) + '–' + String(offset + payload.users.length);
    id('directory-prev').disabled = offset === 0;
    id('directory-next').disabled = !payload.has_more;
  }
  async function showDetails(userId) {
    const [user, sessions] = await Promise.all([
      api('/admin/users/' + encodeURIComponent(userId), {}, auth()),
      api('/admin/users/' + encodeURIComponent(userId) + '/sessions', {}, auth())
    ]);
    const parent = id('directory-detail');
    parent.replaceChildren();
    parent.append(node('h3', user.name + (user.enabled ? ' · 已启用' : ' · 已禁用')));
    parent.append(node('p', user.id + ' · ' + (user.email || '未提供邮箱'), 'small'));
    parent.append(node('p', '关联身份', 'small'));
    if (!user.identities.length) parent.append(node('p', '未关联身份', 'small'));
    for (const identity of user.identities) {
      parent.append(node('div', identity.provider + ' · ' + identity.subject, 'item'));
    }
    parent.append(node('h3', '活跃浏览器会话（' + sessions.length + '）'));
    for (const session of sessions) {
      parent.append(node('div', (session.method || '未知方式') + ' · ' +
        (session.user_agent || '未知浏览器') + ' · 到期 ' + date(session.expires), 'item'));
    }
    if (sessions.length) {
      const revoke = node('button', '强制注销该用户的全部浏览器会话', 'danger');
      revoke.onclick = async () => {
        if (!confirm('强制注销所有浏览器会话？已授权应用的 OAuth Token 不受此操作影响。')) return;
        try {
          const result = await api('/admin/users/' + encodeURIComponent(userId) + '/sessions/revoke',
            { method: 'POST' }, auth());
          toast('已注销 ' + result.revoked_sessions + ' 个浏览器会话');
          await showDetails(userId);
          await load();
        } catch (e) { toast(e.message); }
      };
      parent.append(revoke);
    }
  }
  id('directory-search').onclick = () => { offset = 0; load().catch(e => toast(e.message)); };
  id('directory-query').onkeydown = e => {
    if (e.key === 'Enter') { e.preventDefault(); offset = 0; load().catch(err => toast(err.message)); }
  };
  id('directory-prev').onclick = () => { offset = Math.max(0, offset - 30); load().catch(e => toast(e.message)); };
  id('directory-next').onclick = () => { offset += 30; load().catch(e => toast(e.message)); };
})();