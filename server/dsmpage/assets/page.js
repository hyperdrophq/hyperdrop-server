// HyperDrop's page in DSM. Every API call carries DSM's session token as
// X-SYNO-TOKEN, which is how the CGI learns the DSM user behind the request
// (and why another site cannot call it). The token comes from DSM's own
// login.cgi with the session cookie.
'use strict';

const BASE = '/webman/3rdparty/hyperdrop/index.cgi';
const SIGN_IN = 'Sign in to DSM again.';

let token = '';

async function fetchToken() {
  const res = await fetch('/webman/login.cgi', { credentials: 'same-origin', cache: 'no-store' });
  let body = {};
  try { body = await res.json(); } catch (_) { /* not JSON: no session */ }
  token = typeof body.SynoToken === 'string' ? body.SynoToken : '';
  return token;
}

class APIError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// api(method, path, body) calls BASE + path and answers the decoded JSON,
// or throws an APIError carrying the server's one-sentence error. A 401
// fetches a fresh token and tries once more.
async function api(method, path, body) {
  for (let attempt = 0; attempt < 2; attempt++) {
    if (!token || attempt > 0) {
      await fetchToken().catch(() => { token = ''; });
      if (!token) throw new APIError(401, SIGN_IN);
    }
    const init = { method, credentials: 'same-origin', cache: 'no-store', headers: { 'X-SYNO-TOKEN': token } };
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const res = await fetch(BASE + path, init);
    let data = null;
    try { data = await res.json(); } catch (_) { /* no JSON body */ }
    if (res.status === 401 && attempt === 0) continue;
    if (res.status === 401) throw new APIError(401, SIGN_IN);
    if (!res.ok) {
      const msg = data && typeof data.error === 'string' ? data.error : 'HyperDrop could not answer (' + res.status + ').';
      throw new APIError(res.status, msg);
    }
    return data;
  }
  throw new APIError(401, SIGN_IN);
}

function showError(message) {
  const banner = document.getElementById('banner');
  banner.textContent = message;
  banner.hidden = !message;
}

function selectTab(name) {
  for (const tab of document.querySelectorAll('[role="tab"]')) {
    const on = tab.dataset.panel === name;
    tab.setAttribute('aria-selected', on ? 'true' : 'false');
    tab.tabIndex = on ? 0 : -1;
    document.getElementById('panel-' + tab.dataset.panel).hidden = !on;
  }
}

function setUpTabs() {
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  for (const tab of tabs) {
    tab.addEventListener('click', () => selectTab(tab.dataset.panel));
    tab.addEventListener('keydown', (e) => {
      const step = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[e.key];
      if (!step) return;
      e.preventDefault();
      const next = tabs[(tabs.indexOf(tab) + step + tabs.length) % tabs.length];
      selectTab(next.dataset.panel);
      next.focus();
    });
  }
}

// el(tag, className, text) builds an element; text goes in as textContent.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function row(...children) {
  const r = el('div', 'row');
  r.append(...children);
  return r;
}

function field(label, value, small) {
  const input = el('input', small ? 'in sm' : 'in');
  input.value = value;
  const id = 'f-' + label.toLowerCase().replace(/[^a-z]+/g, '-');
  input.id = id;
  const k = el('label', 'k', label);
  k.htmlFor = id;
  return { input, row: row(k, input) };
}

// link(text, href) opens only an https address.
function link(text, href) {
  const a = el('a', '', text);
  if (/^https:\/\//.test(href)) a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  return a;
}

function messageNode(m, proxyInput) {
  const red = m.code !== 'not-reachable' && m.code !== 'address-pending' && m.code !== 'files-missing';
  const box = el('div', 'msg ' + (red ? 'red' : 'amber'));
  box.append(el('span', 'dot ' + (red ? 'bad' : 'warn')), ' ', m.text, ' ');
  if (m.action && m.action.fill !== undefined && m.action.fill !== '') {
    const b = el('button', 'btn', m.action.label);
    b.type = 'button';
    b.addEventListener('click', () => { proxyInput.value = m.action.fill; proxyInput.focus(); });
    box.append(b, ' ');
  } else if (m.action && m.action.url) {
    box.append(link(m.action.label, m.action.url), ' ');
  }
  if (m.link) box.append(link('Help', m.link));
  return box;
}

const FINISH_MOVE = 'Finish the move first: start HyperDrop on the Storage tab.';
const HELP = 'https://gethyperdrop.com/docs/synology/#';
const POLL_MS = 3000;
let pollTimer = 0;

// changeNode shows the last Save: applying, saved, undone or failed.
function changeNode(c) {
  const tone = { applying: 'amber', done: 'green' }[c.state] || 'red';
  const dot = { applying: 'warn', done: 'ok' }[c.state] || 'bad';
  const box = el('div', 'msg ' + tone);
  box.setAttribute('role', 'status');
  box.append(el('span', 'dot ' + dot), ' ', c.text);
  return box;
}

function hint(text, anchor) {
  const h = el('div', 'hint', text + ' ');
  h.append(link('Help', HELP + anchor));
  return h;
}

function addressText(a) {
  return a.kind === 'free' ? a.value + '.hyperdrop.link' : a.value;
}

// addressFields draws the wizard's choice: a free HyperDrop address (the
// name before .hyperdrop.link) or the owner's own domain.
function addressFields(address) {
  const kinds = [['free', 'Free HyperDrop address'], ['domain', 'My own domain']];
  const radios = row();
  radios.classList.add('radio');
  const input = el('input', 'in');
  input.id = 'f-address';
  input.setAttribute('aria-label', 'Address');
  input.autocomplete = 'off';
  input.spellcheck = false;
  const suffix = el('span', 'suffix', '.hyperdrop.link');
  const current = address.kind === 'domain' ? 'domain' : 'free';
  const kept = { free: '', domain: '' };
  kept[current] = address.value || '';
  let kind = current;
  const show = () => {
    input.value = kept[kind];
    input.placeholder = kind === 'free' ? 'alice' : 'share.example.com';
    suffix.hidden = kind !== 'free';
  };
  for (const [value, label] of kinds) {
    const r = el('input');
    r.type = 'radio';
    r.name = 'kind';
    r.value = value;
    r.id = 'f-kind-' + value;
    r.checked = value === current;
    r.addEventListener('change', () => {
      kept[kind] = input.value;
      kind = value;
      show();
    });
    const l = el('label', '', label);
    l.htmlFor = r.id;
    radios.append(r, l);
  }
  show();
  return { radios, row: row(input, suffix), input, kind: () => kind };
}

// port answers the field as a number, or 0 for anything else, which the
// server refuses with the wizard's text.
function port(input) {
  return /^[0-9]{1,5}$/.test(input.value.trim()) ? Number(input.value.trim()) : 0;
}

// renderSettings draws the Settings tab from GET /api/state.
function renderSettings(state) {
  const panel = document.getElementById('panel-settings');
  panel.replaceChildren();
  const applying = !!state.lastChange && state.lastChange.state === 'applying';
  const moving = !!state.lastChange && !!state.lastChange.holdsMove;

  panel.append(el('h4', '', 'Server'));
  const stoppedForMove = !!state.lastChange && state.lastChange.state === 'stopped-for-move';
  const run = row(el('span', 'dot ' + (state.running ? 'ok' : 'bad')),
    el('b', '', state.running ? 'Running' : (stoppedForMove ? 'Stopped for a move' : 'Stopped')));
  if (state.version) run.append(' version ' + state.version);
  panel.append(run);

  const proxy = field('Proxy address', state.proxy);
  proxy.input.placeholder = 'empty: no proxy';
  if (state.lastChange) panel.append(changeNode(state.lastChange));
  for (const m of state.messages) panel.append(messageNode(m, proxy.input));

  // A waiting address change fills the fields, so saving other settings
  // sends it again and keeps it waiting.
  panel.append(el('h4', '', 'Address'));
  const pending = state.pendingAddress;
  const address = addressFields(pending || state.address);
  panel.append(address.radios, address.row);
  if (pending) panel.append(el('div', 'cap', 'Waiting to switch to ' + addressText(pending) + '.'));

  panel.append(el('h4', '', 'Ports on this NAS'));
  const https = field('HTTPS port', state.httpsPort ? String(state.httpsPort) : '', true);
  const http = field('HTTP port', state.httpPort ? String(state.httpPort) : '', true);
  panel.append(https.row, http.row, hint('Your router (or proxy) forwards 443 and 80 to these.', 'ports'));

  panel.append(el('h4', '', 'Proxy in front of HyperDrop'));
  panel.append(proxy.row, hint("Only for a pass-through proxy that sends the PROXY protocol, such as HAProxy or nginx stream. Leave empty otherwise; DSM's Reverse Proxy is not supported.", 'proxy'));

  const save = el('button', 'btn primary', 'Save and restart');
  save.type = 'button';
  const log = el('pre', 'log', state.log || 'The log is empty.');
  log.hidden = true;
  const open = el('button', 'btn', 'Open log');
  open.type = 'button';
  open.addEventListener('click', () => {
    log.hidden = !log.hidden;
    open.textContent = log.hidden ? 'Open log' : 'Hide log';
  });
  const refused = el('div', 'msg red');
  refused.setAttribute('role', 'alert');
  refused.hidden = true;
  const actions = row(save, open);
  actions.classList.add('actions');
  panel.append(actions, refused,
    el('div', 'cap', "If HyperDrop can't start on the new settings, the old ones come back and the reason shows here."), log);

  const inputs = Array.from(panel.querySelectorAll('input'));
  for (const i of inputs) i.disabled = applying || moving;
  save.disabled = applying || moving;
  if (moving) panel.append(el('div', 'msg amber', FINISH_MOVE));

  save.addEventListener('click', async () => {
    refused.hidden = true;
    save.disabled = true;
    try {
      await api('POST', '/api/settings', {
        kind: address.kind(),
        address: address.input.value.trim(),
        httpPort: port(http.input),
        httpsPort: port(https.input),
        proxy: proxy.input.value.trim(),
      });
    } catch (e) {
      refused.textContent = e.message;
      refused.hidden = false;
      save.disabled = false;
      return;
    }
    load();
  });
}

// humanBytes writes a byte count as KB, MB, GB or TB.
function humanBytes(n) {
  const units = ['bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
  return (i === 0 || n >= 100 ? Math.round(n) : n.toFixed(1)) + ' ' + units[i];
}

// storageStopped is true while HyperDrop waits for its folder to be moved:
// stopped for it (or a stop cut short), or a start that failed because DSM
// had not finished.
function storageStopped(c) {
  return !!c && !!c.holdsMove;
}

// DSM counts a package as running until DSM itself stops it, and refuses to
// move a running package's shared folder; only DSM's own start points the
// package at the folder's new place. So a move's stop and start are DSM's
// package control, the calls Package Center makes, sent with the signed-in
// administrator's session. The CGI runs as the package user and cannot.
const DSM_API = '/webapi/entry.cgi';
const PACKAGE = 'hyperdrop';
// DSM's error codes for a session that has expired or a token it no longer
// accepts: the token is fetched again and the call made once more.
const DSM_SESSION_CODES = [106, 107, 119];
// STOP_WAIT_TRIES bounds the wait, after DSM's stop, for the CGI to see no
// server running.
const STOP_WAIT_TRIES = 20;

// dsmPackage asks DSM to stop or start HyperDrop and answers '' once DSM
// has, or a sentence saying why not. No answer, or one that is not JSON,
// leaves it unknown whether DSM acted.
async function dsmPackage(method) {
  const verb = method === 'stop' ? 'stop' : 'start';
  for (let attempt = 0; attempt < 2; attempt++) {
    if (!token || attempt > 0) {
      await fetchToken().catch(() => { token = ''; });
      if (!token) return SIGN_IN;
    }
    const body = new URLSearchParams({
      api: 'SYNO.Core.Package.Control', version: '1', method, id: JSON.stringify(PACKAGE),
    });
    let data = null;
    try {
      const res = await fetch(DSM_API, {
        method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'X-SYNO-TOKEN': token }, body,
      });
      data = await res.json();
    } catch (_) {
      return 'DSM did not answer the ' + verb + '.';
    }
    if (data && data.success === true) return '';
    const code = data && data.error && typeof data.error.code === 'number' ? data.error.code : 0;
    if (DSM_SESSION_CODES.includes(code) && attempt === 0) continue;
    if (DSM_SESSION_CODES.includes(code)) return SIGN_IN;
    // A package script's refusal comes back as DSM's error message, the
    // sentence Package Center shows.
    const said = data && data.error && data.error.errors && typeof data.error.errors.message === 'string'
      ? data.error.errors.message.trim() : '';
    if (said) return 'DSM could not ' + verb + ' HyperDrop: ' + said;
    return 'DSM could not ' + verb + ' HyperDrop' + (code ? ' (error ' + code + ')' : '') + '.';
  }
  return SIGN_IN;
}

// storageRefusal is the sentence the Storage tab shows under its button
// after a stop or start went wrong, kept across the redraw that follows.
let storageRefusal = '';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// stopForMove records the hold with the CGI, has DSM stop HyperDrop and
// waits until no server runs. When DSM does not confirm the stop (a refusal
// or no answer), the CGI is told and decides: it clears the hold while a
// server still runs and keeps it when none does, and the tab is drawn from
// what it decided.
async function stopForMove(button) {
  storageRefusal = '';
  button.disabled = true;
  button.textContent = 'Stopping HyperDrop…';
  try {
    await api('POST', '/api/storage/stop');
  } catch (e) {
    storageRefusal = e.message;
    load();
    return;
  }
  const failure = await dsmPackage('stop');
  if (failure) {
    // A report that does not arrive leaves the hold in place, with the move
    // steps and Start still offered, so its own error is not shown.
    const after = await api('POST', '/api/storage/stop-failed').catch(() => null);
    const held = !!after && after.state === 'stopped-for-move';
    storageRefusal = failure + (held ? ' HyperDrop is not running, so the move can go ahead.' : '');
    load();
    return;
  }
  for (let i = 0; i < STOP_WAIT_TRIES; i++) {
    try {
      if (!(await api('GET', '/api/state')).running) break;
    } catch (_) { break; }
    await sleep(POLL_MS);
  }
  load();
}

// startAfterMove has DSM start HyperDrop, then the CGI wait for it to come
// up as a Save does. A start DSM refused is still waited for: the CGI
// records why HyperDrop is not running, from what the start left behind.
async function startAfterMove(button) {
  storageRefusal = '';
  button.disabled = true;
  button.textContent = 'Starting HyperDrop…';
  const failure = await dsmPackage('start');
  try {
    await api('POST', '/api/storage/start');
    if (failure === SIGN_IN) storageRefusal = failure;
  } catch (e) {
    storageRefusal = failure || e.message;
  }
  load();
}

// renderStorage draws the Storage tab from GET /api/storage: where the data
// folder is and the guided move to another volume.
function renderStorage(storage, lastChange) {
  const panel = document.getElementById('panel-storage');
  panel.replaceChildren();
  const applying = !!lastChange && lastChange.state === 'applying';

  panel.append(el('h4', '', 'Storage'));
  if (!storage.available) {
    panel.append(el('div', 'cap lead', 'HyperDrop keeps its files in its own folder on this NAS.'));
    return;
  }
  if (storage.locked) {
    const box = el('div', 'msg red', storage.text);
    box.setAttribute('role', 'alert');
    panel.append(el('div', 'cap lead', storage.folder), box);
  } else {
    const where = storage.volume ? storage.folder + ' on ' + storage.volume.replace('/volume', 'Volume ') : storage.folder;
    const free = typeof storage.freeBytes === 'number' ? ', ' + humanBytes(storage.freeBytes) + ' free' : '';
    panel.append(el('div', '', where + free));
  }
  if (lastChange && (lastChange.job === 'stop-for-move' || lastChange.job === 'start')) panel.append(changeNode(lastChange));

  const refused = el('div', 'msg red', storageRefusal);
  refused.setAttribute('role', 'alert');
  refused.hidden = !storageRefusal;
  if (storageStopped(lastChange)) {
    const steps = el('ol', 'steps');
    for (const text of [
      'In Control Panel, open Shared Folder.',
      'Select ' + storage.folder + ' and click Edit.',
      'Under Location, choose the new volume and click Save. DSM copies the files; this can take a while.',
      'When DSM has finished, come back here and click Start HyperDrop.',
    ]) steps.append(el('li', '', text));
    const start = el('button', 'btn primary', 'Start HyperDrop');
    start.type = 'button';
    start.disabled = applying;
    start.addEventListener('click', () => startAfterMove(start));
    const actions = row(start);
    actions.classList.add('actions');
    panel.append(steps, hint('Moving a shared folder is done in DSM.', 'move-storage'), actions, refused);
    return;
  }
  const stop = el('button', 'btn', 'Stop HyperDrop for a move');
  stop.type = 'button';
  stop.disabled = applying;
  stop.addEventListener('click', () => stopForMove(stop));
  const actions = row(stop);
  actions.classList.add('actions');
  panel.append(actions, refused, hint('To keep your files on another volume, stop HyperDrop first.', 'move-storage'));
}

// rescue holds the Admin rescue tab's administrators (or why they could not
// be listed) and the account last chosen, kept across redraws. admins is
// null until the first listing, which waits while a change applies.
const rescue = { admins: null, error: '', account: '' };

// loadAdmins fills rescue from GET /api/rescue.
async function loadAdmins() {
  try {
    const data = await api('GET', '/api/rescue');
    rescue.admins = Array.isArray(data.admins) ? data.admins : [];
    rescue.error = '';
  } catch (e) {
    rescue.admins = null;
    rescue.error = e.message;
  }
}

// renderRescue draws the Admin rescue tab: an administrator, its new
// password twice and whether to remove its second factor too.
function renderRescue(lastChange) {
  const panel = document.getElementById('panel-rescue');
  panel.replaceChildren();
  const applying = !!lastChange && lastChange.state === 'applying';
  const moving = !!lastChange && !!lastChange.holdsMove;

  panel.append(el('h4', '', 'Get back into HyperDrop'));
  panel.append(el('div', 'cap lead', 'For when no app can sign in as an administrator.'));
  if (lastChange) panel.append(changeNode(lastChange));
  if (rescue.error) {
    const box = el('div', 'msg red', rescue.error);
    box.setAttribute('role', 'alert');
    panel.append(box);
    return;
  }

  if (rescue.admins === null) return;
  if (rescue.admins.length === 0) {
    panel.append(el('div', 'msg amber', 'This HyperDrop has no administrator yet.'));
    return;
  }

  // An administrator who cannot sign in is listed with the reason, since a
  // new password alone does not let it in.
  const account = el('select', 'in');
  account.id = 'f-admin-account';
  for (const a of rescue.admins) {
    const label = a.name + ({ suspended: ' (suspended)', expired: ' (expired)' }[a.standing] || '');
    account.append(new Option(label, a.name, false, a.name === rescue.account));
  }
  account.addEventListener('change', () => { rescue.account = account.value; });
  const accountLabel = el('label', 'k', 'Admin account');
  accountLabel.htmlFor = account.id;
  panel.append(row(accountLabel, account));

  const password = field('New password', '');
  const repeat = field('Repeat', '');
  for (const f of [password, repeat]) {
    f.input.type = 'password';
    f.input.autocomplete = 'new-password';
  }
  panel.append(password.row, repeat.row);

  const clear = el('input');
  clear.type = 'checkbox';
  clear.id = 'f-clear2fa';
  const clearLabel = el('label', '', 'Also remove its second factor');
  clearLabel.htmlFor = clear.id;
  const clearRow = row(el('span', 'k'), clear, clearLabel);
  clearRow.classList.add('check');
  const note = el('div', 'hint');
  const explain = () => {
    note.textContent = 'Signs this account out everywhere.' +
      (clear.checked ? ' The app asks for a new second factor at next sign-in.' : '');
  };
  clear.addEventListener('change', explain);
  explain();
  panel.append(clearRow, note);

  const reset = el('button', 'btn danger', 'Reset this admin');
  reset.type = 'button';
  const actions = row(reset);
  actions.classList.add('actions');
  const refused = el('div', 'msg red');
  refused.setAttribute('role', 'alert');
  refused.hidden = true;
  panel.append(actions, refused);

  for (const i of panel.querySelectorAll('input, select')) i.disabled = applying || moving;
  reset.disabled = applying || moving;
  if (moving) panel.append(el('div', 'msg amber', FINISH_MOVE));

  reset.addEventListener('click', async () => {
    refused.hidden = true;
    if (password.input.value !== repeat.input.value) {
      refused.textContent = 'The two passwords are not the same.';
      refused.hidden = false;
      return;
    }
    reset.disabled = true;
    rescue.account = account.value;
    try {
      await api('POST', '/api/rescue', {
        account: account.value,
        password: password.input.value,
        clear2fa: clear.checked,
      });
    } catch (e) {
      refused.textContent = e.message;
      refused.hidden = false;
      reset.disabled = false;
      return;
    }
    load();
  });
}

// load draws both tabs and, while a change is applying, draws them again
// every POLL_MS until the change ends. The administrators are listed only
// while no change applies, since a rescue rewrites them.
async function load() {
  clearTimeout(pollTimer);
  const loading = document.getElementById('loading');
  let applying = false;
  try {
    const state = await api('GET', '/api/state');
    applying = !!state.lastChange && state.lastChange.state === 'applying';
    if (!applying) await loadAdmins();
    renderSettings(state);
    renderRescue(state.lastChange);
    showError('');
    try {
      renderStorage(await api('GET', '/api/storage'), state.lastChange);
    } catch (e) {
      const panel = document.getElementById('panel-storage');
      panel.replaceChildren(el('h4', '', 'Storage'));
      const box = el('div', 'msg red', e.message);
      box.setAttribute('role', 'alert');
      panel.append(box);
    }
  } catch (e) {
    showError(e.message);
    applying = !!document.querySelector('#panel-settings .msg.amber[role="status"], #panel-storage .msg.amber[role="status"], #panel-rescue .msg.amber[role="status"]');
  } finally {
    loading.hidden = true;
    const current = document.querySelector('[role="tab"][aria-selected="true"]');
    selectTab(current ? current.dataset.panel : 'settings');
  }
  if (applying) pollTimer = setTimeout(load, POLL_MS);
}

document.addEventListener('DOMContentLoaded', () => {
  setUpTabs();
  load();
});
