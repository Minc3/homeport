'use strict';

const GB = 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c.nodeType ? c : document.createTextNode(c));
  }
  return node;
}

function bytes(n) {
  if (!n) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

// endpointHost drops the port from an "address:port" pair. IPv6 literals arrive
// bracketed; the overlay is v4 but a peer could reach this host over v6.
function endpointHost(endpoint) {
  if (!endpoint) return '';
  const v6 = endpoint.lastIndexOf(']:');
  if (v6 >= 0) return endpoint.slice(0, v6).replace(/^\[/, '');
  const i = endpoint.lastIndexOf(':');
  return i >= 0 ? endpoint.slice(0, i) : endpoint;
}

function since(ts) {
  if (!ts) return 'never';
  const secs = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  if (secs < 60) return `${Math.round(secs)}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

function toast(message, isError) {
  document.querySelectorAll('.toast').forEach((t) => t.remove());
  const t = el('div', { class: 'toast' + (isError ? ' error' : ''), text: message });
  document.body.append(t);
  setTimeout(() => t.remove(), 5000);
}

// ---------------------------------------------------------------------------
// Tooltips
//
// One bubble, parented to <body> and positioned in viewport coordinates rather
// than inside the thing it describes. The settings tables scroll horizontally
// (`.table-wrap { overflow-x: auto }`) and a bubble inside one is clipped by it
// - which is exactly where the column headings that most need explaining live.
// ---------------------------------------------------------------------------

const tipBox = el('div', { class: 'tip hidden' });
document.addEventListener('DOMContentLoaded', () => document.body.append(tipBox));

function showTip(target) {
  tipBox.textContent = target.dataset.tip;
  tipBox.classList.remove('hidden');
  const r = target.getBoundingClientRect();
  const box = tipBox.getBoundingClientRect();
  const left = Math.min(Math.max(8, r.left + r.width / 2 - box.width / 2), window.innerWidth - box.width - 8);
  // Above where there is room, below otherwise, so a marker near the top of
  // the page does not put its own explanation off-screen.
  const above = r.top > box.height + 12;
  tipBox.style.left = `${Math.round(left)}px`;
  tipBox.style.top = `${Math.round(above ? r.top - box.height - 8 : r.bottom + 8)}px`;
}

function hideTip() { tipBox.classList.add('hidden'); }

// Delegated, because every marker is built and rebuilt by renderSettings.
document.addEventListener('pointerover', (e) => {
  const t = e.target.closest?.('[data-tip]');
  if (t) showTip(t); else hideTip();
});
// Keyboard and touch reach the same text: the markers are focusable.
document.addEventListener('focusin', (e) => {
  const t = e.target.closest?.('[data-tip]');
  if (t) showTip(t); else hideTip();
});
document.addEventListener('focusout', hideTip);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideTip(); });
window.addEventListener('scroll', hideTip, true);

// help returns the marker itself. The text lives in an attribute rather than in
// `title` so it appears immediately and can be styled; `aria-label` carries the
// same string for a screen reader.
function help(text) {
  return el('span', {
    class: 'help', tabindex: '0', role: 'img', 'aria-label': text, 'data-tip': text,
    // Markers sit inside <label>, and a click on a label activates its control -
    // so without this, reading the help for a checkbox would toggle it.
    onclick: (e) => e.preventDefault(),
  }, '?');
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (res.status === 401) { location.href = '/login.html'; throw new Error('unauthenticated'); }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `request failed (${res.status})`);
  return body;
}

async function act(path, payload, okMessage) {
  try {
    await api(path, { method: 'POST', body: JSON.stringify(payload || {}) });
    if (okMessage) toast(okMessage);
    refreshStatus();
  } catch (e) {
    toast(e.message, true);
  }
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

document.querySelectorAll('nav button').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach((b) => b.classList.toggle('active', b === btn));
    for (const name of ['dashboard', 'settings', 'events']) {
      document.getElementById('tab-' + name).classList.toggle('hidden', name !== btn.dataset.tab);
    }
    // Settings gets the whole window. The paths table is fourteen columns of
    // input, and inside the reading-width column the dashboard wants they are
    // squeezed to the point of being unusable.
    document.querySelector('main').classList.toggle('wide', btn.dataset.tab === 'settings');
    if (btn.dataset.tab === 'events') refreshEvents();
    // Reload for freshness only when nothing is pending: loadSettings replaces
    // `config`, so coming back to the tab must not discard edits. The edited
    // form is still in the DOM and stays as it was left.
    if (btn.dataset.tab === 'settings' && !settingsDirty) loadSettings();
  });
});

document.getElementById('logout').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  location.href = '/login.html';
});

document.getElementById('arm').addEventListener('click', () => {
  if (!confirm('Arm the agent? It will start changing routing and nftables on this host.')) return;
  act('/api/mode', { mode: 'armed' }, 'Armed');
});

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

const history = new Map(); // path id -> [{ts, rtt_ms, loss_pct}]

const healthClass = { up: 'ok', suspect: 'warn', down: 'bad', unknown: '' };

function blockLabel(p) {
  switch (p.block) {
    case 'quota': return ['bad', 'over quota'];
    case 'quarantine': return ['warn', 'quarantined'];
    case 'disabled': return ['', 'disabled'];
    case 'degraded': return ['warn', 'degraded'];
    default: return null;
  }
}

function sparkline(points) {
  const w = 300, h = 42;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', 'spark');
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.setAttribute('preserveAspectRatio', 'none');
  if (!points || points.length < 2) return svg;

  const max = Math.max(20, ...points.map((p) => p.rtt_ms));
  const step = w / (points.length - 1);
  const path = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(1)},${(h - (p.rtt_ms / max) * (h - 4) - 2).toFixed(1)}`)
    .join(' ');

  const line = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  line.setAttribute('d', path);
  line.setAttribute('fill', 'none');
  line.setAttribute('stroke', 'var(--accent)');
  line.setAttribute('stroke-width', '1.5');
  svg.append(line);

  // Loss shows as vertical marks so a lossy-but-fast path cannot look healthy.
  points.forEach((p, i) => {
    if (!p.loss_pct) return;
    const bar = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bar.setAttribute('x', (i * step).toFixed(1));
    bar.setAttribute('y', 0);
    bar.setAttribute('width', Math.max(1, step * 0.8).toFixed(1));
    bar.setAttribute('height', h);
    bar.setAttribute('fill', 'var(--bad)');
    bar.setAttribute('opacity', Math.min(0.5, p.loss_pct / 100).toFixed(2));
    svg.append(bar);
  });
  return svg;
}

function pathCard(p, pinned, shared) {
  const cls = healthClass[p.health] || '';
  // The other paths arriving from this same public address, if any.
  const clash = (shared || []).find((s) => s.paths.includes(p.name));
  const shares = clash ? clash.paths.filter((n) => n !== p.name) : null;
  const block = blockLabel(p);
  const quotaPct = p.limit_bytes > 0 ? Math.min(100, (p.used_bytes / p.limit_bytes) * 100) : 0;
  const quotaCls = quotaPct >= 100 ? 'bad' : quotaPct >= 85 ? 'warn' : '';

  const actions = [
    pinned === p.id
      ? el('button', { class: 'btn', onclick: () => act('/api/pin', { path_id: 0 }, 'Pin cleared') }, 'Unpin')
      : el('button', { class: 'btn', onclick: () => act('/api/pin', { path_id: p.id }, `Pinned to ${p.name}`) }, 'Pin'),
  ];
  if (p.block === 'quarantine') {
    actions.push(el('button', {
      class: 'btn',
      onclick: () => act('/api/quarantine/clear', { path_id: p.id }, 'Quarantine cleared'),
    }, 'Clear quarantine'));
  }
  if (p.grant_until && new Date(p.grant_until).getTime() > Date.now()) {
    actions.push(el('button', {
      class: 'btn danger',
      onclick: () => act('/api/revoke', { path_id: p.id }, 'Approval revoked'),
    }, 'Revoke approval'));
  } else if (p.block === 'quota') {
    actions.push(el('button', {
      class: 'btn primary',
      onclick: () => approve(p),
    }, 'Use anyway…'));
  }

  return el('div', { class: 'card' + (p.active ? ' active' : '') },
    el('div', { class: 'card-head' },
      el('h2', { text: p.name }),
      el('span', { class: 'prio', text: `priority ${p.priority} · ${p.iface}` }),
      el('span', { class: 'spacer' }),
      p.active ? el('span', { class: 'badge ok', text: 'active' }) : null,
      pinned === p.id ? el('span', { class: 'badge warn', text: 'pinned' }) : null,
      el('span', { class: 'badge ' + cls, text: p.health }),
      block ? el('span', { class: 'badge ' + block[0], text: block[1] }) : null,
    ),
    el('div', { class: 'metrics' },
      el('div', { class: 'metric' }, el('div', { class: 'k', text: 'rtt' }), el('div', { class: 'v', text: p.rtt_ms ? p.rtt_ms.toFixed(1) + ' ms' : '-' })),
      el('div', { class: 'metric' }, el('div', { class: 'k', text: 'loss' }), el('div', { class: 'v', text: p.loss_pct.toFixed(1) + '%' })),
      el('div', { class: 'metric' }, el('div', { class: 'k', text: 'jitter' }), el('div', { class: 'v', text: p.jitter_ms.toFixed(1) + ' ms' })),
    ),
    sparkline(history.get(p.id)),
    p.limit_bytes > 0
      ? el('div', {},
          el('div', { class: 'bar' }, el('div', { class: quotaCls, style: `width:${quotaPct}%` })),
          el('div', { class: 'quota-line' },
            el('span', { text: `${bytes(p.used_bytes)} of ${bytes(p.limit_bytes)}` }),
            el('span', { text: p.period_end ? 'resets ' + new Date(p.period_end).toLocaleDateString() : '' }),
          ))
      : null,
    el('p', { class: 'hint', text: `last reply ${since(p.last_reply)} · handshake ${p.handshake_age_sec ? Math.round(p.handshake_age_sec) + 's ago' : 'unknown'}` }),
    // The public address this tunnel's traffic is actually arriving from. The
    // frontend configures no endpoint - the backend dials out from behind
    // CGNAT - so this is observed, not declared, which is what makes it worth
    // showing: it is the WAN that tunnel really rode.
    el('p', {
      class: 'hint' + (shares ? ' bad-text' : '') + (p.peer_endpoint ? ' copy' : ''),
      // The port is the carrier's NAT source port. It carries no information
      // about which service this is - two tunnels on one WAN get different
      // ports, which is why the comparison ignores it - so it stays out of the
      // line and into the hover, where somebody chasing a NAT rebind can find it.
      title: p.peer_endpoint ? `${p.peer_endpoint}. Click to copy the address` : '',
      text: p.peer_endpoint
        ? (shares
          ? `WAN ${endpointHost(p.peer_endpoint)}, same as ${shares.join(' and ')}`
          : `WAN ${endpointHost(p.peer_endpoint)}`)
        : 'WAN unknown: no handshake on this tunnel yet',
      // The address alone, as on the WAN badge: the port is the carrier's and
      // changes under the tunnel, so it is never what anybody wants pasted.
      ...(p.peer_endpoint ? { onclick: () => copyText(endpointHost(p.peer_endpoint)) } : {}),
    }),
    el('div', { class: 'row' }, actions),
  );
}

function approve(p) {
  const hoursInput = prompt(
    `Use ${p.name} past its quota for how many hours?\n\n` +
    'The approval expires on its own so quota enforcement comes back automatically.', '24');
  if (hoursInput === null) return;
  const hours = parseFloat(hoursInput);
  if (!(hours > 0)) { toast('Approval cancelled: hours must be a positive number', true); return; }

  const gbInput = prompt(
    `Cap the overage at how many GB? (0 for no byte limit)\n\n` +
    'This is a hard stop in addition to the time limit.', '5');
  // Cancelling here must abort, not fall through. Treating a dismissed prompt
  // as 0 would send "no byte limit", an unbounded grant, which is the exact
  // opposite of what someone backing out of the dialog intends.
  if (gbInput === null) return;
  const gb = parseFloat(gbInput);
  if (isNaN(gb) || gb < 0) { toast('Approval cancelled: enter a number of GB, or 0 for no limit', true); return; }

  act('/api/approve', { path_id: p.id, hours, extra_gb: gb },
    `${p.name} approved for ${hours}h`);
}

let lastStatus = null;

async function refreshStatus() {
  let data;
  try {
    data = await api('/api/status');
  } catch (e) {
    document.getElementById('backend-badge').className = 'badge bad';
    document.getElementById('backend-badge').textContent = 'portal offline';
    return;
  }
  lastStatus = data;
  const st = data.status;

  const mode = document.getElementById('mode-badge');
  mode.textContent = st.mode === 'armed' ? 'armed' : 'observe only';
  mode.className = 'badge ' + (st.mode === 'armed' ? 'ok' : 'warn');
  document.getElementById('observe').classList.toggle('hidden', st.mode === 'armed' || st.reverted);

  // After a revert the trackers are frozen, so every path card below shows its
  // last pre-revert health - typically three green tunnels - while nothing is
  // measured at all. This banner is the page saying so; without it the frozen
  // cards read as a live, healthy system.
  document.getElementById('reverted').classList.toggle('hidden', !st.reverted);

  // Disarming stops further changes but leaves whatever was already installed
  // in place, because deleting the DNAT rules would drop every published
  // service on the spot. Say so, rather than letting "observe only" imply the
  // host is untouched.
  const stale = document.getElementById('stale-rules');
  stale.classList.toggle('hidden', !(st.mode !== 'armed' && st.rules_active));

  // Two tunnels arriving from one public address. Nothing else on this page can
  // show it: each of those paths measures perfectly, because each tunnel really
  // is up - there is simply one link under both of them.
  const shared = st.shared_endpoints || [];
  document.getElementById('endpoint-clash').classList.toggle('hidden', shared.length === 0);
  if (shared.length) {
    document.getElementById('endpoint-clash-detail').textContent = shared
      .map((s) => `${s.paths.join(' and ')} are both on the WAN at ${s.address}`)
      .join('; ') + '.';
  }

  // Green only while traffic is on the preferred path. Any fallback is left
  // plain: the system is working as designed, but it is not where it wants to
  // be, and that distinction should be readable without opening a card. The
  // engine reports which path is preferred so this does not have to guess.
  const active = document.getElementById('active-badge');
  active.textContent = st.active_name ? 'via ' + st.active_name : 'no path';
  const onPreferred = st.active_path !== 0 && st.active_path === st.preferred_path;
  active.className = 'badge ' + (!st.active_name ? 'bad' : onPreferred ? 'ok' : '');
  active.title = !st.active_name ? ''
    : onPreferred ? 'on the preferred path'
    : 'on a fallback path';

  // There was no way to tell what a host was running without shell access, and
  // a wrong assumption about the deployed build misleads every check that
  // follows. The backend's is the last one it reported, so it can outlive the
  // connection - the backend badge beside it is what says whether it is live.
  const versions = document.getElementById('versions');
  const beVer = st.backend_version || 'unknown';
  versions.textContent = `frontend ${st.frontend_version || 'unknown'} · backend ${beVer}`;
  versions.title = (st.backend_host ? `backend host: ${st.backend_host}. ` : '') + 'Click to copy';
  versions.classList.add('copy');
  versions.onclick = () => copyText(versions.textContent);

  const backend = document.getElementById('backend-badge');
  backend.textContent = st.backend_up ? 'backend connected' : 'backend unreachable';
  backend.className = 'badge ' + (st.backend_up ? 'ok' : 'bad');

  // The WAN address published services are reachable at: the configured
  // public IP, or the address read from the public interface when none is
  // configured. Hidden entirely when the engine cannot report one, which is
  // an unconfigured public interface rather than a fault.
  const wan = document.getElementById('wan-badge');
  wan.classList.toggle('hidden', !st.public_address);
  if (st.public_address) {
    wan.textContent = `WAN ${st.public_address}`;
    wan.title = 'The public address published services are reachable at. Configured in Settings, or read from the public interface when no public IP is set. Click to copy the address.';
    wan.classList.add('copy');
    // The address alone, not the "WAN" label: what gets pasted is a server
    // browser entry or a config line, and neither wants the word.
    wan.onclick = () => copyText(st.public_address);
  }

  const held = document.getElementById('held');
  held.classList.toggle('hidden', !st.held);
  if (st.held) {
    document.getElementById('held-reason').textContent = st.held_reason;
    const actions = document.getElementById('held-actions');
    actions.textContent = '';
    for (const p of st.paths) {
      // Match the engine's notion of a usable path: suspect counts, so a path
      // named in the held reason always gets an approve button rather than
      // being mentioned with no way to act on it.
      if (p.block === 'quota' && (p.health === 'up' || p.health === 'suspect')) {
        actions.append(el('button', { class: 'btn primary', onclick: () => approve(p) },
          `Use ${p.name} anyway…`));
      }
    }
  }

  const cards = document.getElementById('cards');
  cards.textContent = '';
  for (const p of st.paths) cards.append(pathCard(p, data.pinned, shared));

  // Deliberately below the paths and visually apart from them. An extra host
  // being down is not a path problem: it must never look like one, or the
  // reflex is to go hunting for a failing tunnel.
  const states = st.linker_states || [];
  document.getElementById('linkers-section').classList.toggle('hidden', states.length === 0);
  const linkers = document.getElementById('linkers');
  linkers.textContent = '';
  for (const l of states) linkers.append(linkerCard(l));

  renderProtect(st.protect);
}

// The counters are the whole reason any of this is reported. A limit that is
// dropping traffic and a service that is broken look identical from outside, so
// without these numbers a tuning mistake becomes an unexplained outage.
function renderProtect(p) {
  const section = document.getElementById('protect-section');
  section.classList.toggle('hidden', !p);
  if (!p) return;

  const counters = p.counters || [];
  const blocked = p.blocked || [];
  const body = document.getElementById('protect-body');
  body.textContent = '';

  if (!counters.length) {
    body.append(el('p', { class: 'hint', text: 'Rules are loaded and nothing has been dropped yet.' }));
  } else {
    // geo-trip counts packets over an auto-lock threshold, which are not
    // themselves dropped (the drop is the geo counter beside it), so it is
    // shown but kept out of a total labelled "dropped".
    const total = counters.reduce((n, c) => n + (c.name.startsWith('geo-trip') ? 0 : c.packets), 0);
    body.append(el('div', { class: 'metrics' }, ...counters.map((c) => el('div', { class: 'metric' },
      el('div', { class: 'k', text: c.name }),
      el('div', { class: 'v', text: c.packets.toLocaleString() }),
      el('div', { class: 'hint', text: bytes(c.bytes) })))));
    body.append(el('p', { class: 'hint', text: total === 0
      ? 'Nothing dropped since the rules were last loaded.'
      : `${total.toLocaleString()} packets dropped since the rules were last loaded. Saving the configuration resets these.` }));
  }

  // Said loudly, because an engaged lock looks exactly like the service being
  // down to everybody outside the region - this line is the only thing that
  // separates "under attack, held" from "broken".
  const locked = p.geo_locked || [];
  for (const l of locked) {
    body.append(el('div', { class: 'alert info' },
      el('p', { text: `Region lock engaged on ${l.proto}/${l.port}: traffic to it exceeded the auto-lock threshold, and the sources its lock bars are being dropped. `
        + (l.expires_sec ? `Releases in ${l.expires_sec}s unless the flood is still refreshing it.` : 'Releasing shortly.') }),
    ));
  }

  if (blocked.length) {
    body.append(el('p', { class: 'hint', text: `${blocked.length} source${blocked.length === 1 ? '' : 's'} currently parked. They expire on their own; nothing needs to be cleared by hand.` }));
    body.append(el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {}, el('th', { text: 'Address' }), el('th', { text: 'Expires in' }))),
      el('tbody', {}, blocked.slice(0, 20).map((b) => el('tr', {},
        el('td', { text: b.address }),
        el('td', { text: b.expires_sec ? `${b.expires_sec}s` : 'soon' })))))));
  }
}

function linkerCard(l) {
  return el('div', { class: 'card' },
    el('div', { class: 'card-head' },
      el('h2', { text: l.name || l.overlay_ip }),
      el('span', { class: 'prio', text: `${l.overlay_ip} · via ${l.lan_ip}` }),
      el('span', { class: 'spacer' }),
      el('span', { class: 'badge ' + (l.up ? 'ok' : 'bad'), text: l.up ? 'up' : 'not connected' }),
    ),
    el('div', { class: 'metrics' },
      el('div', { class: 'metric' },
        el('div', { class: 'k', text: 'host' }),
        el('div', { class: 'v', text: l.hostname || '-' })),
      el('div', { class: 'metric' },
        el('div', { class: 'k', text: 'build' }),
        el('div', { class: 'v', text: l.version || '-' })),
      // Two different questions, and only one of them is worth asking at a
      // time. While the host is connected, how long it has been is the useful
      // fact; once it is not, all that matters is how long it has been quiet -
      // and 'since' meant only the first, so a host that had been down for a
      // week said nothing at all.
      el('div', { class: 'metric' },
        el('div', { class: 'k', text: l.up ? 'connected' : 'last contact' }),
        el('div', { class: 'v', text: since(l.up ? l.since : l.last_seen) })),
    ),
    l.up ? null : el('p', { class: 'hint', text: 'Configured here but not connected. Published traffic still routes to it (the backend’s route does not depend on this), but nothing on that host has checked in.' }),
    l.up && l.table && l.table !== (l.configured_table || 200)
      ? el('p', { class: 'hint', text: `This host is using routing table ${l.table}, but the portal has ${l.configured_table || 200}. The host wins: it reads the value from its own linker.json before this channel exists. Update one of them so they agree.` })
      : null,
  );
}

async function refreshHistory() {
  if (!lastStatus) return;
  for (const p of lastStatus.status.paths) {
    try {
      history.set(p.id, await api(`/api/history?path_id=${p.id}&hours=6`));
    } catch { /* a missing chart is not worth an error toast */ }
  }
}

// ---------------------------------------------------------------------------
// Activity log
// ---------------------------------------------------------------------------

async function refreshEvents() {
  try {
    const events = await api('/api/events?limit=200');
    const body = document.getElementById('events-body');
    body.textContent = '';
    for (const e of events || []) {
      body.append(el('tr', {},
        el('td', { text: new Date(e.ts * 1000).toLocaleString() }),
        el('td', {}, el('span', { class: 'log-kind', text: e.kind.replace('_', ' ') })),
        el('td', { text: e.message }),
      ));
    }
  } catch (e) {
    toast(e.message, true);
  }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

let config = null;
// The shipped detection tunings, from /api/presets. Only the settings page
// reads them, and an empty list just leaves the dropdown showing Custom.
let presets = [];

// ---------------------------------------------------------------------------
// Unsaved-changes tracking
//
// Nothing on this page is staged: an edit lives only in `config` until Save
// sends it, and it was easy to type into a field and navigate away believing
// it had taken. Dirtiness is the config differing from the last loaded or
// saved copy, rather than a flag set by each input, so the Add and Remove
// buttons, which mutate the object directly, are caught the same way a
// keystroke is, and typing a password below, which touches no config, never
// counts. The snapshot is taken after renderSettings has run, because
// rendering fills in structures an older stored config lacks and that repair
// is not an edit.
// ---------------------------------------------------------------------------

let savedConfig = null;
let settingsDirty = false;

// zeroish groups the values Go's omitempty treats as absent. A key the loaded
// JSON never carried and one an input has set back to its default are the same
// configuration on the wire, so they must compare equal here: ticking and
// unticking Source engine writes `false` under a key the fetch omitted, and a
// plain string comparison would then read dirty forever, with no way to clear
// the badge short of saving a change that changes nothing.
function zeroish(v) {
  return v === undefined || v === null || v === false || v === 0 || v === ''
    || (typeof v === 'number' && Number.isNaN(v))
    || (Array.isArray(v) && v.length === 0);
}

function sameConfig(a, b) {
  if (zeroish(a) && zeroish(b)) return true;
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((v, i) => sameConfig(v, b[i]));
  }
  if (typeof a === 'object' && a !== null && typeof b === 'object' && b !== null) {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
      if (!sameConfig(a[k], b[k])) return false;
    }
    return true;
  }
  return a === b;
}

function updateDirty() {
  settingsDirty = config !== null && savedConfig !== null && !sameConfig(config, savedConfig);
  document.getElementById('unsaved-badge')?.classList.toggle('hidden', !settingsDirty);
  document.querySelector('nav button[data-tab="settings"]').classList.toggle('dirty', settingsDirty);
}

function markSaved() {
  savedConfig = JSON.parse(JSON.stringify(config));
  updateDirty();
}

// Delegated, because renderSettings rebuilds everything inside the form.
// updateGeoWarn says out loud that a region lock on a service row does not
// exist while Protection is disabled. Nothing refuses that state on purpose:
// unticking Protection has to stay the one-click way to back every filter out,
// locks included, so the save is legal - which is exactly why it needs saying,
// because a lock somebody believes is standing is worse than none. Driven by
// the same delegated form events as the dirty badge, so it tracks the region
// dropdowns, the row enable boxes and the Protection switch live.
function updateGeoWarn() {
  const w = document.getElementById('geo-warn');
  if (!w || !config) return;
  const locked = (config.services || [])
    .filter((s) => s.enabled && (s.geo_regions || []).length)
    .map((s) => s.name || '(unnamed)');
  const show = locked.length > 0 && !(config.protect && config.protect.enabled);
  w.classList.toggle('hidden', !show);
  if (show) {
    w.textContent = '';
    w.append(
      el('h3', { text: `Region lock${locked.length === 1 ? '' : 's'} NOT active: ${locked.join(', ')}` }),
      el('p', { text: 'Protection is disabled, and the locks live in its table, so nothing is being dropped for these rows: '
        + 'they are open to the whole world right now. Tick Enabled under Protection below and save to make the locks live, '
        + 'or set the row back to anywhere if that is what you meant.' }),
    );
  }
}

// 'input' catches typing, 'change' the dropdowns and checkboxes, 'click' the
// Add and Remove buttons.
for (const evt of ['input', 'change', 'click']) {
  const form = document.getElementById('settings-form');
  form.addEventListener(evt, updateDirty);
  form.addEventListener(evt, updateGeoWarn);
}

// Closing or reloading the page with edits pending gets the browser's own
// are-you-sure. Switching tabs inside the portal is handled separately: the
// form and its edits stay in the DOM.
window.addEventListener('beforeunload', (e) => {
  if (settingsDirty) { e.preventDefault(); e.returnValue = ''; }
});

// caption is a label with its help marker beside it. Empty labels are the table
// rows, where the heading carries the explanation for the whole column instead.
function caption(label, tip) {
  if (!label) return null;
  return el('span', {}, label, tip ? help(tip) : null);
}

function field(label, value, onInput, opts = {}) {
  const input = el('input', {
    type: opts.type || 'text',
    value: value ?? '',
    step: opts.step,
    min: opts.min,
    placeholder: opts.placeholder,
  });
  input.addEventListener('input', () => onInput(opts.type === 'number' ? parseFloat(input.value) : input.value));
  return el('label', { class: 'field' }, caption(label, opts.help), input);
}

function readOnly(label, value, tip) {
  const input = el('input', { type: 'text', value: value ?? '', readonly: 'readonly', disabled: 'disabled' });
  return el('label', { class: 'field' }, caption(label, tip), input);
}

function checkbox(label, value, onInput, tip) {
  const input = el('input', { type: 'checkbox' });
  input.checked = !!value;
  input.addEventListener('change', () => onInput(input.checked));
  return el('label', { class: 'inline' }, input, label, tip ? help(tip) : null);
}

// th is a column heading carrying the explanation for every cell beneath it.
// The cells are bare inputs with no room for a label of their own, so this is
// the only place the column can be described.
function th(label, tip) {
  return el('th', {}, label, tip ? help(tip) : null);
}

function num(label, value, onInput, opts = {}) {
  return field(label, value, onInput, { ...opts, type: 'number' });
}

function section(title, ...children) {
  return el('fieldset', {}, el('legend', { text: title }), ...children);
}

function pathRow(p) {
  // An older stored config has no shaping at all, and a row cannot bind an
  // input to a field that is not there.
  if (!p.shape) p.shape = { to_backend_mbit: 0, to_frontend_mbit: 0 };
  return el('tr', {},
    el('td', {}, field('', p.name, (v) => (p.name = v), { placeholder: 'lte1' })),
    el('td', {}, field('', p.iface, (v) => (p.iface = v), { placeholder: 'wg-lte1' })),
    el('td', {}, num('', p.priority, (v) => (p.priority = v), { min: 1, placeholder: '2' })),
    el('td', {}, num('', p.table, (v) => (p.table = v), { min: 1, placeholder: '102' })),
    el('td', {}, field('', '0x' + (p.mark || 0).toString(16), (v) => (p.mark = parseInt(v, 16) || 0), { placeholder: '0x102' })),
    el('td', {}, checkbox('', p.enabled, (v) => (p.enabled = v))),
    el('td', {}, checkbox('', p.metered, (v) => (p.metered = v))),
    el('td', {}, num('', (p.quota.limit_bytes || 0) / GB, (v) => (p.quota.limit_bytes = Math.round(v * GB)), { step: 1, min: 0, placeholder: '60' })),
    el('td', {}, num('', (p.quota.ceiling_bytes || 0) / GB, (v) => (p.quota.ceiling_bytes = Math.round(v * GB)), { step: 1, min: 0, placeholder: '0' })),
    el('td', {}, num('', p.shape.to_backend_mbit, (v) => (p.shape.to_backend_mbit = v || 0), { min: 0, step: 1, placeholder: '0 = off' })),
    el('td', {}, num('', p.shape.to_frontend_mbit, (v) => (p.shape.to_frontend_mbit = v || 0), { min: 0, step: 1, placeholder: '0 = off' })),
    el('td', {}, num('', p.quota.reset_day, (v) => (p.quota.reset_day = v), { min: 1, placeholder: '1' })),
    el('td', {}, field('', p.quota.timezone, (v) => (p.quota.timezone = v), { placeholder: 'Australia/Melbourne' })),
    el('td', {}, num('', p.quota.calibration, (v) => (p.quota.calibration = v), { step: 0.5, placeholder: '100' })),
  );
}

// hostSelect is the "which machine" dropdown: the backend, or one of the
// configured linkers. The stored value is an overlay address (empty meaning
// the backend), so the options are built from the linker table rather than
// typed by hand: a mistyped address here looks exactly like the service
// being down. A value that matches no linker (a row removed while a service
// still points at it) is kept as its own option instead of being silently
// shown as the backend, so what would be saved is what is on screen.
function hostSelect(value, c, onChange) {
  const sel = el('select', {});
  sel.append(el('option', { value: '', text: 'the backend' }));
  const known = new Set();
  // The backend's own overlay address is a valid explicit way of saying "the
  // backend": validate accepts it, and the old free-text field let it be
  // typed. Same destination as blank, so it is labelled as such rather than
  // flagged as unknown.
  if (value && value === c.overlay.backend_ip) {
    known.add(value);
    sel.append(el('option', { value, text: `the backend (${value})` }));
  }
  for (const l of c.linkers || []) {
    if (!l.overlay_ip || known.has(l.overlay_ip)) continue;
    known.add(l.overlay_ip);
    sel.append(el('option', { value: l.overlay_ip, text: l.name ? `${l.name} (${l.overlay_ip})` : l.overlay_ip }));
  }
  if (value && !known.has(value)) {
    sel.append(el('option', { value, text: `${value} (no such linker)` }));
  }
  sel.value = value || '';
  sel.addEventListener('change', () => onChange(sel.value));
  return sel;
}

function serviceRow(s, c, onRemove) {
  const proto = el('select', {});
  for (const v of ['tcp', 'udp']) {
    const o = el('option', { value: v, text: v });
    if (s.proto === v) o.selected = true;
    proto.append(o);
  }
  proto.addEventListener('change', () => (s.proto = proto.value));

  return el('tr', {},
    el('td', {}, field('', s.name, (v) => (s.name = v), { placeholder: 'gmod' })),
    el('td', {}, proto),
    el('td', {}, num('', s.port, (v) => (s.port = v), { min: 1, placeholder: '27015' })),
    el('td', {}, num('', s.port_end, (v) => (s.port_end = v), { min: 0, placeholder: '0 = single port' })),
    el('td', {}, hostSelect(s.target, c, (v) => (s.target = v))),
    el('td', {}, num('', s.ceiling_pps, (v) => (s.ceiling_pps = v || 0), { min: 0, placeholder: '0 = off' })),
    el('td', {}, regionSelect(s, c, (v, block) => { s.geo_regions = v; s.geo_block = block; })),
    el('td', {}, num('', s.geo_auto_pps, (v) => (s.geo_auto_pps = v || 0), { min: 0, placeholder: '0 = always' })),
    el('td', {}, checkbox('', s.source_engine, (v) => (s.source_engine = v))),
    el('td', {}, checkbox('', s.enabled, (v) => (s.enabled = v))),
    el('td', {}, el('button', { class: 'btn danger', type: 'button', onclick: onRemove }, 'Remove')),
  );
}

// regionSelect is the "which region" dropdown for a service row: anywhere, or
// one of the regions defined under Protection. Options come from that table
// rather than being typed, for the same reason hostSelect's do: a mistyped
// name is refused at save, and a dropdown cannot mistype. A stored value that
// matches no region (a renamed row, or several regions on one service, which
// the API allows and this dropdown keeps but does not build) stays visible as
// its own option instead of being silently shown as anywhere, so what would
// be saved is what is on screen.
function regionSelect(s, c, onChange) {
  // Each region offers both directions: "only x" admits that region and drops
  // the rest of the world, "block x" drops that region and admits the rest.
  // A leading ! on the option value carries the direction; the stored config
  // keeps them apart as geo_regions plus geo_block.
  const names = (s.geo_regions || []).join(', ');
  const value = s.geo_block && names ? '!' + names : names;
  const sel = el('select', {});
  sel.append(el('option', { value: '', text: 'anywhere' }));
  const known = new Set(['']);
  for (const r of (c.protect && c.protect.regions) || []) {
    if (!r.name || known.has(r.name)) continue;
    known.add(r.name);
    known.add('!' + r.name);
    sel.append(el('option', { value: r.name, text: `only ${r.name}` }));
    sel.append(el('option', { value: '!' + r.name, text: `block ${r.name}` }));
  }
  if (value && !known.has(value)) {
    const prefix = s.geo_block ? 'block' : 'only';
    const label = names.includes(',') ? `${prefix} ${names} (several regions)` : `${prefix} ${names} (no such region)`;
    sel.append(el('option', { value, text: label }));
  }
  sel.value = value;
  sel.addEventListener('change', () => {
    const block = sel.value.startsWith('!');
    const list = sel.value.replace(/^!/, '').split(',').map((t) => t.trim()).filter(Boolean);
    onChange(list, block && list.length > 0);
  });
  return sel;
}

// A region is a name and a pile of networks, filled either way: the Fetch
// button asks the frontend for the current lists for a set of country codes,
// or a list is pasted by hand (one CIDR per line, the shape the aggregated
// country files come in, so deploy/geo-zones.sh output pastes straight in).
//
// The fetch fills the form and nothing else. What came back is on screen, the
// unsaved badge is lit, and it goes through Save and validation exactly like
// something typed - the configuration is never touched by the fetch itself.
function regionRow(r, onRemove, onChange) {
  const ta = el('textarea', { rows: 4, placeholder: '1.128.0.0/11\n101.160.0.0/11\n…' });
  ta.value = (r.cidrs || []).join('\n');
  ta.addEventListener('input', () => {
    r.cidrs = ta.value.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
  });

  const codes = el('input', { type: 'text', placeholder: 'au, nz', value: (r.countries || []).join(', ') });
  codes.addEventListener('input', () => {
    r.countries = codes.value.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
  });
  const fetchBtn = el('button', {
    class: 'btn', type: 'button',
    onclick: async () => {
      const countries = codes.value.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
      if (!countries.length) { toast('Name the country codes to fetch, e.g. au, nz', true); return; }
      fetchBtn.disabled = true;
      fetchBtn.textContent = 'Fetching…';
      try {
        const res = await api('/api/geo/fetch', { method: 'POST', body: JSON.stringify({ countries }) });
        ta.value = (res.cidrs || []).join('\n');
        r.cidrs = res.cidrs || [];
        r.countries = countries;
        updateDirty();
        const detail = (res.counts || []).map((c) => `${c.country} ${c.networks}`).join(', ');
        toast(`Fetched ${r.cidrs.length} networks (${detail}). Review the list, then Save.`);
      } catch (e) {
        toast(e.message, true);
      } finally {
        fetchBtn.disabled = false;
        fetchBtn.textContent = 'Fetch';
      }
    },
  }, 'Fetch');

  return el('tr', {},
    el('td', {}, field('', r.name, (v) => { r.name = v; onChange(); }, { placeholder: 'oceania' })),
    el('td', {}, el('div', { class: 'row' }, codes, fetchBtn)),
    el('td', {}, ta),
    el('td', {}, el('button', { class: 'btn danger', type: 'button', onclick: onRemove }, 'Remove')),
  );
}

function egressRow(s, c, onRemove, onChange) {
  return el('tr', {},
    el('td', {}, field('', s.name, (v) => (s.name = v), { placeholder: 'gmod container' })),
    el('td', {}, hostSelect(s.host, c, (v) => (s.host = v))),
    el('td', {}, field('', s.cidr, (v) => (s.cidr = v), { placeholder: '172.18.0.0/16' })),
    el('td', {}, checkbox('', s.enabled, (v) => { s.enabled = v; onChange(); })),
    el('td', {}, el('button', { class: 'btn danger', type: 'button', onclick: onRemove }, 'Remove')),
  );
}

function linkerRow(l, onRemove, onChange) {
  return el('tr', {},
    el('td', {}, field('', l.name, (v) => { l.name = v; onChange(); }, { placeholder: 'gs1' })),
    el('td', {}, field('', l.overlay_ip, (v) => { l.overlay_ip = v; onChange(); }, { placeholder: '10.99.0.3' })),
    el('td', {}, field('', l.lan_ip, (v) => { l.lan_ip = v; onChange(); }, { placeholder: '10.1.1.4' })),
    el('td', {}, num('', l.table, (v) => { l.table = v || 0; onChange(); }, { min: 0, placeholder: '0 = 200' })),
    el('td', {}, checkbox('', l.enabled, (v) => { l.enabled = v; onChange(); })),
    el('td', {}, el('button', { class: 'btn danger', type: 'button', onclick: onRemove }, 'Remove')),
  );
}

// Copy to the clipboard, in a page that is usually not a secure context.
//
// The portal is served over plain HTTP on a WireGuard address, so
// navigator.clipboard is undefined in every browser that follows the spec -
// which made the Copy button a no-op reporting failure. execCommand is
// deprecated and works here, so it is the fallback rather than the exception.
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      toast('Copied');
      return;
    }
  } catch { /* fall through to the old way */ }
  const ta = el('textarea', { style: 'position:fixed;opacity:0' });
  ta.value = text;
  document.body.append(ta);
  ta.select();
  const ok = document.execCommand('copy');
  ta.remove();
  toast(ok ? 'Copied' : 'Could not copy. Select it and copy by hand', !ok);
}

// The shared secret, fetched only when somebody opens a linker's setup block.
//
// It is not in the configuration - it lives in the bootstrap file, which the
// portal cannot edit - so it comes from its own endpoint. Kept for the life of
// the page once asked for, because the two blocks below both need it and
// re-fetching per keystroke while a row is being typed would be silly.
const PSK_PLACEHOLDER = 'PASTE-FROM-/etc/failover/frontend.json';
let pskCache = null;

async function ensurePSK() {
  if (pskCache) return pskCache;
  try {
    const r = await api('/api/psk');
    pskCache = r.psk || null;
  } catch { /* an older frontend, or no secret to show */ }
  return pskCache;
}

// The config the linker host needs, ready to paste.
function linkerConfigText(l, ov, backendLan, psk) {
  return JSON.stringify({
    role: 'linker',
    psk: psk || PSK_PLACEHOLDER,
    state_dir: '/var/lib/failover',
    overlay: {
      frontend_ip: ov.frontend_ip,
      backend_ip: ov.backend_ip,
      subnet: ov.subnet,
      device: ov.device || 'dummy0',
      probe_port: ov.probe_port,
      control_port: ov.control_port,
    },
    linker: { overlay_ip: l.overlay_ip, backend_lan: backendLan, table: l.table || 200 },
  }, null, 2);
}

// The one command that sets a linker up, with this row's values already in it.
//
// Every argument here is something the portal knows and the operator would
// otherwise be reading off two hosts and retyping. The overlay addresses are
// only passed when they are not the shipped ones, so the usual case stays
// short enough to read before running it.
function linkerInstallText(l, ov, backendLan, psk) {
  const args = [
    `--psk ${psk || PSK_PLACEHOLDER}`,
    `--overlay-ip ${l.overlay_ip}`,
    `--backend-lan ${backendLan || '<the backend\'s address on that network>'}`,
    `--subnet ${ov.subnet || '<overlay.subnet is not set on this site>'}`,
    `--table ${l.table || 200}`,
  ];
  if (ov.frontend_ip && ov.frontend_ip !== '10.99.0.1') args.push(`--frontend-ip ${ov.frontend_ip}`);
  if (ov.backend_ip && ov.backend_ip !== '10.99.0.2') args.push(`--backend-ip ${ov.backend_ip}`);
  return [
    `# on ${l.name || l.overlay_ip}, in a clone of the repo`,
    'sudo ./deploy/install-linker.sh \\',
    ...args.map((a, i) => `  ${a}${i === args.length - 1 ? '' : ' \\'}`),
  ].join('\n');
}

function renderSettings() {
  const form = document.getElementById('settings-form');
  form.textContent = '';
  const c = config;

  if (!c.egress) c.egress = { sources: [] };
  if (!c.egress.sources) c.egress.sources = [];
  if (!c.linkers) c.linkers = [];

  // A network configured while the master switch is off installs nothing at
  // all: the frontend only sends these to the backend once it is prepared to
  // translate them. Without a warning that is a silent no-op, and the place
  // somebody looks is the table they just filled in, not the checkbox two
  // sections above it. Built before either section so both can update it.
  const egressWarning = el('div', { class: 'alert hidden' },
    el('h3', { text: 'These networks are not being routed' }),
    el('p', { text: 'Backend egress via this address is switched off in the Frontend section above, so the frontend will not send these networks to the backend and no rules are installed. Tick it and save.' }),
  );
  const updateEgressWarning = () => {
    const wanted = c.egress.sources.some((s) => s.enabled);
    egressWarning.classList.toggle('hidden', !(wanted && !c.frontend.backend_egress));
  };

  form.append(section('Frontend',
    el('div', { class: 'grid' },
      field('Public interface', c.frontend.public_iface, (v) => (c.frontend.public_iface = v), {
        placeholder: 'eth0',
        help: 'The internet-facing NIC on this datacentre box, the one the public IP sits on. '
          + 'Published traffic is only translated when it arrives here, and the backend-egress rule below is scoped to it. '
          + 'Find it with: ip -br addr. Examples: eth0, ens3, enp1s0.',
      }),
      field('Public IP (optional)', c.frontend.public_ip, (v) => (c.frontend.public_ip = v), {
        placeholder: '203.0.113.10',
        help: 'Only needed when that interface holds several addresses and you want to publish on one of them. '
          + 'Blank matches any address on the interface, which is what most sites want. Example: 203.0.113.10.',
      }),
    ),
    el('p', { class: 'hint', text: 'Scopes the DNAT rules to traffic arriving from the internet. Leave the IP blank to match any address on that interface.' }),
    el('div', {}, checkbox('Backend egress via this address', c.frontend.backend_egress, (v) => {
      c.frontend.backend_egress = v;
      updateEgressWarning();
    }, 'Off by default. Turn it on when something at the far end has to appear to the outside world at this box\'s public address '
      + 'rather than the house\'s WAN IP. A Source game server\'s heartbeat is the case this exists for. '
      + 'Needs the public interface above set, and it is also the master switch for the networks section further down.')),
    el('p', { class: 'hint', text: 'Sends traffic the backend starts from its overlay address out through this public address instead of the house internet. A game server is listed in the server browser at the address its heartbeat appears to come from, so without this it is advertised at the home WAN IP, which has no port forward behind it and is unreachable while an LTE path is carrying traffic.' }),
    el('p', { class: 'hint', text: 'It also puts everything else the backend sends from that address on the tunnel, so it counts against the LTE quota during a failover.' }),
  ));

  form.append(section('Overlay (read-only)',
    el('div', { class: 'grid' },
      readOnly('Frontend overlay IP', c.overlay.frontend_ip,
        'This box\'s own address on the overlay, carried on the dummy device below. Probes and the control channel are sent from it. '
        + 'Example: 10.99.0.1. Changed only in /etc/failover/frontend.json, and it must match the backend\'s copy.'),
      readOnly('Backend overlay IP', c.overlay.backend_ip,
        'The address every published service is translated to, and the one failover keeps pointing at a working tunnel. '
        + 'It never changes: that is why a switch is a two-second stall rather than a disconnect. Example: 10.99.0.2.'),
      readOnly('Device', c.overlay.device,
        'The dummy interface both overlay addresses live on. It carries nothing itself; it exists so the addresses survive a tunnel '
        + 'going down, which is what keeps connections alive across a failover. Example: dummy0.'),
      readOnly('Probe port', c.overlay.probe_port,
        'UDP port the backend answers health probes on, inside the tunnels. Never reachable from the internet. Example: 51999.'),
      readOnly('Control port', c.overlay.control_port,
        'TCP port the backend and any linkers dial to reach this frontend, inside the tunnels. Carries configuration down and usage up. '
        + 'Must differ from the probe port. Example: 51998.'),
    ),
    el('p', { class: 'hint', text: 'These two addresses never change. Failover swaps only the interface behind them, which is why live game sessions and TCP connections survive a switch.' }),
    el('p', { class: 'hint', text: 'Set in /etc/failover/*.json on both hosts, which must agree. Not editable here: changing it would tear down the very channel the change has to travel over.' }),
  ));

  const pathsTable = el('table', {},
    el('thead', {}, el('tr', {},
      th('Name', 'Label only: what this path is called in the dashboard, the alerts and the activity log. Examples: main, lte1, lte2.'),
      th('Interface', 'The WireGuard interface on this frontend that carries this path, spelled exactly as wg show names it. '
        + 'The agent never creates tunnels, so it must already exist and be up. Example: wg-lte1.'),
      th('Priority', 'Lower number wins. 1 is the preferred path and keeps the traffic whenever it is usable. '
        + 'This is the cost order, not the speed order: put the unmetered link first even if an LTE service measures better. Example: main 1, lte1 2, lte2 3.'),
      th('Table', 'A routing table used only for probing this one tunnel, so it can be tested while a different path carries the traffic. '
        + 'Unique per path, 1-252, and not 100 (reserved). Example: 101, 102, 103.'),
      th('fwmark', 'Firewall mark stamped on this path\'s probe packets so the kernel sends them to the table above. '
        + 'Unique per path, written in hex, and not 0x100 (reserved). Example: 0x101, 0x102, 0x103.'),
      th('Enabled', 'Untick to take the path out of service entirely: not probed, never selected, nothing installed for it. '
        + 'Use it for a service you have cancelled, or a tunnel you are rebuilding.'),
      th('Metered', 'Tick for a link with a data cap. Only metered paths accumulate usage against a quota and appear with a usage bar on the dashboard. '
        + 'Leave it off for unmetered fixed line.'),
      th('Quota GB', 'The monthly allowance for this link. Once it is reached the path stops being selectable. It stays up, and the dashboard offers a button to approve going over. '
        + '0 means no quota at all. Example: 60.'),
      th('Ceiling GB', 'A hard stop that not even an approved overage can pass, for the 2am click you regret. '
        + 'Must be at or above the quota; 0 means none. Example: 80.'),
      th('Down Mbit/s', 'Shapes what this frontend sends into that tunnel, which is the home end\'s download. '
        + '0 is off and installs nothing. Enter about 90% of a measured speed test: the point is to hold the queue here, where it is kept short and shared fairly, '
        + 'instead of in the carrier\'s buffer where a download puts seconds of delay in front of every game packet. Too high and it does nothing at all.'),
      th('Up Mbit/s', 'The same for what the backend sends into that tunnel: the home end\'s upload, and the one that matters most for a game server, '
        + 'because srcds sends far more than it receives. 0 is off. Needs the sch_cake module, which Debian 12 has: modprobe sch_cake.'),
      th('Reset day', 'Day of the month your carrier\'s billing period starts, 1-31. Months too short for it clamp to the last day. Example: 1.'),
      th('Timezone', 'The zone that reset day is counted in, so the period turns over where the carrier draws it rather than at UTC midnight. '
        + 'IANA name, and blank means Australia/Melbourne. Example: Australia/Melbourne.'),
      th('Calibration %', 'Scales the measured figure to match what the carrier actually bills. 100 means trust the tunnel counters plus per-packet overhead. '
        + 'After a month of comparison: if this portal says 50 GB and the carrier says 55, set 110.'),
    )),
    el('tbody', {}, c.paths.map(pathRow)),
  );
  form.append(section('Paths',
    el('div', { class: 'table-wrap' }, pathsTable),
    el('p', { class: 'hint', text: 'Lower priority number wins. Ceiling 0 means no absolute stop. Calibration corrects the metered figure against your carrier’s own portal after a month of comparison.' }),
  ));

  // Detection speed. The numbers below are the only thing the engine reads;
  // the dropdown just fills four of them in, so the stored configuration never
  // carries a preset and a site that never opens it is untouched. The note
  // under it is the trade-off, shown at the moment the choice is being made,
  // because a faster condemnation is bought with false failovers and nothing
  // else on this page says so.
  // The four fields a preset owns, by their JSON names. One list drives the
  // match, the fill of the config and the fill of the inputs, so a field
  // added to a preset is added here once.
  const PRESET_KEYS = ['active_interval_ms', 'timeout_ms', 'fail_threshold', 'window_size'];
  const probeInputs = {};
  const presetSel = el('select', {});
  for (const d of presets) presetSel.append(el('option', { value: d.name, text: d.label }));
  presetSel.append(el('option', { value: 'custom', text: 'Custom' }));
  const presetNote = el('p', { class: 'hint' });
  const detectLine = el('p', { class: 'hint' });
  const matchingPreset = () => presets.find((d) => PRESET_KEYS.every((k) => d[k] === c.probe[k]));
  const refreshDetection = () => {
    const m = matchingPreset();
    presetSel.value = m ? m.name : 'custom';
    presetNote.textContent = m ? m.note
      : 'Custom numbers. Faster detection is bought with false failovers on any link that drops bursts of packets, and each one of those '
        + 'parks players on a metered path until the failback hold-down clears. Keep the timeout above the worst round trip on the slowest link.';
    // Mirrors ProbeConfig.DetectMs in Go. A field that is blank or not a
    // number gives NaN here and blanks the line, rather than quoting a figure
    // for numbers that cannot be saved.
    const p = c.probe;
    const ms = (Math.max(p.fail_threshold, 1) - 1) * p.active_interval_ms + p.timeout_ms;
    detectLine.textContent = Number.isFinite(ms)
      ? `With these numbers a dead active path is condemned in about ${Math.round(ms / 100) / 10}s. Players feel a freeze of roughly that long, `
        + 'plus a moment for the switch, and a link that goes quiet for that long without being dead moves traffic too.'
      : '';
  };
  presetSel.addEventListener('change', () => {
    const d = presets.find((x) => x.name === presetSel.value);
    if (!d) { refreshDetection(); return; }
    for (const k of PRESET_KEYS) {
      c.probe[k] = d[k];
      probeInputs[k].value = d[k];
    }
    // Validation refuses a standby cadence faster than the active one, and a
    // preset the portal offers must never produce a form it then refuses.
    if (!(c.probe.standby_interval_ms >= d.active_interval_ms)) {
      c.probe.standby_interval_ms = d.active_interval_ms;
      probeInputs.standby_interval_ms.value = d.active_interval_ms;
    }
    refreshDetection();
  });
  const probeField = (key, label, value, set, opts) => {
    const f = num(label, value, (v) => { set(v); refreshDetection(); }, opts);
    probeInputs[key] = f.querySelector('input');
    return f;
  };

  form.append(section('Probing',
    el('label', { class: 'field' }, caption('Detection speed',
      'How quickly a failing active path is given up on. Standard is the shipped tuning. Fast makes a failover a brief stutter at the cost of '
      + 'the occasional failover nothing was wrong for. Relaxed is for links that drop bursts of packets or spike in latency, and would otherwise '
      + 'be condemned and recover on their own. Choosing one fills in the four numbers below; editing any of them shows Custom.'), presetSel),
    presetNote,
    detectLine,
    el('div', { class: 'grid' },
      probeField('active_interval_ms', 'Active interval (ms)', c.probe.active_interval_ms, (v) => (c.probe.active_interval_ms = v), {
        placeholder: '250',
        help: 'How often the path currently carrying traffic is probed. Detection time is this times one less than losses-before-down, plus the timeout, '
          + 'so 250 × 7 + 800 is about 2.6 seconds. Minimum 50. Example: 250.',
      }),
      probeField('standby_interval_ms', 'Standby interval (ms)', c.probe.standby_interval_ms, (v) => (c.probe.standby_interval_ms = v), {
        placeholder: '5000',
        help: 'How often the idle paths are probed. Slower on purpose: they only need to be known-good, and on LTE every probe costs data. '
          + 'Cannot be shorter than the active interval. Example: 5000.',
      }),
      probeField('timeout_ms', 'Timeout (ms)', c.probe.timeout_ms, (v) => (c.probe.timeout_ms = v), {
        placeholder: '800',
        help: 'How long an unanswered probe waits before it counts as lost. Keep it comfortably above the worst round trip you expect '
          + 'on the slowest link, or a healthy path logs losses that are really just late replies. A reply slower than this is never measured, '
          + 'so a Max RTT above the timeout can never trip. Minimum 50. Example: 800.',
      }),
      probeField('fail_threshold', 'Losses before down', c.probe.fail_threshold, (v) => (c.probe.fail_threshold = v), {
        placeholder: '8',
        help: 'Consecutive unanswered probes before a path is condemned and traffic moves. '
          + 'One loss only makes it "suspect", which stays selectable: LTE drops the odd packet routinely and that must not move traffic. Example: 8.',
      }),
      num('Successes before up', c.probe.recover_threshold, (v) => (c.probe.recover_threshold = v), {
        placeholder: '10',
        help: 'Consecutive good probes before a condemned path counts as healthy again. It still has to serve the failback hold-down below '
          + 'before it is given traffic back. Example: 10.',
      }),
      probeField('window_size', 'Window size', c.probe.window_size, (v) => (c.probe.window_size = v), {
        placeholder: '60',
        help: 'How many recent probes the loss, RTT and jitter figures on the dashboard are calculated over. '
          + '60 probes at 250ms is about the last 15 seconds. Minimum 5. Example: 60.',
      }),
      num('Max loss %', c.probe.max_loss_pct, (v) => (c.probe.max_loss_pct = v), {
        step: 0.5,
        placeholder: '15',
        help: 'Loss across that window above this figure blocks the path as degraded: it is answering, but too badly to carry a game. '
          + 'It is not condemned, and becomes selectable again the moment it improves. Example: 15.',
      }),
      num('Max RTT (ms)', c.probe.max_rtt_ms, (v) => (c.probe.max_rtt_ms = v), {
        placeholder: '400',
        help: 'Average round trip across the window above this figure blocks the path as degraded, the same way loss does. '
          + 'Set it above what a busy but working link looks like, or you will block a path that is merely loaded. Example: 400.',
      }),
    ),
    el('p', { class: 'hint', text: 'Standby paths are probed slower because they only need to be known-good, and on metered LTE that difference is most of the monthly probe cost.' }),
  ));
  refreshDetection();

  form.append(section('Failover',
    el('div', { class: 'grid' },
      num('Failback hold-down (s)', c.failover.hold_down_sec, (v) => (c.failover.hold_down_sec = v), {
        placeholder: '90',
        help: 'How long a better path must be unbroken-clean before traffic goes back to it. A single lost probe restarts the clock. '
          + 'Raise it if a marginal service keeps half-recovering; every return is a visible stall for connected players. Example: 90.',
      }),
      num('Flap window (s)', c.failover.flap_window_sec, (v) => (c.failover.flap_window_sec = v), {
        placeholder: '600',
        help: 'The rolling period failures are counted in for the quarantine rule below. Example: 600.',
      }),
      num('Failures before quarantine', c.failover.flap_threshold, (v) => (c.failover.flap_threshold = v), {
        placeholder: '4',
        help: 'How many failures inside that window before a path is benched instead of being tried again. '
          + 'This is what stops a dying link being picked, dropped and picked again every few seconds. Example: 4.',
      }),
      num('Quarantine (s)', c.failover.quarantine_sec, (v) => (c.failover.quarantine_sec = v), {
        placeholder: '300',
        help: 'How long a flapping path is benched the first time. It doubles each time it happens again, up to the maximum beside it. Example: 300.',
      }),
      num('Max quarantine (s)', c.failover.quarantine_max_sec, (v) => (c.failover.quarantine_max_sec = v), {
        placeholder: '3600',
        help: 'The ceiling on that doubling, so a path that has come good is never benched for longer than this before being tried again. Example: 3600 (an hour).',
      }),
    ),
    el('p', { class: 'hint', text: 'Failing over to a worse path is immediate. Failing back to a better one waits for an unbroken clean streak, so a marginal fixed line service cannot drag traffic back and forth.' }),
  ));

  if (!c.failover.quality) c.failover.quality = { loss_weight: 25, rtt_weight: 1, jitter_weight: 3, margin_pct: 25, min_dwell_sec: 300 };
  const q = c.failover.quality;
  const selection = el('select', {});
  for (const [v, label] of [['priority', 'Priority order (default)'], ['quality', 'Best measured fallback']]) {
    const o = el('option', { value: v, text: label });
    if ((c.failover.selection || 'priority') === v) o.selected = true;
    selection.append(o);
  }
  selection.addEventListener('change', () => (c.failover.selection = selection.value));

  form.append(section('Choosing between fallbacks',
    el('label', { class: 'field' }, caption('Selection',
      'Priority order (the default) always takes the highest-priority path that works. '
      + 'Best measured fallback changes exactly one thing: once the preferred path is out, the replacement is whichever remaining path measures best, '
      + 'rather than simply the next one down the list. The settings below only do anything in that mode.'), selection),
    el('p', { class: 'hint', text: 'Priority order always uses the highest-priority path that works. Best measured fallback changes one thing: once the preferred path is out, it picks whichever remaining path is measuring best rather than simply the next one down the list.' }),
    el('p', { class: 'hint', text: 'The preferred path is never second-guessed: while it is usable it keeps the traffic whatever the numbers say, and it wins the traffic back on its clean streak alone. Priority order is the cost order here, and a link that is 10ms quicker is not a reason to sit on a metered one.' }),
    el('div', { class: 'grid' },
      num('Loss weight (ms per 1%)', q.loss_weight, (v) => (q.loss_weight = v), {
        step: 1,
        placeholder: '25',
        help: 'How many milliseconds of latency one percent of packet loss is treated as being worth. '
          + 'At 25, a link losing 1% has to be 25ms quicker just to draw level, which is right for a game server, where a clean 60ms path beats a lossy 30ms one. '
          + 'Cannot be negative.',
      }),
      num('RTT weight', q.rtt_weight, (v) => (q.rtt_weight = v), {
        step: 0.1,
        placeholder: '1',
        help: 'Multiplier on average round trip in the score. 1 means one millisecond of latency counts as one point, which is what makes the score read in milliseconds. '
          + 'Cannot be negative.',
      }),
      num('Jitter weight', q.jitter_weight, (v) => (q.jitter_weight = v), {
        step: 0.1,
        placeholder: '3',
        help: 'Multiplier on jitter, how much the round trip varies. Weighted above plain latency because inconsistency is what players actually notice. '
          + 'Cannot be negative.',
      }),
      num('Switch margin (%)', q.margin_pct, (v) => (q.margin_pct = v), {
        step: 1,
        placeholder: '25',
        help: 'How much better a candidate must score before it takes traffic off another fallback: 25 means it has to score at least 25% lower. '
          + 'The same margin applies coming back, so there is a dead zone rather than a threshold and two similar links cannot trade places on noise. '
          + 'Between 0 and 99.',
      }),
      num('Minimum time between switches (s)', q.min_dwell_sec, (v) => (q.min_dwell_sec = v), {
        step: 30,
        placeholder: '300',
        help: 'The floor between two fallback swaps, for links genuinely taking turns being better, which is what a carrier working on a tower produces. '
          + 'It never delays leaving a path that has stopped working, and never delays the return to the preferred path. Example: 300.',
      }),
    ),
    el('p', { class: 'hint', text: 'Score = loss% × loss weight + RTT × RTT weight + jitter × jitter weight, in milliseconds-equivalent, lower being better. Loss is weighted heavily on purpose: for a game server a clean 60ms link beats a lossy 30ms one.' }),
    el('p', { class: 'hint', text: 'The margin is how much better a fallback must score before it takes the traffic, and it then has to hold that lead for the failback hold-down above. Because the same margin applies in reverse, there is a dead zone rather than a threshold, and two links cannot trade places on measurement noise.' }),
    el('p', { class: 'hint', text: 'Minimum time between switches is the floor for a genuine alternation: two links really taking turns being much better, which is what a carrier working on a tower produces. It never delays leaving a path that has stopped working, and never delays the return to the preferred path.' }),
  ));

  const servicesBody = el('tbody', {});
  const renderServices = () => {
    servicesBody.textContent = '';
    c.services.forEach((s, i) => servicesBody.append(serviceRow(s, c, () => {
      c.services.splice(i, 1);
      renderServices();
    })));
  };
  renderServices();
  form.append(section('Published services',
    // Filled by updateGeoWarn, which every form event runs: a region lock on a
    // row does nothing while Protection is disabled, and a lock somebody
    // believes exists is worse than none. First in the section, above the
    // table, because the first real use scrolled past it at the bottom.
    el('div', { class: 'alert warn hidden', id: 'geo-warn' }),
    el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {},
        th('Name', 'Label only: it appears as a comment in the generated ruleset and in this table. Examples: gmod, gmod-hltv, https.'),
        th('Proto', 'udp for game traffic (srcds and HLTV are both udp), tcp for web. '
          + 'One row per protocol: a service that needs both takes two rows.'),
        th('Port', 'The port on the public IP, forwarded unchanged to the same port at the far end. There is no port translation to think about. '
          + '1-65535. Example: 27015.'),
        th('Port end', 'Publishes a contiguous range from Port up to this one, in a single rule. Leave 0 for a single port. '
          + 'Example: Port 27015 with Port end 27020 publishes six ports.'),
        th('Published to', 'The machine this service runs on: the backend, which is what most sites want, '
          + 'or one of the linkers from the section below. A linker has to be added there before it appears here, '
          + 'because publishing to an address with no host behind it looks exactly like the service being down.'),
        th('Ceiling pps', 'A cap on this service in total, across every client, in packets per second. 0 is off. '
          + 'Set it above the busiest legitimate moment you have measured and below what the active tunnel can carry: '
          + 'the point is that a flood is discarded here rather than filling a 20 Mbit LTE link and being billed to your quota.'),
        th('Region', 'Two directions per region: "only x" admits that region and drops the rest of the world, "block x" drops '
          + 'that region and admits everyone else. Either way the drop happens before anything is translated or sent down a '
          + 'tunnel, and anywhere means no lock. The regions on offer are defined in the Protection section below, so add one '
          + 'there first, and like everything in that section the lock only exists while protection is enabled. '
          + 'Several regions on one service are possible through the API and are kept if present.'),
        th('Auto-lock pps', 'Leave 0 and the lock above is permanent. Set a packets-per-second threshold instead and the port stays '
          + 'open to the world until its total traffic exceeds it: the lock then engages in the kernel at line rate, holds while the '
          + 'flood lasts, and releases on its own once it stops. The threshold counts every packet to the row\'s ports together, '
          + 'in-region traffic included, so it belongs above the busiest legitimate moment you have measured: a full server tripping '
          + 'it costs out-of-region players their access.'),
        th('Source engine', 'Tick for a Source game port. It does nothing unless protection is on, and then it lets the connectionless packets, '
          + 'the A2S queries and connection attempts, which are what gets flooded, be rate limited on their own. '
          + 'A player already in the game sends sequence-numbered packets and is never touched by it.'),
        th('Enabled', 'Untick to stop publishing without losing the row. The rule disappears from the ruleset on the next save.'),
        el('th', {}),
      )),
      servicesBody)),
    el('div', { class: 'row' }, el('button', {
      class: 'btn', type: 'button',
      onclick: () => { c.services.push({ name: 'new', proto: 'tcp', port: 5000, port_end: 0, enabled: true }); renderServices(); },
    }, 'Add service')),
    el('p', { class: 'hint', text: 'Destination NAT only. Source addresses are never rewritten, so the game server and the web server see real client IPs.' }),
  ));

  if (!c.protect) c.protect = {};
  const pr = c.protect;
  if (!pr.regions) pr.regions = [];

  const regionBody = el('tbody', {});
  // The services table's Regions dropdown is built from this table, so a
  // rename rebuilds it. Debounced for the same reason the linker refresh is:
  // the name field fires per keystroke, and rebuilt eagerly every half-typed
  // name landed in the dropdowns as an option.
  let regionRefresh = 0;
  const regionsChanged = () => {
    clearTimeout(regionRefresh);
    regionRefresh = setTimeout(renderServices, 400);
  };
  const renderRegions = () => {
    regionBody.textContent = '';
    pr.regions.forEach((r, i) => regionBody.append(regionRow(r, () => {
      pr.regions.splice(i, 1);
      renderRegions();
      renderServices();
    }, regionsChanged)));
  };
  renderRegions();

  form.append(section('Protection (rate limiting and edge filtering)',
    // Stated before the switches, not after them. Everything in this section
    // drops packets somebody sent, and the difference between a limit that is
    // working and a limit that is breaking your service is invisible from the
    // outside - so what it cannot do belongs where it will actually be read.
    el('div', { class: 'alert info' },
      el('h3', { text: 'What this can and cannot do' }),
      el('p', { text: 'It runs on this frontend, on traffic arriving from the internet, before anything is '
        + 'translated or sent down a tunnel. That is the useful place for it: what it stops never reaches the house, '
        + 'never fills an LTE link and is never billed to a quota.' }),
      el('p', { text: 'It cannot help with an attack larger than this datacentre link. Once the port itself is full, '
        + 'the packets are already here and dropping them changes nothing. That needs scrubbing upstream, from your provider. '
        + 'Ask them what they include before relying on any of this.' }),
      el('p', { text: 'Nothing here can see a probe or the control channel: every rule is scoped to the public interface, '
        + 'and the system\'s own traffic arrives on the tunnels. That is deliberate: a limiter able to drop a health check '
        + 'would make this system condemn a working link and move traffic because of its own firewall.' }),
      el('p', { text: 'Every limit below can drop a packet a real player sent. Turn them on one at a time and watch the counters '
        + 'on the dashboard: a threshold set from a guess produces "some people cannot connect", which looks exactly like the service being down.' }),
    ),
    el('div', {}, checkbox('Enabled', pr.enabled, (v) => (pr.enabled = v),
      'The master switch. Off, nothing in this section is generated and the table is removed entirely. '
      + 'If a limit ever locks players out, unticking this and saving is the whole fix. It reaches the system in about two seconds.')),
    el('p', { class: 'hint', text: 'Needs the frontend\'s public interface set, in the section at the top. Saving is refused without it, because a rule that could not be scoped to that interface would also match traffic arriving on a tunnel.' }),

    el('h3', { class: 'sub-head', text: 'Per-source limits' }),
    el('p', { class: 'hint', text: 'Each of these applies to one client address at a time, and each does nothing at zero. They are counted against the ports of your enabled published services, nothing else.' }),
    el('div', { class: 'grid' },
      num('New connections per second', pr.new_conns_per_sec, (v) => (pr.new_conns_per_sec = v || 0), {
        min: 0, placeholder: '0 = off',
        help: 'TCP connection attempts from one address, per second. Established connections are never touched, so this only affects how fast a client may open new ones. '
          + 'A browser opens a handful per page; 20 is generous. Stops connection floods and a stuck client reconnecting in a loop.',
      }),
      num('Concurrent connections per source', pr.max_conns_per_source, (v) => (pr.max_conns_per_source = v || 0), {
        min: 0, placeholder: '0 = off',
        help: 'How many tracked TCP connections one address may hold open at once. Shared connections behind one office or carrier NAT can be surprisingly many, '
          + 'so keep it well clear of what you see in normal use: 50 to 100 for a web service.',
      }),
      num('UDP packets per second per source', pr.packets_per_sec, (v) => (pr.packets_per_sec = v || 0), {
        min: 0, placeholder: '0 = off',
        help: 'Packets per second from one address to a published UDP port. A player in a game sends tens per second, so this wants to be generous: 400 is far above normal play '
          + 'and still stops a single source saturating the tunnel. This is the one that protects against one client hurting everyone else.',
      }),
      num('Source-engine queries per second per source', pr.queries_per_sec, (v) => (pr.queries_per_sec = v || 0), {
        min: 0, placeholder: '0 = off',
        help: 'Applies only to services ticked as Source engine, and only to their connectionless packets, the A2S queries and connection attempts. '
          + 'Players already in the game are unaffected, which is what makes a tight number safe here: 2 or 3 per second is ample, and this is the usual flood vector for a Source server.',
      }),
      num('Block a tripping source for (s)', pr.block_seconds, (v) => (pr.block_seconds = v || 0), {
        min: 0, placeholder: '0 = never block',
        help: 'When a source trips any limit above, park it for this long: everything from that address is dropped on sight until it expires, cheaply, before conntrack. '
          + '0 drops only the excess and never parks anybody, which is gentler and much less effective. 600 is a reasonable start. Parked addresses are listed on the dashboard.',
      }),
    ),

    el('h3', { class: 'sub-head', text: 'Edge filtering' }),
    el('p', { class: 'hint', text: 'No thresholds to get wrong, and no legitimate client sends any of what these drop. Reasonable to turn on together.' }),
    el('div', { class: 'grid' },
      checkbox('Drop invalid', pr.drop_invalid, (v) => (pr.drop_invalid = v),
        'Packets connection tracking cannot place in any connection: late fragments, out-of-window segments, and most of what a crafted flood is made of.'),
      checkbox('Drop bogus TCP flags', pr.drop_bogus_tcp, (v) => (pr.drop_bogus_tcp = v),
        'Flag combinations no real stack produces: SYN+FIN, SYN+RST, null and Xmas packets. Port scans and cheap floods, dropped before conntrack has to think about them.'),
      checkbox('Drop spoofed sources', pr.drop_spoofed, (v) => (pr.drop_spoofed = v),
        'Source addresses that cannot legitimately arrive from the internet: the private ranges, loopback, link-local, multicast and reserved space. '
        + 'Leave it off if anything reaches this box\'s public interface from a private network.'),
    ),
    el('p', { class: 'hint', text: 'There is no SYN-proxy option, and that is not an omission. SYN proxying needs the handshake to be untracked, and this frontend has to track every connection in order to translate it, so the two cannot both be true. Per-source connection limiting above is what covers the same ground here.' }),

    el('h3', { class: 'sub-head', text: 'Regions (for locking a port to part of the world)' }),
    el('p', { class: 'hint', text: 'A region is a named list of source networks. A published service locked to one (the Regions column above) drops everything arriving from outside it, before anything is translated or sent down a tunnel; with an auto-lock threshold on the row, the drop instead engages only while the port is being flooded and releases on its own afterwards.' }),
    el('p', { class: 'hint', text: 'Two ways to fill a region, same result. Fetch: enter ISO country codes and click Fetch, and this frontend downloads the current aggregated lists (from ipdeny.com, built from the RIR delegation statistics) into the box for you to review. By hand: paste any list of networks, one per line; deploy/geo-zones.sh prints the same data offline. Either way nothing applies until you Save, and the fetch is only ever a click, never a schedule: the running system does not depend on that site, and a stale list just misses a few newly allocated networks. Refreshing a couple of times a year is plenty.' }),
    el('p', { class: 'hint', text: 'It matches where an address is allocated, not where a player is. A VPN endpoint inside an allowed region walks straight through, so this keeps a server regional and thins a flood; it is not an access control.' }),
    el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {},
        th('Name', 'How service rows refer to this region, e.g. oceania. Lowercase letters, digits, hyphens and underscores only: it becomes an nftables set name.'),
        th('Countries', 'ISO codes for the Fetch button, comma separated, e.g. au, nz. Fetch fills the Networks box with the current lists for them; the codes are remembered so a refresh is one click. Leave blank for a hand-maintained region.'),
        th('Networks', 'The source networks the region admits, in CIDR form, one per line: what Fetch filled in, or your own paste. A bare address counts as a /32, and overlapping or duplicate entries are merged on save, so a generous paste is fine.'),
        el('th', {}),
      )),
      regionBody)),
    el('div', { class: 'row' }, el('button', {
      class: 'btn', type: 'button',
      onclick: () => { pr.regions.push({ name: '', cidrs: [] }); renderRegions(); },
    }, 'Add region')),
    el('div', { class: 'grid' },
      num('Auto-lock release (s)', pr.geo_lock_seconds, (v) => (pr.geo_lock_seconds = v || 0), {
        min: 0, placeholder: '0 = 60',
        help: 'How long an automatic lock lingers once the flood that engaged it stops. While traffic stays over the threshold the lock '
          + 'is refreshed continuously, so this is release lag, not a rearm interval. The default minute stops a flood pulsing on and off '
          + 'from letting a burst through between pulses, without locking out-of-region players out for long after a false trip.',
      }),
    ),
    el('p', { class: 'hint', text: 'The counters reset whenever you save, because saving reloads the rules.' }),
  ));

  const linkerBody = el('tbody', {});
  const linkerConfigs = el('div', {});
  // Everything needed to bring one of these hosts up, with this row's values
  // already filled in. Two ways, because a host may not have the repo on it:
  // the install script, and the config file it would have written.
  //
  // The secret is fetched only when a block is opened, so it is not sitting in
  // the page for every visit to Settings.
  const renderLinkerConfigs = () => {
    linkerConfigs.textContent = '';
    for (const l of c.linkers) {
      if (!l.enabled || !l.overlay_ip) continue;

      const cmd = el('pre', { class: 'config-block', text: linkerInstallText(l, c.overlay, c.backend_lan, pskCache) });
      const cfgPre = el('pre', { class: 'config-block', text: linkerConfigText(l, c.overlay, c.backend_lan, pskCache) });
      const fill = (psk) => {
        cmd.textContent = linkerInstallText(l, c.overlay, c.backend_lan, psk);
        cfgPre.textContent = linkerConfigText(l, c.overlay, c.backend_lan, psk);
      };

      const block = el('details', { class: 'setup-block' },
        el('summary', { text: `Set up ${l.name || l.overlay_ip}` }),
        el('p', { class: 'hint', text: 'Run this on that host, in a clone of the repo. It writes the config below, installs the unit and starts the agent. Nothing has to be run on the backend.' }),
        cmd,
        el('div', { class: 'row' }, el('button', {
          class: 'btn', type: 'button', onclick: () => copyText(cmd.textContent),
        }, 'Copy command')),
        el('p', { class: 'hint', text: 'Without the repo on that host: write this as /etc/failover/linker.json, owned by root and mode 0600, then install the binary and unit from deploy/ and start failover-linker.' }),
        cfgPre,
        el('div', { class: 'row' }, el('button', {
          class: 'btn', type: 'button', onclick: () => copyText(cfgPre.textContent),
        }, 'Copy config')),
        el('p', { class: 'hint', text: 'Both carry this site’s shared secret. It must match the frontend exactly: that is what the linker authenticates with, and a mismatch shows up as a host that never connects.' }),
      );
      block.addEventListener('toggle', async () => {
        if (!block.open || pskCache) return;
        const psk = await ensurePSK();
        if (psk) fill(psk);
        else toast('Could not read the shared secret; it is in /etc/failover/frontend.json on this host', true);
      });
      linkerConfigs.append(block);
    }
  };
  // The Published to and On host dropdowns are built from the linker table, so
  // editing a linker rebuilds both. Only ever fired by user input, which is why
  // it may name renderEgress before that is declared further down. Debounced,
  // because the linker fields fire per keystroke: rebuilt eagerly, every
  // half-typed overlay address landed in the dropdowns as an option.
  let linkerRefresh = 0;
  const linkersChanged = () => {
    renderLinkerConfigs();
    clearTimeout(linkerRefresh);
    linkerRefresh = setTimeout(() => { renderServices(); renderEgress(); }, 400);
  };
  const renderLinkers = () => {
    linkerBody.textContent = '';
    c.linkers.forEach((l, i) => linkerBody.append(linkerRow(l, () => {
      c.linkers.splice(i, 1);
      renderLinkers();
      renderServices();
      renderEgress();
    }, linkersChanged)));
    renderLinkerConfigs();
  };
  renderLinkers();
  form.append(section('Linkers (extra hosts behind the backend)',
    el('div', { class: 'grid' },
      field("Backend's address on this network", c.backend_lan, (v) => { c.backend_lan = v; renderLinkerConfigs(); }, {
        placeholder: '10.1.1.3',
        help: 'Where the backend sits on the LAN the extra hosts share with it: its ordinary address there, not its overlay address. '
          + 'It routes nothing by itself; it is the one fact a linker\'s own config needs and nothing else here carries, which is what lets the portal '
          + 'generate that file below instead of you assembling it by hand. Find it on the backend with: ip -br addr. Example: 10.1.1.3.',
      }),
    ),
    el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {},
        th('Name', 'Label only: used in error messages and on the dashboard card for this host. Examples: gs1, web.'),
        th('Overlay address', 'The address that machine holds on its own dummy0, and what services are published to. '
          + 'Must be inside the overlay subnet, and not the frontend\'s or the backend\'s. Two linkers cannot share one. Example: 10.99.0.3.'),
        th('LAN address', 'Where that machine actually is on the backend\'s network: the address the backend forwards to as a neighbour. '
          + 'Not the same as the overlay address above; transposing the two produces a route pointing at the address it is meant to reach. Example: 10.1.1.4.'),
        th('Table', 'The routing table that host uses for its overlay traffic. Leave 0 for the default of 200. '
          + 'The number belongs to that machine, not to this system: if it already policy-routes for a second ISP or a VPN, pick a free number, '
          + 'or the agent writes its default route over that host\'s. Check on that box with: ip rule show, and cat /etc/iproute2/rt_tables. '
          + '1-252, and it must match the value in that host\'s own linker.json.'),
        th('Enabled', 'Untick to stop the backend routing to this host and stop pushing it configuration. The row and the host itself are left alone.'),
        el('th', {}),
      )),
      linkerBody)),
    el('div', { class: 'row' }, el('button', {
      class: 'btn', type: 'button',
      onclick: () => { c.linkers.push({ name: 'new', overlay_ip: '', lan_ip: '', enabled: true }); renderLinkers(); },
    }, 'Add linker')),
    el('p', { class: 'hint', text: 'A linker is a machine behind the backend that publishes its own services, a game server on its own box. It gets its own overlay address, so two of them can both listen on 27015 with nothing to translate.' }),
    el('p', { class: 'hint', text: 'Overlay address is what services are published to, e.g. 10.99.0.3, and must sit inside the overlay subnet. LAN address is where that machine actually is on the backend’s network, e.g. 10.1.1.4: the backend forwards to it as a neighbour.' }),
    el('p', { class: 'hint', text: 'Saving here installs the backend’s route to each linker and keeps it repaired. Nothing has to be run on the backend by hand.' }),
    el('p', { class: 'hint', text: 'Table is the routing table that host uses for overlay traffic, 200 unless you change it. It belongs to that machine’s own namespace, so pick another number if the box already policy-routes (a second ISP, a VPN): two systems writing one table fight over its default route, and the loser’s traffic goes somewhere nobody intended. Check with: ip rule show, and cat /etc/iproute2/rt_tables.' }),
    el('p', { class: 'hint', text: 'It must also be set in that host’s own linker.json: the rule it names is what carries the control connection, so the agent needs it before it can be told anything. The generated config below has it; the dashboard warns if the host reports a different one.' }),
    el('p', { class: 'hint', text: 'Requires overlay.subnet in both bootstrap files. The frontend’s WireGuard peers must also cover that range: the shipped setup uses 10.99.0.0/24, so normally there is nothing to change. A peer still limited to the backend’s single address drops everything for a linker before it reaches the tunnel, and reports nothing: check with wg show wg-main allowed-ips.' }),
    linkerConfigs,
  ));

  const egressBody = el('tbody', {});
  const renderEgress = () => {
    egressBody.textContent = '';
    c.egress.sources.forEach((s, i) => egressBody.append(egressRow(s, c, () => {
      c.egress.sources.splice(i, 1);
      renderEgress();
    }, updateEgressWarning)));
    updateEgressWarning();
  };
  renderEgress();
  form.append(section('Backend networks routed out through the frontend',
    egressWarning,
    el('div', { class: 'table-wrap' }, el('table', {},
      el('thead', {}, el('tr', {},
        th('Name', 'Label only: it becomes the comment on the generated rule. Example: gmod container.'),
        th('On host', 'The machine this network is on: the backend, or one of the linkers from the section above. '
          + 'It matters because Docker hands out the same subnets everywhere: 172.17.0.0/16 is the default on every box, so an unowned row would pull '
          + 'the wrong containers onto the tunnel. The same network on two hosts is fine; the same one twice on a single host is not.'),
        th('Network (CIDR)', 'The container network whose outbound traffic should leave through the frontend\'s public address. IPv4 only. '
          + 'Find it with: docker network inspect <name> -f "{{range .IPAM.Config}}{{.Subnet}}{{end}}". Example: 172.18.0.0/16.'),
        th('Enabled', 'Untick to stop routing that network this way. Its traffic goes back to leaving by the house\'s own internet on the next save.'),
        el('th', {}),
      )),
      egressBody)),
    el('div', { class: 'row' }, el('button', {
      class: 'btn', type: 'button',
      onclick: () => { c.egress.sources.push({ name: 'new', cidr: '172.18.0.0/16', enabled: true }); renderEgress(); },
    }, 'Add network')),
    el('p', { class: 'hint', text: 'Requires Backend egress via this address, in the Frontend section above.' }),
    el('p', { class: 'hint', text: 'For services the backend cannot bind to the overlay address: a container has its own network namespace, so the overlay address does not exist inside it. Traffic from these networks is pulled onto the active tunnel and leaves with the frontend’s public address, which is what gets a containerised game server listed at the right address.' }),
    el('p', { class: 'hint', text: 'Use the docker bridge network, e.g. 172.18.0.0/16. Find it with: docker network inspect <name> -f "{{range .IPAM.Config}}{{.Subnet}}{{end}}". Give the service its own network if the bridge carries anything you do not want routed this way.' }),
    el('p', { class: 'hint', text: 'All of that network’s internet traffic takes this route, so it counts against the LTE quota during a failover.' }),
    el('p', { class: 'hint', text: 'Only internet destinations are diverted. Traffic to private, link-local and multicast addresses (RFC 1918, 169.254.0.0/16, 100.64.0.0/10, 224.0.0.0/3) keeps its normal route, so the network can still reach the LAN, the host, its resolver and the other container networks.' }),
    el('p', { class: 'hint', text: 'On host is the machine the network belongs to: the backend unless the containers run on a linker. It matters because Docker uses the same bridge subnets on every machine: 172.17.0.0/16 is the default everywhere, so a row with no owner would pull containers onto the tunnel on hosts it was never meant to touch. The same network on two different hosts is fine; the same network twice on one host is not.' }),
  ));

  form.append(section('Notifications',
    el('div', { class: 'grid' },
      el('div', {}, checkbox('Enabled', c.notify.enabled, (v) => (c.notify.enabled = v),
        'Alerts are sent from this frontend, which is in a datacentre on its own internet, so they still arrive when every tunnel to the house is down.')),
      field('Kind (ntfy, telegram, webhook)', c.notify.kind, (v) => (c.notify.kind = v), {
        placeholder: 'ntfy',
        help: 'One of ntfy, telegram or webhook. Anything else is treated as webhook. '
          + 'ntfy is the least work: install the app, pick an unguessable topic name, done.',
      }),
      field('URL', c.notify.url, (v) => (c.notify.url = v), {
        placeholder: 'https://ntfy.sh/your-unguessable-topic',
        help: 'ntfy: the full topic URL, e.g. https://ntfy.sh/your-unguessable-topic. Anyone who knows it can read your alerts, so make it long. '
          + 'telegram: https://api.telegram.org/bot<bot-token>/sendMessage. '
          + 'webhook: a Discord or Slack incoming webhook URL; the body suits both.',
      }),
      field('Token / chat id', c.notify.token, (v) => (c.notify.token = v), {
        placeholder: 'blank for a public ntfy topic',
        help: 'telegram: the chat id to send to, which is required. '
          + 'ntfy and webhook: optional, sent as an Authorization: Bearer header for a protected topic or endpoint. Leave blank if there is none.',
      }),
    ),
    el('div', { class: 'grid' },
      checkbox('On switch', c.notify.on_switch, (v) => (c.notify.on_switch = v),
        'Traffic moved to a different tunnel. The routine one: expect a few a week on a marginal fixed line.'),
      checkbox('On path down', c.notify.on_path_down, (v) => (c.notify.on_path_down = v),
        'A path was condemned or came back. Worth having even when failover handled it silently: two of these in a week is a service to complain about.'),
      checkbox('On quota', c.notify.on_quota, (v) => (c.notify.on_quota = v),
        'A metered path crossed its quota or its ceiling, and has stopped being selectable.'),
      checkbox('When held', c.notify.on_held, (v) => (c.notify.on_held = v),
        'Nothing is selectable at all: everything is down, over quota or quarantined. The one that needs you: the system parks and waits for an approval.'),
    ),
    el('p', { class: 'hint', text: 'Worth turning on. When every usable path is over quota the system parks and waits for you to approve one. Without an alert, that approval only happens when you next open this page.' }),
  ));

  // Not part of the configuration blob, so it saves on its own rather than
  // with the button below - and deliberately at the end, where somebody who
  // has just been handed a generated password will scroll looking for it.
  const pwCurrent = el('input', { type: 'password', autocomplete: 'current-password' });
  const pwNew = el('input', { type: 'password', autocomplete: 'new-password' });
  const pwConfirm = el('input', { type: 'password', autocomplete: 'new-password' });
  form.append(section('Portal account',
    el('div', { class: 'grid' },
      el('label', { class: 'field' }, caption('Current password',
        'The one you are logged in with. The first-run password was printed to the journal on this host when the agent first started: '
        + 'journalctl -u failover-frontend | grep "portal account created".'), pwCurrent),
      el('label', { class: 'field' }, caption('New password',
        'At least 10 characters. The portal is reachable only over the admin WireGuard tunnel, so this login is defence in depth for a lost phone '
        + 'rather than the perimeter. A passphrase you will actually remember beats a short one you have to write down.'), pwNew),
      el('label', { class: 'field' }, caption('Repeat new password', 'Typed twice because there is no way to recover a mistyped one from here.'), pwConfirm),
    ),
    el('div', { class: 'row' }, el('button', {
      class: 'btn', type: 'button',
      onclick: async () => {
        if (pwNew.value !== pwConfirm.value) { toast('The two new passwords do not match', true); return; }
        try {
          await api('/api/password', { method: 'POST', body: JSON.stringify({ current: pwCurrent.value, new: pwNew.value }) });
          pwCurrent.value = pwNew.value = pwConfirm.value = '';
          toast('Password changed; other sessions have been logged out');
        } catch (e) { toast(e.message, true); }
      },
    }, 'Change password')),
    el('p', { class: 'hint', text: 'Changing it logs out every other session for this account, which is usually the reason for changing it. This one stays signed in.' }),
    el('p', { class: 'hint', text: 'Locked out entirely? On the frontend itself: sudo failoverctl passwd. It prints a new one and needs no old password, because anyone who can run it is already root on that box.' }),
  ));

  form.append(el('div', { class: 'sticky-save' },
    el('span', { id: 'unsaved-badge', class: 'badge warn hidden', text: 'Unsaved changes' }),
    el('button', { class: 'btn primary', type: 'button', onclick: saveSettings }, 'Save configuration'),
    help('Applies immediately: the probers restart, the rulesets are regenerated, and the backend and any linkers are pushed their share of it within a couple of seconds. '
      + 'Nothing here is staged. In observe mode the parts that would move traffic are still withheld.'),
    el('button', { class: 'btn', type: 'button', onclick: loadSettings }, 'Discard changes'),
    help('Reloads the saved configuration and throws away anything typed since. Nothing on either host changes.'),
    el('span', { class: 'spacer' }),
    el('button', {
      class: 'btn danger', type: 'button',
      onclick: () => {
        if (!confirm('Remove the nftables table and every policy route this agent installed?\n\nWireGuard tunnels are left alone.')) return;
        act('/api/revert', {}, 'Reverted');
      },
    }, 'Revert all system changes'),
    help('Takes down the nftables tables and every policy route this agent installed, and drops back to observe mode so the next decision cannot quietly reinstall them. '
      + 'Published services stop working until you arm it again. WireGuard tunnels are never touched: the agent did not create them.'),
  ));
}

async function loadSettings() {
  try {
    [config, presets] = await Promise.all([
      api('/api/config'),
      // A missing preset list is not fatal, but it must not be silent: the
      // dropdown would otherwise offer only Custom under a caption that
      // promises three choices, and show the shipped numbers as Custom.
      api('/api/presets').catch((e) => { toast(`Detection presets unavailable: ${e.message}`, true); return []; }),
    ]);
    renderSettings();
    markSaved();
    // The form events keep it live from here; this covers a config loaded
    // already carrying the mismatch.
    updateGeoWarn();
  } catch (e) {
    toast(e.message, true);
  }
}

async function saveSettings() {
  try {
    await api('/api/config', { method: 'PUT', body: JSON.stringify(config) });
    markSaved();
    toast('Configuration saved');
    refreshStatus();
  } catch (e) {
    toast(e.message, true);
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

refreshStatus();
refreshHistory();
setInterval(refreshStatus, 1000);
setInterval(refreshHistory, 30000);
setInterval(() => {
  if (!document.getElementById('tab-events').classList.contains('hidden')) refreshEvents();
}, 10000);
