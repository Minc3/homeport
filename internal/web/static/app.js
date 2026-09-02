'use strict';

const GB = 1024 * 1024 * 1024;
// The largest figure a quota box may hold, in GB.
//
// 2^30 GiB is 2^60 bytes, which is store.MaxLedgerValue: the ledger column
// saturates there, so a cap above it can never be reached and is not a cap. It
// is also what keeps `v * GB` inside an int64 - without a ceiling here, a box
// overflowed to MAX_SAFE_INTEGER multiplies to 9.67e24, which Go's decoder
// refuses outright, and that then blocks every later save of the whole form.
// web.validate enforces the same bound on the same constant, because a bound
// that lives only in the browser is decoration for a hand-written PUT.
const MAX_QUOTA_GB = 1024 * 1024 * 1024;

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
    // form is still in the DOM and stays as it was left. An import in flight
    // counts as pending too, or whichever of the two requests lands second
    // wins the form, and the toast naming the file is on screen either way.
    if (btn.dataset.tab === 'settings' && !settingsDirty && !importing) loadSettings();
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
  renderBlocklist(st.blocklist, st.mode === 'armed');
  renderQueryCache(st.query_cache);
}

// The blocklist is the one list here nobody in this deployment reviewed, and
// every way it fails is quiet. A feed that stopped updating six weeks ago, a
// list that never made it into the kernel, and a list working perfectly all
// look identical from outside - the drops are indistinguishable from the
// internet being calm - so the age, the load state and the last error are
// stated rather than implied.
function renderBlocklist(b, armed) {
  const section = document.getElementById('blocklist-section');
  section.classList.toggle('hidden', !b);
  if (!b) return;

  const body = document.getElementById('blocklist-body');
  body.textContent = '';

  // Age first, because it is the number that goes wrong silently. Written as
  // hours or days rather than a timestamp: what matters is how far behind the
  // feed this list has fallen, not when a clock said so.
  // The threshold is the agent's, sent down beside the age. Written out here
  // as well, it was a second definition of a number the Go constant already
  // owned, with nothing to fail when the two drifted.
  const stale = !!b.stale;
  const age = !b.updated_at || b.age_hours <= 0 ? 'never'
    : b.age_hours < 1 ? 'under an hour'
    : !stale ? `${Math.round(b.age_hours)}h`
    : `${Math.round(b.age_hours / 24)} days`;

  body.append(el('div', { class: 'metrics' },
    el('div', { class: 'metric', title: 'Networks in the loaded set. Fewer than the feed publishes, because overlapping entries are merged and private, reserved and carrier-NAT space is dropped before anything reaches the kernel.' },
      el('div', { class: 'k', text: 'networks' }),
      el('div', { class: 'v', text: (b.networks || 0).toLocaleString() }),
      el('div', { class: 'hint', text: b.exceptions ? `${b.exceptions} exception${b.exceptions === 1 ? '' : 's'}` : 'no exceptions' })),
    el('div', { class: 'metric', title: 'How long since the feed last confirmed this list is current. A list that has stopped refreshing keeps working, so nothing else says this.' },
      el('div', { class: 'k', text: 'list age' }),
      el('div', { class: 'v', text: age })),
    el('div', { class: 'metric', title: 'Packets dropped by the blocklist since its table was last loaded. Refreshing the list does not reset this; saving a change to the blocklist settings does.' },
      el('div', { class: 'k', text: 'dropped' }),
      el('div', { class: 'v', text: (b.packets || 0).toLocaleString() }),
      el('div', { class: 'hint', text: bytes(b.bytes || 0) })),
  ));

  // On before loaded, because "the switch is on" and "the rules are in the
  // kernel" are different facts and the gap between them is where this
  // feature does nothing at all while the settings page says it is enabled.
  if (!b.loaded) {
    body.append(el('div', { class: 'alert warn' },
      el('p', { text: 'The blocklist is switched on but its rules are not in the kernel, so nothing is being dropped. '
        + 'In observe mode that is expected: this rule drops packets, so it is not installed until the system is armed. '
        + 'Armed, it means the last apply failed - check the Activity tab.' })));
  } else if (!armed) {
    // Disarming is not a teardown, so the table loaded while armed is still
    // there and still dropping. It is the list behind it that stops moving:
    // loading a fresh one would change what a live rule drops, which is the
    // one thing observe mode may not do.
    body.append(el('div', { class: 'alert warn' },
      el('p', { text: 'The system is not armed, but this table was loaded while it was and is still in the kernel and still dropping. '
        + 'The list inside it is no longer being refreshed, so it will go stale where it stands. '
        + 'Arming resumes the refresh; Revert takes the rules down.' })));
  } else if (!b.networks) {
    body.append(el('div', { class: 'alert warn' },
      el('p', { text: 'The rules are loaded and the list is empty, so nothing is being dropped yet. '
        + 'The first fetch happens within a minute of enabling this; if it stays empty, the error below says why.' })));
  } else if (stale) {
    body.append(el('div', { class: 'alert warn' },
      el('p', { text: `This list was last confirmed current ${age} ago. It is still loaded and still dropping, which is `
        + 'deliberate - an old blocklist beats none - but it is no longer picking up newly listed networks.' })));
  }

  // A refused kernel load is its own alert, ahead of a failed fetch, because
  // the figures above describe the list the frontend accepted and not the
  // set: the list is accepted before it is loaded, so without this a refusal
  // read as N networks, loaded, no error, while the kernel went on dropping
  // from the previous list or from nothing.
  if (b.load_error) {
    body.append(el('div', { class: 'alert warn' },
      el('p', { text: `The list was fetched but the kernel refused to load it: ${b.load_error}` }),
      el('p', { text: 'The set still holds whatever it held before, so the count above is not what is being dropped. '
        + 'The load is retried on its own every fifteen minutes; if this stays, the Activity tab has the full error.' })));
  }

  if (b.last_error) {
    body.append(el('div', { class: 'alert warn' },
      el('p', { text: `The last refresh failed: ${b.last_error}` }),
      el('p', { text: 'The previously loaded list is untouched and still dropping. This retries on its own; a refusal naming an '
        + 'implausible shrink means the feed served a short list and was not believed, which needs somebody to look at the feed by hand. '
        + 'To accept what the feed now serves, stop the frontend unit, delete blocklist-cache.json from its state directory and start it again.' })));
  }

  body.append(el('p', { class: 'hint', text: `Source: ${b.source || 'unset'}. Fetched by this frontend on a timer, checked whole, and loaded into a set of its `
    + 'own so a refresh never touches a rule or resets a counter. TCP only, and only on the public interface, so a false positive can never drop a player '
    + 'mid-match and nothing here can see a probe or the control channel. If a visitor cannot connect and you suspect this list, add their network to the '
    + 'exceptions in Settings rather than turning the whole thing off.' }));
}

// The cache's freshness is the whole reason it is reported: a cache serving
// stale data looks exactly like a healthy server with the wrong map name, and
// a port whose socket failed to bind is redirecting every query to nothing.
function renderQueryCache(states) {
  const section = document.getElementById('qcache-section');
  const all = states || [];
  // Only ports with something to say. A site publishing a wide Source range
  // caches every port in it, and a hundred rows of zeros bury the handful
  // that carry the story; a port nobody has queried has no story yet. A bind
  // error always shows, because that port is redirecting queries to nothing.
  const list = all.filter((q) => q.error || q.refresh_error
    || q.answered || q.challenged || q.unanswered
    || q.info_age_sec >= 0 || q.player_age_sec >= 0 || q.rules_age_sec >= 0);
  section.classList.toggle('hidden', list.length === 0);
  if (!list.length) return;

  const body = document.getElementById('qcache-body');
  body.textContent = '';
  // The threshold is the bound the cache is actually serving under, carried
  // in the snapshot, never a copy kept here: the first version hardcoded 90,
  // which had already drifted from the shipped 10 and was wrong in both
  // directions - a dead port shown as serving for 80 seconds, and a long
  // configured bound labelled stale while it was still being served.
  const age = (s, stale) => (s < 0 ? 'never fetched' : s > stale ? `${Math.round(s)}s (stale, not served)` : `${Math.round(s)}s`);
  body.append(el('div', { class: 'table-wrap' }, el('table', {},
    el('thead', {}, el('tr', {},
      el('th', { text: 'Port' }), el('th', { text: 'Service' }),
      el('th', { text: 'Answered' }), el('th', { text: 'Challenged' }), el('th', { text: 'Unanswered' }),
      el('th', { text: 'Info age' }), el('th', { text: 'Players age' }), el('th', { text: 'Rules age' }),
      el('th', { text: 'Problem' }))),
    el('tbody', {}, list.map((q) => el('tr', {},
      el('td', { text: q.port }),
      el('td', { text: q.service }),
      el('td', { text: q.answered.toLocaleString() }),
      el('td', { text: q.challenged.toLocaleString() }),
      el('td', { text: q.unanswered.toLocaleString() }),
      el('td', { text: age(q.info_age_sec, q.stale_sec) }),
      el('td', { text: age(q.player_age_sec, q.stale_sec) }),
      el('td', { text: age(q.rules_age_sec, q.stale_sec) }),
      // An icon with the message on hover, not the message itself: the error
      // strings carry whole socket addresses and were wider than the rest of
      // the table put together. data-tip, not title: the browser sits on a
      // native title for a second before showing it, and the one column an
      // operator hovers is the one that must answer at once. The tip rides
      // the same instant bubble the help markers use, and the icon is
      // focusable so keyboard and touch reach the same text.
      el('td', q.error ? { text: '✖', 'data-tip': `cannot bind: ${q.error}`, tabindex: '0', role: 'img', 'aria-label': `cannot bind: ${q.error}` }
        : q.refresh_error ? { text: '⚠', 'data-tip': `no answer from ${q.target}: ${q.refresh_error}`, tabindex: '0', role: 'img', 'aria-label': `no answer from ${q.target}: ${q.refresh_error}` }
        : { text: '' })))))));
  const hidden = all.length - list.length;
  if (hidden > 0) {
    body.append(el('p', { class: 'hint', text: `${hidden} cached port${hidden === 1 ? '' : 's'} with no activity hidden.` }));
  }
  body.append(el('p', { class: 'hint', text: 'Answered is payloads served from cache; Challenged counts the challenge every new source gets first, so under a '
    + 'spoofed flood it is the number climbing while Answered stays flat, which is the cache doing its job. Hover a ⚠ for the error. Counters climbing '
    + 'on a ⚠ port usually mean nothing is listening there at the far end: internet scanners query every published port and complete challenges like '
    + 'anybody else. The same ⚠ on a port whose game server is really running is the cache unable to reach it, and the port answers nothing rather than '
    + 'advertising a server that may be gone. A ✖ is a port something else on the frontend holds, redirecting its queries to nothing.' }));
}

// counterInfo turns a rule comment into a readable label and an explanation.
// The comments are the kernel's identifiers and stay terse on purpose (nft
// bounds them in bytes); the place to be understood by a person is here.
function counterInfo(name) {
  const fixed = {
    blocked: ['parked sources', 'Dropped on sight because the source tripped a limit earlier and is parked until its block expires.'],
    invalid: ['invalid packets', 'Packets connection tracking could not place in any connection: late fragments, out-of-window segments, crafted floods.'],
    'bogus-tcp': ['bogus TCP flags', 'Flag combinations no real stack sends: SYN+FIN, null and Xmas packets, port scans. Seven rules, counted together.'],
    spoofed: ['spoofed sources', 'Source addresses that cannot legitimately arrive from the internet: private, loopback, link-local, multicast, reserved.'],
    'legacy-query': ['legacy queries', 'The two deprecated Source connectionless queries, GETCHALLENGE and A2A_PING, dropped before conntrack. No client sends them; a server that answers them is a reflector.'],
    'conn-rate': ['connection rate', 'TCP connection attempts over the per-source rate. Established connections are never touched.'],
    'conn-count': ['connections held', 'Connection attempts from sources already holding too many open connections.'],
    'packet-rate': ['packet rate', 'UDP packets over the per-source rate to a published port.'],
    'query-rate': ['query rate', 'Source-engine connectionless packets (A2S queries and connection attempts) over the per-source rate. Players in game never match.'],
  };
  if (fixed[name]) return fixed[name];
  const i = name.indexOf(':');
  if (i > 0) {
    const kind = name.slice(0, i);
    const svc = name.slice(i + 1);
    if (kind === 'ceiling') return [`ceiling: ${svc}`, `Packets over that service's total cap, across every client.`];
    if (kind === 'geo') return [`region lock: ${svc}`, `Packets dropped by that service's region lock.`];
    if (kind === 'geo-trip') return [`auto-lock trips: ${svc}`, 'Packets over the auto-lock threshold. Not drops: each one engaged or refreshed the region lock.'];
    if (kind === 'conn-rate') return [`connection rate: ${svc}`, `TCP connection attempts over that service's own per-source rate. Established connections are never touched.`];
    if (kind === 'conn-count') return [`connections held: ${svc}`, `Connection attempts from sources already holding too many open connections to that service.`];
  }
  return [name, ''];
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
    // The trip counter counts packets over an auto-lock threshold, which are
    // not themselves dropped (the drop is the geo counter beside it), so it
    // is shown but kept out of a total labelled "dropped". Which counters
    // drop is the API's `drops` flag, decided where the rules are generated,
    // not sniffed off the counter's name here.
    const total = counters.reduce((n, c) => n + (c.drops ? c.packets : 0), 0);
    body.append(el('div', { class: 'metrics' }, ...counters.map((c) => {
      const [label, tip] = counterInfo(c.name);
      return el('div', { class: 'metric', title: tip },
        el('div', { class: 'k', text: label }),
        el('div', { class: 'v', text: c.packets.toLocaleString() }),
        el('div', { class: 'hint', text: bytes(c.bytes) }));
    })));
    body.append(el('p', { class: 'hint', text: 'Hover a card for what its limit drops. Every figure is packets dropped by that limit, except auto-lock trips, which is the threshold being crossed.' }));
    body.append(el('p', { class: 'hint', text: total === 0
      ? 'Nothing dropped since the rules were last loaded.'
      : `${total.toLocaleString()} packets dropped since the rules were last loaded. Saving a change to the protection settings resets these.` }));
  }

  // Said loudly, because an engaged lock looks exactly like the service being
  // down to everybody outside the region - this line is the only thing that
  // separates "under attack, held" from "broken".
  const locked = p.geo_locked || [];
  for (const l of locked) {
    body.append(el('div', { class: 'alert info' },
      el('p', { text: `Region lock engaged on ${l.proto}/${l.port}: traffic to it exceeded the auto-lock threshold, and the sources its lock bars are being dropped. `
        + (l.expires_sec ? `Releases in ${l.expires_sec}s unless the flood is still refreshing it.` : 'Releasing shortly.')
        + ' Saving a change to the protection settings reloads the rules and releases the lock too, until the flood trips it again; a save that leaves protection alone keeps it engaged.' }),
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
// The shipped per-source limit tunings, from /api/protect-presets. Same
// contract as the detection list above.
let protectPresets = [];

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
// Set while an import is in flight. The dirty flag cannot stand in for it: it
// is cleared by the debounced compare a quarter of a second after the file is
// chosen, and the tab handler reloads the settings whenever it is false, so a
// slow check request could be overtaken by a tab switch and leave the operator
// reviewing the running configuration under a toast naming their file.
let importing = false;

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

// debounce(fn, ms) coalesces a burst of calls into one, ms after the last.
// run() schedules or reschedules; flush() runs a pending call immediately,
// for a handler that needs the result committed before anything reads it -
// 'change' firing after typed 'input' is the case every user of this has.
// One helper rather than a timer variable per site, because the flush
// discipline is exactly the part that gets forgotten when the pattern is
// copied by hand, and a forgotten flush is a stale parse read at save time.
function debounce(fn, ms) {
  let t = 0;
  return {
    run() { clearTimeout(t); t = setTimeout(() => { t = 0; fn(); }, ms); },
    flush() { if (t) { clearTimeout(t); t = 0; fn(); } },
  };
}

function markSaved() {
  savedConfig = JSON.parse(JSON.stringify(config));
  updateDirty();
}

// Delegated, because renderSettings rebuilds everything inside the form.
// updateGeoWarn says out loud that the per-row protection settings - a region
// lock, a packet ceiling, a connection override - do not exist while
// Protection is disabled. Nothing refuses that state on purpose: unticking
// Protection has to stay the one-click way to back every filter out, the row
// settings included, so the save is legal - which is exactly why it needs
// saying, because a limit somebody believes is standing is worse than none.
// Driven by the same delegated form events as the dirty badge, so it tracks
// the row inputs, the row enable boxes and the Protection switch live.
function updateGeoWarn() {
  const w = document.getElementById('geo-warn');
  if (!w || !config) return;
  const rows = (config.services || []).filter((s) => s.enabled);
  const locked = rows.filter((s) => (s.geo_regions || []).length).map((s) => s.name || '(unnamed)');
  const limited = rows.filter((s) => s.ceiling_pps || s.new_conns_per_sec || s.max_conns_per_source)
    .map((s) => s.name || '(unnamed)');
  const names = [...new Set([...locked, ...limited])];
  const show = names.length > 0 && !(config.protect && config.protect.enabled);
  w.classList.toggle('hidden', !show);
  if (show) {
    w.textContent = '';
    w.append(
      el('h3', { text: `Per-row protection NOT active: ${names.join(', ')}` }),
      el('p', { text: 'Protection is disabled, and the region locks, ceilings and connection limits on these rows all live in its table, '
        + 'so none of them is dropping anything right now'
        + (locked.length ? ' - the locked rows are open to the whole world' : '') + '. '
        + 'Tick Enabled under Protection below and save to make them live, or clear the row settings if that is what you meant.' }),
    );
  }
}

// updatePortClashWarn names two enabled rows of one protocol publishing the
// same port, before the save is attempted. validate refuses the state - a
// service row is a DNAT rule, DNAT is first-match, and the other row's
// overlap silently receives nothing - but a validate refusal lands after
// Save is clicked and blocks every unrelated edit in the form with it, so
// the clash is worth naming while it is still being typed. The mirror of
// validate's rule, not a second opinion, and mirrored in three particulars
// that each earned their line: rows without a usable port are skipped,
// because a cleared Port box holds 0 in the model until it is retyped, and
// validate refuses that row as an invalid port before its overlap loop ever
// runs - scanned here, a half-edited row announced a phantom clash against a
// row the operator never touched; the scan runs in validate's own order
// (each row against the rows before it), so with two independent clashes
// the banner and the refusal name the same pair, not different ones; and
// the earlier row is named first, as the refusal names it. Port fields
// speak through 'change', so the banner appears when the operator leaves
// the field.
function updatePortClashWarn() {
  const w = document.getElementById('port-clash-warn');
  if (!w || !config) return;
  const rows = (config.services || []).filter((s) => s.enabled && s.port >= 1);
  const clash = (() => {
    for (let i = 1; i < rows.length; i++) {
      for (let j = 0; j < i; j++) {
        const a = rows[i], b = rows[j];
        if (a.proto !== b.proto) continue;
        const hiA = Math.max(a.port, a.port_end || 0), hiB = Math.max(b.port, b.port_end || 0);
        if (a.port > hiB || b.port > hiA) continue;
        const lo = Math.max(a.port, b.port), hi = Math.min(hiA, hiB);
        return { first: b, second: a, range: hi > lo, ports: hi > lo ? `${lo}-${hi}` : `${lo}` };
      }
    }
    return null;
  })();
  w.classList.toggle('hidden', !clash);
  if (clash) {
    w.textContent = '';
    w.append(
      el('h3', { text: `Port${clash.range ? 's' : ''} ${clash.ports} published twice: `
        + `${clash.first.name || '(unnamed)'} and ${clash.second.name || '(unnamed)'}` }),
      el('p', { text: 'Each port can be published by one enabled row per protocol: the translation is first-match, so the other '
        + 'row\'s overlap would silently receive nothing and look exactly like the service being down. Saving will be refused '
        + 'until the overlap is gone. Split the range so each port appears on one row; disabling a row instead is only right for '
        + 'a true duplicate, because if the two rows publish to different hosts it silently moves the port to the other one.' }),
    );
  }
}

// updateQcacheWarn notes, without refusing anything, that the query cache is
// on while Protection is off. That combination is supported by design - the
// cache absorbs floods the limits cannot see - but with protection off there
// is no edge hygiene, no parked sources and no ceiling in front of any
// published port, and an operator who arrived here by unticking Protection
// for an unrelated reason should hear what else that changed.
function updateQcacheWarn() {
  const w = document.getElementById('qcache-warn');
  if (!w || !config) return;
  const show = !!(config.query_cache && config.query_cache.enabled)
    && !(config.protect && config.protect.enabled);
  w.classList.toggle('hidden', !show);
  if (show) {
    w.textContent = '';
    w.append(
      el('h3', { text: 'Query cache on, Protection off' }),
      el('p', { text: 'That works: the cache challenges and absorbs query floods on its own. But nothing else now stands in front of your '
        + 'published ports - no edge hygiene, no per-source limits, no parked sources and no service ceilings - so everything that is not '
        + 'an A2S query reaches the tunnel unfiltered. Deliberate is fine; if Protection was turned off for some other reason, its master '
        + 'switch is in the section above.' }),
    );
  }
}

// The three banners as one call. The set of them is enumerated wherever the
// form is rebuilt or reloaded, and a fourth added to two of the three sites is
// a banner that stays silent for exactly the operator who did not type the
// state it warns about, which on an import is all of them.
function updateWarnings() {
  updateGeoWarn();
  updateQcacheWarn();
  updatePortClashWarn();
}

// 'input' catches typing, 'change' the dropdowns and checkboxes, 'click' the
// Add and Remove buttons. Typing is debounced: a fetched country list puts
// tens of thousands of networks in the config, and sameConfig walks all of
// them, so running it on every keystroke made the whole settings form pay a
// per-key cost proportional to region size. 'change' and 'click' stay
// immediate - they are single actions, and 'change' fires on blur, so the
// badge is always right by the time a Save can be clicked. The geo warning
// only reads dropdowns, enable boxes and the Protection switch, all of which
// speak through 'change' and 'click', so it skips typing entirely.
{
  const form = document.getElementById('settings-form');
  const dirty = debounce(updateDirty, 250);
  form.addEventListener('input', () => {
    // The flag itself is armed now, not 250ms from now: beforeunload reads
    // it synchronously, and an edit followed by a fast close would slip out
    // with no are-you-sure while the timer was still pending. Only the deep
    // compare that repaints the badge - and can clear the flag again for an
    // edit typed back to its saved value - waits for the debounce.
    settingsDirty = true;
    dirty.run();
  });
  for (const evt of ['change', 'click']) {
    form.addEventListener(evt, updateDirty);
    form.addEventListener(evt, updateWarnings);
  }
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
    max: opts.max,
    placeholder: opts.placeholder,
  });
  // A number field never hands its callback a NaN, and it rounds unless the Go
  // field behind it is a float. Both were reachable and neither was harmless.
  //
  // parseFloat('') is NaN, so clearing a box passed NaN straight into the
  // config; JSON.stringify writes that as null, and Go decodes null into a
  // numeric field as a no-op, leaving whatever the zero value is.
  //
  // Be exact about what that does and does not fix, because the first version
  // of this comment was not. The delivered configuration is identical either
  // way - a null onto a zero field and a literal 0 both store 0 - so clearing
  // the Overhead box still means "no per-packet overhead" and still under-counts
  // that path by 5 to 15%. What it buys is that the model always holds a number,
  // so nothing downstream has to reason about a NaN leaking into arithmetic,
  // which is how the detection hint below came to quote a figure for an
  // unsavable form. The under-billing is a separate hole and is still open; the
  // placeholder reading "0 = none" is the whole of what warns about it.
  //
  // The fraction is the louder half: a decimal typed into a field Go declares
  // as int fails the whole PUT with "cannot unmarshal number 60.5", so an
  // unrelated edit elsewhere in the form cannot be saved until the operator
  // finds a field they may not have touched. Rounding here is the same
  // reasoning as declaring min and max: the form must not be able to build a
  // body the save endpoint refuses.
  //
  // Rounding is the default and `float: true` is the opt-out, which is the way
  // round it has to be. model.Config holds thirty-four integer fields against
  // eight float ones, and the first version of this made rounding opt-in and
  // reached four of them, so the same save-blocking decimal was still typeable
  // into every probe interval, every threshold, every timeout, every service
  // port and every protection limit: an invariant stated in a comment and held
  // in four places. The minority is the one worth naming at the call site.
  //
  // Neither direction is safe enough to leave to memory, which is why
  // web.TestEveryFractionalPortalInputOptsOutOfRounding reads this file and
  // takes the float list from model.Config by reflection. A float field that
  // loses its opt-out turns a typed 0.4 into 0, and on a quality weight that
  // stops the selector counting latency while model.Normalise leaves it alone,
  // because it only repairs that group when every weight in it is zero.
  //
  // The opt-out is about the units the *input* carries, not the Go type behind
  // it. The two quota caps are int64 in model.Config and are still float here,
  // because the box is in GB and its handler multiplies: rounding the box turns
  // a 2.5 GB cap into 3, and anything under half a gigabyte into 0, which is
  // how a quota is disabled. That is the silent direction, so where the units
  // and the Go type disagree the units win.
  //
  // An empty box is 0 and an unparseable one is not. parseFloat returns
  // Infinity for a value past Number.MAX_VALUE - a pasted 309-digit figure,
  // 1e400 - and folding that into the same branch as an empty box wrote 0,
  // which in a quota box is how a quota is disabled and in a shape box is how
  // shaping is turned off: the silent direction, reached by a value the
  // operator can see in front of them.
  //
  // It goes to the end of the field's own range that it overflowed towards, so
  // it is refused or corrected rather than accepted quietly. The sign matters
  // and the first version ignored it: -1e400 is -Infinity, and sending that to
  // the *ceiling* turned a pasted negative into Calibration 1000, over-billing
  // tenfold, or into a quota box with no ceiling at MAX_SAFE_INTEGER, whose
  // `v * GB` is 9.67e24 and fails the whole PUT as an int64. clamp() below is
  // what settles it back inside the range; this only has to pick the right end.
  const read = () => {
    const raw = input.value.trim();
    if (raw === '') return 0;
    const v = parseFloat(raw);
    if (Number.isNaN(v)) return 0;
    if (v === Infinity) return opts.max === undefined ? Number.MAX_SAFE_INTEGER : opts.max;
    if (v === -Infinity) return opts.min === undefined ? -Number.MAX_SAFE_INTEGER : opts.min;
    return v;
  };
  const clamp = (v) => {
    if (opts.min !== undefined && v < opts.min) v = opts.min;
    if (opts.max !== undefined && v > opts.max) v = opts.max;
    return opts.float ? v : Math.round(v);
  };
  input.addEventListener('input', () => {
    if (opts.type !== 'number') return onInput(input.value);
    const v = read();
    return onInput(opts.float ? v : Math.round(v));
  });
  // And the range, on change rather than on input.
  //
  // min and max on the element are advisory: saveSettings posts with fetch, so
  // the browser never runs constraint validation, and nothing clamped. Typing
  // 5000 into Calibration therefore stored 5000 and every later save was
  // refused by the endpoint, blocking unrelated edits - which is the whole
  // failure declaring the bounds was meant to close, left open in the half that
  // was never implemented.
  //
  // On change rather than on input because clamping every keystroke fights the
  // operator: typing "1" toward "100" in a field with a floor of 10 would snap
  // to 10 under their cursor. change fires on blur or Enter, so the value is
  // corrected once they have finished with it, and the box is rewritten so what
  // is stored is what they can see.
  if (opts.type === 'number' && (opts.min !== undefined || opts.max !== undefined)) {
    input.addEventListener('change', () => {
      if (input.value.trim() === '') return;
      const v = clamp(read());
      input.value = String(v);
      onInput(v);
    });
  }
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

// clearNum blanks a num() box's visible input; the caller zeroes the model
// field beside it. One helper because reaching for the input means knowing
// that field() wraps exactly one <input> in its label, and three call sites
// each coupled to that shape would break separately - with the model zeroed
// while the box still shows the old number, which is the on-screen/on-save
// divergence the callers exist to prevent.
function clearNum(box) { box.querySelector('input').value = ''; }

// presetPicker is the dropdown mechanism the two preset families share: a
// select listing the presets plus a Custom sentinel, the note under it, the
// strict match of the config's numbers against each preset, and the change
// handler that fills them in. One copy, because the first two were written
// twice and diverged inside a single commit: the per-source copy needed the
// absent-field coercion below and the detection copy never did, so a fix
// landing in one had nothing to make it land in the other. What genuinely
// differs between families rides the hooks: onRefresh runs after every
// refresh (detection recomputes its detection-time line), onApply runs after
// a chosen preset's numbers land (detection lifts a standby interval the new
// active one would overtake).
//
// The match coerces an absent field to the 0 it means, rather than writing 0
// into the config up front. The five per-source limits are omitempty in Go,
// so a config that never set one omits it entirely; pre-normalising made Off
// match but also made every untouched box render a literal 0, which buried
// the placeholder saying what zero means ("0 = off", "0 = never block") - the
// only in-form statement of that semantics. Coercing in the comparison keeps
// the box empty, the placeholder visible, and Off still reads as Off.
function presetPicker(list, keys, target, customNote, hooks = {}) {
  const inputs = {};
  const sel = el('select', {});
  for (const d of list) sel.append(el('option', { value: d.name, text: d.label }));
  sel.append(el('option', { value: 'custom', text: 'Custom' }));
  const note = el('p', { class: 'hint' });
  const refresh = () => {
    const m = list.find((d) => keys.every((k) => d[k] === (target[k] ?? 0)));
    sel.value = m ? m.name : 'custom';
    note.textContent = m ? m.note : customNote;
    if (hooks.onRefresh) hooks.onRefresh();
  };
  sel.addEventListener('change', () => {
    const d = list.find((x) => x.name === sel.value);
    if (!d) { refresh(); return; }
    for (const k of keys) {
      target[k] = d[k];
      inputs[k].value = d[k];
    }
    if (hooks.onApply) hooks.onApply(d);
    refresh();
  });
  // field builds one number input owned by the family: the setter stays at the
  // call site so the assignment is visible to the scan in
  // portal_numeric_test.go, and the input is registered under its key here so
  // the key cannot drift from the box the change handler fills.
  const field = (key, label, value, set, opts) => {
    const f = num(label, value, (v) => { set(v); refresh(); }, opts);
    inputs[key] = f.querySelector('input');
    return f;
  };
  return { sel, note, inputs, refresh, field };
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
    el('td', {}, num('', (p.quota.limit_bytes || 0) / GB, (v) => (p.quota.limit_bytes = Math.round(v * GB)), { float: true, step: 1, min: 0, max: MAX_QUOTA_GB, placeholder: '60' })),
    el('td', {}, num('', (p.quota.ceiling_bytes || 0) / GB, (v) => (p.quota.ceiling_bytes = Math.round(v * GB)), { float: true, step: 1, min: 0, max: MAX_QUOTA_GB, placeholder: '0' })),
    el('td', {}, num('', p.shape.to_backend_mbit, (v) => (p.shape.to_backend_mbit = v || 0), { float: true, min: 0, step: 1, placeholder: '0 = off' })),
    el('td', {}, num('', p.shape.to_frontend_mbit, (v) => (p.shape.to_frontend_mbit = v || 0), { float: true, min: 0, step: 1, placeholder: '0 = off' })),
    el('td', {}, num('', p.quota.reset_day, (v) => (p.quota.reset_day = v), { min: 1, placeholder: '1' })),
    el('td', {}, field('', p.quota.timezone, (v) => (p.quota.timezone = v), { placeholder: 'Australia/Melbourne' })),
    // The bounds are quota.MinCalibration and quota.MaxCalibration, mirrored
    // here by hand because the page cannot call Go, exactly as the detection
    // figure mirrors ProbeConfig.DetectMs. Keep the two in step: without them
    // the form accepts a figure PUT /api/config refuses outright, and the
    // refusal blocks the whole save, so an unrelated edit in this form cannot
    // be stored until a field the operator may never have touched is corrected.
    el('td', {}, num('', p.quota.calibration, (v) => (p.quota.calibration = v), { float: true, step: 0.5, min: 10, max: 1000, placeholder: '100' })),
    // Rendered for the same reason the bounds above are declared, and it was
    // the half that was missing. validate refuses an overhead outside 0 to
    // 65535, and this value had no input at all - it round-tripped from GET
    // straight back into the PUT body. A blob carrying one out of range
    // therefore failed every save, naming a field the operator could not see or
    // reach, and blocked every unrelated edit with it.
    el('td', {}, num('', p.quota.overhead_per_packet, (v) => (p.quota.overhead_per_packet = v), { step: 1, min: 0, max: 65535, placeholder: '0 = none' })),
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
  // Built ahead of the row because the region dropdown reaches into it: see
  // the comment on its cell below.
  const autoPPS = num('', s.geo_auto_pps, (v) => (s.geo_auto_pps = v || 0), { min: 0, placeholder: '0 = always' });
  const proto = el('select', {});
  for (const v of ['tcp', 'udp']) {
    const o = el('option', { value: v, text: v });
    if (s.proto === v) o.selected = true;
    proto.append(o);
  }
  // The two per-source connection overrides ride TCP connection-state rules,
  // so they are hidden on a udp row - and cleared with the model, not just
  // hidden, because validate refuses a nonzero value on a udp service and a
  // hidden field the save names is one the operator cannot see or reach: the
  // same failure the region dropdown clears the auto-lock threshold to
  // avoid. Clearing on render too, not only on a protocol change, keeps what
  // is on screen equal to what would be saved for a hand-edited blob.
  const connRate = num('', s.new_conns_per_sec, (v) => (s.new_conns_per_sec = v || 0), { min: 0, placeholder: '0 = shared' });
  const connCount = num('', s.max_conns_per_source, (v) => (s.max_conns_per_source = v || 0), { min: 0, placeholder: '0 = shared' });
  const syncConnCols = () => {
    const tcp = proto.value === 'tcp';
    connRate.classList.toggle('hidden', !tcp);
    connCount.classList.toggle('hidden', !tcp);
    if (!tcp) {
      s.new_conns_per_sec = 0;
      s.max_conns_per_source = 0;
      clearNum(connRate);
      clearNum(connCount);
    }
  };
  syncConnCols();
  proto.addEventListener('change', () => { s.proto = proto.value; syncConnCols(); });

  return el('tr', {},
    el('td', {}, field('', s.name, (v) => (s.name = v), { placeholder: 'gmod' })),
    el('td', {}, proto),
    el('td', {}, num('', s.port, (v) => (s.port = v), { min: 1, placeholder: '27015' })),
    el('td', {}, num('', s.port_end, (v) => (s.port_end = v), { min: 0, placeholder: '0 = single port' })),
    el('td', {}, hostSelect(s.target, c, (v) => (s.target = v))),
    el('td', {}, num('', s.ceiling_pps, (v) => (s.ceiling_pps = v || 0), { min: 0, placeholder: '0 = off' })),
    el('td', {}, connRate),
    el('td', {}, connCount),
    el('td', {}, regionSelect(s, c, (v, block) => {
      s.geo_regions = v; s.geo_block = block;
      // Back to "anywhere" takes the auto-lock threshold with it: a
      // threshold with no regions is a state validate refuses, and a
      // dropdown must never build a row the Save button then rejects. The
      // visible input is cleared with the model so what is on screen is
      // what will be saved.
      if (!v.length && s.geo_auto_pps) {
        s.geo_auto_pps = 0;
        clearNum(autoPPS);
      }
    })),
    el('td', {}, autoPPS),
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
  // The option value is a JSON pair [direction, names] rather than a
  // delimited string: validate forbids '!' and ',' in region names, but a
  // hand-edited blob is not bound by validate, and a name carrying either
  // would make a character-based encoding parse back as the wrong direction
  // or the wrong regions - and the next save would write that misreading into
  // the config. JSON round-trips whatever is stored, and building both sides
  // through the one encoder keeps the string comparison exact.
  const enc = (block, names) => JSON.stringify([block ? 1 : 0, names]);
  const names = s.geo_regions || [];
  const value = enc(s.geo_block && names.length > 0, names);
  const anywhere = enc(false, []);
  const sel = el('select', {});
  sel.append(el('option', { value: anywhere, text: 'anywhere' }));
  const known = new Set([anywhere]);
  for (const r of (c.protect && c.protect.regions) || []) {
    if (!r.name || known.has(enc(false, [r.name]))) continue;
    known.add(enc(false, [r.name]));
    known.add(enc(true, [r.name]));
    sel.append(el('option', { value: enc(false, [r.name]), text: `only ${r.name}` }));
    sel.append(el('option', { value: enc(true, [r.name]), text: `block ${r.name}` }));
  }
  if (!known.has(value)) {
    const prefix = s.geo_block && names.length ? 'block' : 'only';
    const joined = names.join(', ');
    const label = names.length > 1 ? `${prefix} ${joined} (several regions)` : `${prefix} ${joined} (no such region)`;
    sel.append(el('option', { value, text: label }));
  }
  sel.value = value;
  sel.addEventListener('change', () => {
    const [block, list] = JSON.parse(sel.value);
    const clean = list.filter(Boolean);
    onChange(clean, !!block && clean.length > 0);
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
  // A fetched country list is tens of thousands of lines, and re-splitting
  // the whole textarea on every keystroke made hand-editing one entry lag on
  // exactly the field built for huge pastes. Debounced while typing; 'change'
  // fires on blur, which is always before a Save can be clicked, so the
  // parsed list can never be behind the screen at the moment it is read.
  const parseTA = debounce(() => {
    r.cidrs = ta.value.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
    updateDirty();
  }, 400);
  ta.addEventListener('input', parseTA.run);
  ta.addEventListener('change', parseTA.flush);

  // One recipe for reading the codes field, shared by the remembering
  // listener and the Fetch click, so what the button sends can never drift
  // from what is stored and validated on save.
  const parseCodes = (v) => v.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
  const codes = el('input', { type: 'text', placeholder: 'au, nz', value: (r.countries || []).join(', ') });
  codes.addEventListener('input', () => {
    r.countries = parseCodes(codes.value);
  });
  const fetchBtn = el('button', {
    class: 'btn', type: 'button',
    onclick: async () => {
      const countries = parseCodes(codes.value);
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
  // Guarded like its neighbours, and the frontend serves an empty list rather
  // than null besides. A file with no services key is what a hand-trimmed
  // backup looks like, and unguarded it threw here after the form had already
  // been emptied: the page ended at Failover, with no Save, no Discard and no
  // Import left on it to get back from.
  if (!c.services) c.services = [];

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
        + 'After a month of comparison: if this portal says 50 GB and the carrier says 55, set 110. Range 10 to 1000, because a factor of ten either way is a typo '
        + 'rather than a calibration. Below is the dangerous direction: it under-bills every metered byte and the quota never trips.'),
      th('Overhead B/pkt', 'What each packet costs on the WAN over the payload the tunnel counters see: WireGuard, UDP and IP together, about 60. '
        + 'The carrier bills the encapsulated datagram, so counting payload alone undercounts by 5 to 15%. 0 to 65535, and 0 really does mean none: '
        + 'an empty box stores 0, not the 60 a fresh install ships with.'),
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
  const detectLine = el('p', { class: 'hint' });
  const detection = presetPicker(presets, PRESET_KEYS, c.probe,
    'Custom numbers. Faster detection is bought with false failovers on any link that drops bursts of packets, and each one of those '
      + 'parks players on a metered path until the failback hold-down clears. Keep the timeout above the worst round trip on the slowest link.',
    {
      onRefresh: () => {
        // Mirrors ProbeConfig.DetectMs in Go, and blanks rather than quoting a
        // figure for numbers that cannot be saved.
        //
        // It reads the boxes rather than the model to decide that. It used to
        // rely on a blank box reaching the model as NaN, which is what
        // parseFloat gave it; a cleared box now coerces to 0, deliberately and
        // for reasons that have nothing to do with this line, so that test
        // became unreachable and the hint started quoting "condemned in about
        // 0.8s" for a form validate refuses. The isFinite guard stays for a
        // value that is not blank and not a number.
        const p = c.probe;
        const blank = Object.values(probeInputs).some((i) => i && i.value.trim() === '');
        const ms = (Math.max(p.fail_threshold, 1) - 1) * p.active_interval_ms + p.timeout_ms;
        detectLine.textContent = !blank && Number.isFinite(ms)
          ? `With these numbers a dead active path is condemned in about ${Math.round(ms / 100) / 10}s. Players feel a freeze of roughly that long, `
            + 'plus a moment for the switch, and a link that goes quiet for that long without being dead moves traffic too.'
          : '';
      },
      // Validation refuses a standby cadence faster than the active one, and a
      // preset the portal offers must never produce a form it then refuses.
      onApply: (d) => {
        if (!(c.probe.standby_interval_ms >= d.active_interval_ms)) {
          c.probe.standby_interval_ms = d.active_interval_ms;
          probeInputs.standby_interval_ms.value = d.active_interval_ms;
        }
      },
    });
  const probeInputs = detection.inputs;
  const probeField = detection.field;

  form.append(section('Probing',
    el('label', { class: 'field' }, caption('Detection speed',
      'How quickly a failing active path is given up on. Standard is the shipped tuning. Fast makes a failover a brief stutter at the cost of '
      + 'the occasional failover nothing was wrong for. Relaxed is for links that drop bursts of packets or spike in latency, and would otherwise '
      + 'be condemned and recover on their own. Choosing one fills in the four numbers below; editing any of them shows Custom.'), detection.sel),
    detection.note,
    detectLine,
    el('div', { class: 'grid' },
      probeField('active_interval_ms', 'Active interval (ms)', c.probe.active_interval_ms, (v) => (c.probe.active_interval_ms = v), {
        min: 50,
        placeholder: '250',
        help: 'How often the path currently carrying traffic is probed. Detection time is this times one less than losses-before-down, plus the timeout, '
          + 'so 250 × 7 + 800 is about 2.6 seconds. Minimum 50. Example: 250.',
      }),
      probeField('standby_interval_ms', 'Standby interval (ms)', c.probe.standby_interval_ms, (v) => (c.probe.standby_interval_ms = v), {
        min: 50,
        placeholder: '5000',
        help: 'How often the idle paths are probed. Slower on purpose: they only need to be known-good, and on LTE every probe costs data. '
          + 'Cannot be shorter than the active interval. Example: 5000.',
      }),
      probeField('timeout_ms', 'Timeout (ms)', c.probe.timeout_ms, (v) => (c.probe.timeout_ms = v), {
        min: 50,
        placeholder: '800',
        help: 'How long an unanswered probe waits before it counts as lost. Keep it comfortably above the worst round trip you expect '
          + 'on the slowest link, or a healthy path logs losses that are really just late replies. A reply slower than this is never measured, '
          + 'so a Max RTT above the timeout can never trip. Minimum 50. Example: 800.',
      }),
      probeField('fail_threshold', 'Losses before down', c.probe.fail_threshold, (v) => (c.probe.fail_threshold = v), {
        min: 1,
        placeholder: '8',
        help: 'Consecutive unanswered probes before a path is condemned and traffic moves. '
          + 'One loss only makes it "suspect", which stays selectable: LTE drops the odd packet routinely and that must not move traffic. Example: 8.',
      }),
      num('Successes before up', c.probe.recover_threshold, (v) => (c.probe.recover_threshold = v), { min: 1,
        placeholder: '10',
        help: 'Consecutive good probes before a condemned path counts as healthy again. It still has to serve the failback hold-down below '
          + 'before it is given traffic back. Example: 10.',
      }),
      probeField('window_size', 'Window size', c.probe.window_size, (v) => (c.probe.window_size = v), {
        min: 5,
        placeholder: '60',
        help: 'How many recent probes the loss, RTT and jitter figures on the dashboard are calculated over. '
          + '60 probes at 250ms is about the last 15 seconds. Minimum 5. Example: 60.',
      }),
      num('Max loss %', c.probe.max_loss_pct, (v) => (c.probe.max_loss_pct = v), { float: true,
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
  detection.refresh();

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
      num('Loss weight (ms per 1%)', q.loss_weight, (v) => (q.loss_weight = v), { min: 0, float: true,
        step: 1,
        placeholder: '25',
        help: 'How many milliseconds of latency one percent of packet loss is treated as being worth. '
          + 'At 25, a link losing 1% has to be 25ms quicker just to draw level, which is right for a game server, where a clean 60ms path beats a lossy 30ms one. '
          + 'Cannot be negative.',
      }),
      num('RTT weight', q.rtt_weight, (v) => (q.rtt_weight = v), { min: 0, float: true,
        step: 0.1,
        placeholder: '1',
        help: 'Multiplier on average round trip in the score. 1 means one millisecond of latency counts as one point, which is what makes the score read in milliseconds. '
          + 'Cannot be negative.',
      }),
      num('Jitter weight', q.jitter_weight, (v) => (q.jitter_weight = v), { min: 0, float: true,
        step: 0.1,
        placeholder: '3',
        help: 'Multiplier on jitter, how much the round trip varies. Weighted above plain latency because inconsistency is what players actually notice. '
          + 'Cannot be negative.',
      }),
      num('Switch margin (%)', q.margin_pct, (v) => (q.margin_pct = v), { float: true, min: 0, max: 99,
        step: 1,
        placeholder: '25',
        help: 'How much better a candidate must score before it takes traffic off another fallback: 25 means it has to score at least 25% lower. '
          + 'The same margin applies coming back, so there is a dead zone rather than a threshold and two similar links cannot trade places on noise. '
          + 'Between 0 and 99.',
      }),
      num('Minimum time between switches (s)', q.min_dwell_sec, (v) => (q.min_dwell_sec = v), { min: 0,
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
    // Filled by updatePortClashWarn, on the same delegated events: validate
    // refuses the save, but the refusal arrives after Save is clicked and
    // blocks every unrelated edit with it, so the clash is worth naming
    // while it is being typed.
    el('div', { class: 'alert warn hidden', id: 'port-clash-warn' }),
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
        th('Conns/s', 'Overrides the shared "new connections per second" per-source limit from the Protection section, for this row\'s ports alone. '
          + '0 means the shared figure applies, and like everything in that section it only exists while protection is enabled. TCP rows only. '
          + 'The shared figure has to leave room for the hungriest service (a browser opens a handful of connections per page), so a game port '
          + 'whose clients hold one connection each can be held far tighter here: a join flood is connection churn, and this is the limit that meets it.'),
        th('Max conns', 'Overrides the shared "concurrent connections per source" limit for this row\'s ports alone. 0 means the shared figure, '
          + 'TCP rows only, and it does nothing unless protection is enabled. A game client holds exactly one connection while playing, but a '
          + 'household or carrier NAT shares one address across several players, so leave room: 6 to 8, not 1 or 2.'),
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
      // The seed port walks up from 5000 to the first port no existing row
      // covers, whatever its protocol or enabled state. A fixed 5000 broke
      // the rule this form itself enforces: the save refuses two enabled
      // rows of one protocol on a port, so two clicks of this button built
      // a form Save then rejected, naming "new and new" - and a button must
      // never build a row the Save button refuses, which is the same
      // invariant the region dropdown holds by clearing the auto-lock
      // threshold. Every proto and disabled rows too, because the new row's
      // protocol can be flipped and a parked row can be enabled, and a seed
      // that is simply free of everything cannot be argued into a clash.
      onclick: () => {
        const covers = (p) => c.services.some((s) => p >= s.port && p <= Math.max(s.port, s.port_end || 0));
        let port = 5000;
        while (covers(port) && port < 65535) port++;
        c.services.push({ name: 'new', proto: 'tcp', port, port_end: 0, enabled: true });
        renderServices();
      },
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
  const regionsChanged = debounce(renderServices, 400).run;
  const renderRegions = () => {
    regionBody.textContent = '';
    pr.regions.forEach((r, i) => regionBody.append(regionRow(r, () => {
      pr.regions.splice(i, 1);
      renderRegions();
      renderServices();
    }, regionsChanged)));
  };
  renderRegions();

  // Per-source limit presets. Same contract as the detection dropdown above:
  // choosing one fills the five numbers below, the stored configuration
  // carries only the numbers, and editing any of them shows Custom. The Off
  // preset is all zeros, which is also the shipped state, so a fresh install
  // reads Off rather than Custom: the five limits are omitempty in Go, so an
  // untouched config omits them, and presetPicker's match reads an absent one
  // as the 0 it means while the box stays empty with its placeholder showing.
  const PROTECT_KEYS = ['new_conns_per_sec', 'max_conns_per_source', 'packets_per_sec', 'queries_per_sec', 'block_seconds'];
  const protect = presetPicker(protectPresets, PROTECT_KEYS, pr,
    'Custom numbers. Keep each one well clear of what the dashboard counters show in normal use: several players or '
      + 'browsers routinely share one address behind a carrier or office NAT, and a limit that is right for one client '
      + 'is far too tight for all of them together.');
  const protectField = protect.field;

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
    el('label', { class: 'field' }, caption('Per-source preset',
      'Starting points sized from what real clients send: a browser holds at most 6 connections to one host, a Source player sends 30 to 66 packets a second, '
      + 'and a carrier NAT can put dozens of subscribers behind one address. Choosing one fills in the five numbers below; editing any of them shows Custom.'), protect.sel),
    protect.note,
    el('div', { class: 'grid' },
      protectField('new_conns_per_sec', 'New connections per second', pr.new_conns_per_sec, (v) => (pr.new_conns_per_sec = v), {
        min: 0, placeholder: '0 = off',
        help: 'TCP connection attempts from one address, per second. Established connections are never touched, so this only affects how fast a client may open new ones. '
          + 'A browser opens a handful per page; 20 is generous. Stops connection floods and a stuck client reconnecting in a loop. '
          + 'A service row can override this for its own ports (the Conns/s column above); this figure covers every TCP service without one.',
      }),
      protectField('max_conns_per_source', 'Concurrent connections per source', pr.max_conns_per_source, (v) => (pr.max_conns_per_source = v), {
        min: 0, placeholder: '0 = off',
        help: 'How many tracked TCP connections one address may hold open at once. Shared connections behind one office or carrier NAT can be surprisingly many, '
          + 'so keep it well clear of what you see in normal use: 50 to 100 for a web service. '
          + 'A service row can override this for its own ports (the Max conns column above); this figure covers every TCP service without one.',
      }),
      protectField('packets_per_sec', 'UDP packets per second per source', pr.packets_per_sec, (v) => (pr.packets_per_sec = v), {
        min: 0, placeholder: '0 = off',
        help: 'Packets per second from one address to a published UDP port. A player in a game sends tens per second, so this wants to be generous: 400 is far above normal play '
          + 'and still stops a single source saturating the tunnel. This is the one that protects against one client hurting everyone else.',
      }),
      protectField('queries_per_sec', 'Source-engine queries per second per source', pr.queries_per_sec, (v) => (pr.queries_per_sec = v), {
        min: 0, placeholder: '0 = off',
        help: 'Applies only to services ticked as Source engine, and only to their connectionless packets, the A2S queries and connection attempts. '
          + 'Players already in the game are unaffected, which is what makes a tight number safe here, but a server browser refresh sends three A2S queries at once, '
          + 'so single digits park anybody who refreshes twice in a second: 10 or more per second is the safe floor, and this is the usual flood vector for a Source server.',
      }),
      protectField('block_seconds', 'Block a tripping source for (s)', pr.block_seconds, (v) => (pr.block_seconds = v), {
        min: 0, placeholder: '0 = never block',
        help: 'When a source trips any limit above, park its address for this long: everything it sends, on every port, not just the port or limit it tripped, is dropped '
          + 'on sight before anything else runs, until the timer expires on its own. That turns a sustained flood into one cheap lookup per packet. 0 never parks anybody '
          + 'and only drops the excess over each limit, which is gentler and much less effective. Parking is by address, and a carrier or office NAT puts many households '
          + 'behind one, so a single tripping client parks everyone sharing its address: keep this short, 60 is a reasonable start, and a refresh-happy player who trips a limit is locked out for a minute rather than ten. '
          + 'Parked addresses are listed on the dashboard, and saving any protection change unparks all of them, because the list lives in the kernel and a save reloads the table.',
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
      checkbox('Drop legacy Source queries', pr.drop_legacy_queries, (v) => (pr.drop_legacy_queries = v),
        'The two deprecated connectionless queries no client has sent in over a decade: A2S_SERVERQUERY_GETCHALLENGE and A2A_PING. '
        + 'Both are small-request, larger-reply shapes, so a server that still answers them is a reflector others can bounce a flood off. '
        + 'Applies only to ports ticked as Source engine, and only to those two query types: the live queries and in-game traffic are untouched.'),
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
  protect.refresh();

  if (!c.query_cache) c.query_cache = {};
  form.append(section('Source query cache',
    // Filled by updateQcacheWarn, which every form change runs: the cache
    // works with protection off by design, but nothing else then stands in
    // front of the published ports, and the operator should choose that with
    // their eyes open rather than arrive at it.
    el('div', { class: 'alert warn hidden', id: 'qcache-warn' }),
    el('p', { class: 'hint', text: 'Answers A2S_INFO, A2S_PLAYER and A2S_RULES queries at this frontend, from a cache refreshed off the real server every '
      + 'few seconds, for every published UDP service ticked as Source engine. Queries stop crossing the tunnel, and every source is challenged before it '
      + 'is served, exactly as a modern Source server does it, so a flood of spoofed addresses gets nothing but challenges no spoofed sender can answer.' }),
    el('p', { class: 'hint', text: 'This is the protection the per-source limits cannot give: those key on source addresses being real. It works with every '
      + 'limit above at zero, and with the limits on they simply apply first. In-game traffic and connection attempts are untouched and still reach the '
      + 'real server.' }),
    el('div', {}, checkbox('Enabled', c.query_cache.enabled, (v) => (c.query_cache.enabled = v),
      'Takes effect when armed, and keeps running after a disarm, because disarming deliberately leaves the installed rules - the redirects included - '
      + 'in place. The refresh costs a small stream down the active tunnel, only while a port is '
      + 'actually being queried; an idle port costs nothing. The dashboard shows each cached port with its counters and cache age: a cache that cannot '
      + 'reach its server serves its last answer for the staleness bound below and then answers nothing, so a dead server drops out of browsers rather '
      + 'than being advertised by its own cache.')),
    el('p', { class: 'hint', text: 'Needs the Source engine tick on the service rows above; a row without it is not touched. If the cache is doing the '
      + 'flood absorbing, the Source queries per second limit above can be set to 0, or left on to cap what the cache ever sees.' }),
    (() => {
      // The unset value renders as an empty box rather than a 0, because the
      // box declares a floor of 500 and a displayed 0 would snap to it on
      // first touch; empty is what the placeholder explains, and empty is
      // what a cleared box stores as 0.
      const refreshBox = num('Refresh interval (ms)', c.query_cache.refresh_ms || '', (v) => (c.query_cache.refresh_ms = v || 0), {
        min: 500, max: 30000, placeholder: 'empty = 3000',
        help: 'How often a queried port is re-fetched from the real server, which is the staleness a browser normally sees. Faster costs more refresh '
          + 'traffic on the active tunnel and polls your own server harder; slower shows staler player counts. Between 500 and 30000: below that the '
          + 'refresher is polling your own server continuously, and above it every browser is looking at counts half a minute old. Clear the box for '
          + 'the default 3000. An idle port is never polled whatever this says.',
      });
      const staleBox = num('Serve a cached reply for at most (ms)', c.query_cache.stale_ms || '', (v) => (c.query_cache.stale_ms = v || 0), {
        min: 1500, max: 300000, placeholder: 'empty = 10000',
        help: 'How long the last good fetch keeps being served once the real server stops answering, and so how long a crashed server is still '
          + 'advertised before its ports go quiet. Must cover at least three refresh intervals: between polls every answer comes out of this window, '
          + 'so a smaller bound would have a healthy port going dark between refreshes - an explicit value under that is lifted here, because the '
          + 'save endpoint refuses it. Clear the box for automatic: 10000, or three refresh intervals where the refresh is slower.',
      });
      // The endpoint refuses an explicit staleness bound under three
      // effective refresh intervals, and the static min above covers that
      // floor only at the fastest refresh: with the refresh box empty the
      // real floor is 9000, so min: 1500 alone let 5000 through and every
      // later save of the whole form was refused on it - the exact "clamp is
      // decoration" failure declaring the bounds exists to close. The floor
      // moves with the refresh box, so it is held here, after each field's
      // own clamp has run (listeners fire in the order they were added), and
      // in both boxes: raising the refresh must lift a bound it now
      // undercuts. An empty staleness box is automatic and never lifted.
      const holdStaleFloor = () => {
        const floor = 3 * (c.query_cache.refresh_ms || 3000);
        if (c.query_cache.stale_ms && c.query_cache.stale_ms < floor) {
          c.query_cache.stale_ms = floor;
          staleBox.querySelector('input').value = String(floor);
        }
      };
      refreshBox.querySelector('input').addEventListener('change', holdStaleFloor);
      staleBox.querySelector('input').addEventListener('change', holdStaleFloor);
      return el('div', { class: 'grid' }, refreshBox, staleBox);
    })(),
  ));

  if (!c.blocklist) c.blocklist = {};
  form.append(section('Blocklist',
    el('p', { class: 'hint', text: 'Drops traffic from a threat feed this frontend downloads and refreshes on a timer, in front of every published TCP port. '
      + 'The feed is FireHOL level1: the conservative aggregate of DShield, abuse.ch Feodo, the Spamhaus DROP list and the bogon list, a few thousand '
      + 'networks, republished daily. It is the only list here that is not something you typed, so everything about it is arranged around a bad fetch '
      + 'being harmless.' }),
    el('p', { class: 'hint', text: 'TCP only, deliberately: a false positive on a UDP game port would drop a player mid-match, where on TCP it is a '
      + 'connection that does not open. Scoped to the public interface like the protection rules, so it can never see a probe or the control channel. It '
      + 'cannot lock you out of this portal either - the portal is on the admin WireGuard tunnel, over UDP, and no rule here is consulted for it.' }),
    el('p', { class: 'hint', text: 'It works with everything above switched off. Its rules live in a table of their own, so refreshing the list never '
      + 'resets a protection counter, unparks a blocked source or releases an engaged region lock.' }),
    el('div', {}, checkbox('Enabled', c.blocklist.enabled, (v) => (c.blocklist.enabled = v),
      'Takes effect when armed: this rule drops packets, so observe mode installs nothing. Needs the public interface set above, for the same reason '
      + 'protection does. The first fetch happens within a minute of saving; until it lands the rules are loaded and drop nothing. The last good list is '
      + 'kept on disk, so a restart while the feed is unreachable still comes up protected.')),
    el('div', { class: 'grid' },
      // A floor of 0 rather than validate's 1, because 0 is not a cadence
      // here: it is "use the default", which validate accepts and every other
      // "0 = default" box on this form spells the same way. Clamped to 1 it
      // silently stored an hourly poll of somebody else's host.
      num('Refresh interval (hours)', c.blocklist.refresh_hours || '', (v) => (c.blocklist.refresh_hours = v || 0), {
        min: 0, max: 168, placeholder: 'empty = 4',
        help: 'How often the feed is re-fetched. The request is conditional, so an unchanged feed costs almost nothing and this can be short. The feed '
          + 'itself republishes about once a day. Between 1 and 168 hours; 0 or an empty box means the default 4. A failed fetch is retried sooner than this '
          + 'on its own, and never empties the loaded list.',
      }),
    ),
    (() => {
      // One network per line, the same shape a region list takes, because
      // the thing an operator does here is paste one address they have just
      // found in the feed.
      const ta = el('textarea', { rows: 3, placeholder: '203.0.113.7\n198.51.100.0/24' });
      ta.value = (c.blocklist.exceptions || []).join('\n');
      const parseTA = debounce(() => {
        c.blocklist.exceptions = ta.value.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean);
        updateDirty();
      }, 400);
      ta.addEventListener('input', parseTA.run);
      ta.addEventListener('change', parseTA.flush);
      return el('div', {},
        el('label', { class: 'field' }, caption('Exceptions', 'Networks that are never dropped, checked before the feed. A bare address is taken as a /32. '
          + 'This is the override for the failure this feature produces, which is silent: a listed source is a visitor who cannot connect, with nothing on '
          + 'the box saying why. If you find yourself adding more than a handful, the feed disagrees with your traffic and the switch above is the answer '
          + 'rather than this box.'), ta),
        el('p', { class: 'hint', text: 'One network per line. Changing these reloads the blocklist table, which resets its drop counter and reloads the list into it.' }));
    })(),
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
  const linkerRefresh = debounce(() => { renderServices(); renderEgress(); }, 400);
  const linkersChanged = () => {
    renderLinkerConfigs();
    linkerRefresh.run();
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

  // The file input is hidden and driven by the button beside it: a bare
  // <input type=file> cannot be styled to match anything else on this page,
  // and the button is where the explanation of what an import does belongs.
  const importInput = el('input', { type: 'file', accept: 'application/json,.json', class: 'hidden' });
  importInput.addEventListener('change', () => {
    const file = importInput.files && importInput.files[0];
    // Cleared before the read rather than after it, so choosing the same file
    // twice fires change the second time; the File is a handle of its own and
    // stays readable once the input has let go of it.
    importInput.value = '';
    if (file) importConfig(file);
  });
  // Its events stop here rather than bubbling into the form. Choosing a file
  // fires a bubbling `input` before `change`, and the form reads any `input`
  // as an edit: every import then asked to discard changes nobody had made,
  // which is how an operator learns to click through the one guard standing
  // between them and half an hour of unsaved typing. The relayed click from
  // the button below bubbles for the same reason, and that one ran the full
  // config walk and all three banner scans twice, undebounced, before the
  // picker had opened.
  for (const evt of ['input', 'change', 'click']) {
    importInput.addEventListener(evt, (e) => e.stopPropagation());
  }
  form.append(section('Backup and restore',
    el('div', { class: 'row' },
      el('button', { class: 'btn', type: 'button', onclick: exportConfig }, 'Export configuration'),
      help('Downloads everything on this form as one JSON file: paths, published services, protection with its region lists, '
        + 'the query cache, linkers, egress networks and notifications. It is the configuration itself rather than a summary of it, '
        + 'so importing it back puts the same system back rather than a reconstruction of it. It goes through the same checks a save does '
        + 'on the way in, so a file written by an older build comes back with whatever that build never wrote filled in. What is written '
        + 'is what is on the form, including anything typed since the last save.'),
      el('button', { id: 'import-config', class: 'btn', type: 'button', onclick: () => { if (!importing) importInput.click(); } }, 'Import configuration'),
      help('Reads a file back into this form and applies nothing. Check it over and press Save configuration, which is the point at which '
        + 'anything changes on either host. A file the frontend refuses is reported with the same message a save would have refused it with, '
        + 'and leaves the form alone. A file written by a newer build is refused by the name of the first setting this one has never heard of, '
        + 'rather than loaded with that setting quietly dropped.'),
      importInput,
    ),
    el('p', { class: 'hint', text: 'Four things in the file are ignored on import, and this host keeps its own. '
      + 'Overlay addressing comes from the bootstrap file on both hosts and cannot be changed from here at all. The mode belongs to the dashboard, '
      + 'so importing a file taken from an armed host does not arm this one. The public interface and public IP in the Frontend section stay as well: '
      + 'they are what this box calls its NIC rather than settings that travel, and a name belonging to another box is an nftables table that matches nothing, '
      + 'which reads as every published service being down while the configuration looks saved. Backend egress does travel, because that one is a routing decision.' }),
    el('p', { class: 'hint', text: 'The shared secret is not in the file, because it lives in the bootstrap file rather than in the configuration. '
      + 'The notification token is, in the clear, along with every region list and every published port. Treat the file the way you would treat a copy of this page.' }),
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

// ---------------------------------------------------------------------------
// Export and import
//
// One file, the whole configuration blob in the shape GET /api/config serves
// and Save PUTs back, so a restore is the same configuration and not a
// reconstruction of it. Paths, published services, protection with its region
// lists, the query cache, linkers, egress networks, notifications.
//
// Four fields deliberately do not travel, and the frontend is what discards
// them rather than this file: overlay addressing is bootstrap-owned on both
// hosts, the mode belongs to the dashboard, and the public interface and the
// address on it describe the box being imported into rather than the
// deployment. See handleCheckConfig.
//
// What comes back from the import is the file after everything a save would
// do to it, which is not always the file: an older build's export is missing
// fields this one fills in. The badge lights accordingly.
// ---------------------------------------------------------------------------

// Mirrors web.maxConfigBytes, which bounds the same bytes at the far end.
// Checked here so a mispicked file is refused before it is read rather than
// after: this page cannot ask the frontend about a file it has not sent, and
// reading first is a limit on memory already committed.
const MAX_CONFIG_BYTES = 32 << 20;

// The button only exists on a rendered form, and renderSettings cannot run
// without a configuration, so there is nothing here to guard against a null
// one. What is written is what is on the form, not what is stored, because
// that is what the operator is looking at - and the unsaved badge beside the
// Save button is already saying which of the two this is.
function exportConfig() {
  // Stamped in local time rather than toISOString's UTC. The stamp is the only
  // thing telling two backups apart in a folder, and a backup taken at eight in
  // the morning in Melbourne was filed under the previous day, so "the one from
  // this morning" picked the wrong file.
  const d = new Date();
  const two = (n) => String(n).padStart(2, '0');
  const stamp = `${d.getFullYear()}-${two(d.getMonth() + 1)}-${two(d.getDate())}-${two(d.getHours())}${two(d.getMinutes())}${two(d.getSeconds())}`;
  // Compact rather than indented. Indenting is about 1.7x, which carries a
  // region-heavy export past maxConfigBytes: the file this button writes has
  // to fit back through the endpoint that reads it, which is the same ordering
  // geoFetchMaxTotal < maxRegionsBytes < maxConfigBytes exists for. It is also
  // what lets an import post the file's own bytes instead of a re-rendering
  // of them.
  const url = URL.createObjectURL(new Blob([`${JSON.stringify(config)}\n`], { type: 'application/json' }));
  const a = el('a', { href: url, download: `homeport-config-${stamp}.json` });
  document.body.append(a);
  try {
    a.click();
  } finally {
    a.remove();
    // Revoked well after the click rather than on the next turn: the click is
    // dispatched synchronously but the read of the blob behind it is not, and
    // revoking while that is outstanding cancels the download with no error
    // anywhere. In a finally because the alternative to revoking late is
    // pinning the whole configuration, notification token included, in memory
    // for the life of the tab.
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  }
}

// importConfig fills the form and applies nothing. Deliberately, for the
// reason the geo fetch fills the form rather than the configuration: this
// arrives from outside, and what it decides is every published port, every
// limit and every region lock on a live system. It goes through the operator's
// eyes and then through Save like anything typed.
//
// The file is checked by the frontend rather than here. A file written by an
// older build is missing whatever has been added since, exactly as an older
// stored blob is, and model.Normalise is what repairs that - on the host, in
// one copy. Binding this form straight to a parsed file would mean a second
// copy of that repair in the browser, and the failure when it drifted is a row
// builder reaching into a structure the file never carried.
async function importConfig(file) {
  try {
    if (settingsDirty && !confirm(`Discard the unsaved changes on this form and load ${file.name}?`)) return;
    // Bounded before it is read, not after. `accept` is a hint and every
    // picker offers All Files, so the disk image sitting beside the backup is
    // one mis-click away, and reading it stringifies the whole thing in this
    // tab - with the parse beside it - before the frontend's own bound could
    // refuse it, on the page somebody opens when all three tunnels are down.
    if (file.size > MAX_CONFIG_BYTES) {
      throw new Error(`${file.name} is ${Math.round(file.size / (1 << 20))} MB; a configuration file cannot be larger than ${MAX_CONFIG_BYTES >> 20} MB`);
    }
    importing = true;
    const btn = document.getElementById('import-config');
    if (btn) btn.disabled = true;
    const text = await file.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new Error(`${file.name} is not JSON: ${e.message}`);
    }
    // Parsed for the shape alone, and the bytes rather than the parse are what
    // goes up. An array or a bare string decodes into model.Config as an error
    // the endpoint would report as "invalid configuration", which reads as
    // though the settings inside it were wrong rather than the file being the
    // wrong thing entirely. Posting `text` is what makes the host validate
    // what is actually on disk: re-serialising the parse would quietly round
    // any number JSON.parse cannot hold exactly, and inflate a large file for
    // no reason.
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(`${file.name} does not hold a configuration object`);
    }
    const checked = await api('/api/config/check', { method: 'POST', body: text });
    // Committed only once it has rendered. renderSettings empties the form as
    // its first statement and appends section by section, so a throw partway
    // through leaves half a form bound to a configuration nothing else knows
    // about - and a throw landing after the save bar leaves a Save that posts
    // a configuration the operator was never shown in full.
    const previous = config;
    config = checked;
    try {
      renderSettings();
    } catch (e) {
      config = previous;
      renderSettings();
      throw new Error(`${file.name} could not be displayed (${e.message}); the form is unchanged`);
    }
    // savedConfig is left where it is, so the badge lights and the tab is
    // marked: until it is saved an import is an edit like any other, and
    // Discard changes still puts the running configuration back.
    updateDirty();
    updateWarnings();
    toast(`Loaded ${file.name}. Nothing has been applied yet: review it, then Save configuration.`);
  } catch (e) {
    toast(e.message, true);
  } finally {
    importing = false;
    // Re-queried rather than held: a successful import has rebuilt the form,
    // so the button locked above is no longer the one on the page.
    const live = document.getElementById('import-config');
    if (live) live.disabled = false;
  }
}

async function loadSettings() {
  try {
    // A missing preset list is not fatal, but it must not be silent: the
    // dropdown would otherwise offer only Custom under a caption that
    // promises choices, and show the shipped numbers as Custom. The failures
    // are collected into one toast rather than raised from each catch,
    // because toast() replaces whatever is showing: both lists fail together
    // in the realistic case (the same network blip takes both requests), and
    // two toasts racing would leave whichever ran second on screen with the
    // other failure unreported.
    const missing = [];
    [config, presets, protectPresets] = await Promise.all([
      api('/api/config'),
      api('/api/presets').catch((e) => { missing.push(`detection: ${e.message}`); return []; }),
      api('/api/protect-presets').catch((e) => { missing.push(`per-source: ${e.message}`); return []; }),
    ]);
    if (missing.length) toast(`Preset lists unavailable (${missing.join('; ')}); their dropdowns offer only Custom`, true);
    renderSettings();
    markSaved();
    // The form events keep them live from here; this covers a config loaded
    // already carrying either mismatch.
    updateWarnings();
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
