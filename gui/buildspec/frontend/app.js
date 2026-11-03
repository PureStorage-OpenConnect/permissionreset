import { api, isMock, onSessionLost, onBusy } from './api.js';

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------

const state = {
  caps: { os: '', kernelTransport: true, credentialFromProcess: true, version: '' },
  session: { connected: false, root: '', transport: '', warnings: [], lostReason: '' },
  rail: {
    server: '192.0.2.50',
    export: '/data',
    mountPath: '/mnt/fb',
    transport: 'userspace',
    uid: '',
    gid: '',
    gids: '',
    rpcTimeoutMs: 30000,
    retryBudget: 5,
    retryBaseMs: 100,
    advancedOpen: false,
    exportCustom: false,
  },
  exports: { list: [], supported: false },
  tree: { nodes: {} }, // path -> {entries, truncated, expanded, loaded}
  marks: { dir: null, file: null },
  filter: '',
  result: null, // {yaml, dirAces, fileAces, dirSacl, fileSacl, hasSacl, keepsDacl, notes, identity}
  error: null, // Error
  busy: '',
  verify: { enabled: false, scratch: '', picking: false },
  withDacl: false, // build-spec --with-dacl
  acceptUnproven: false, // build-spec --accept-unproven-read
  plan: null, // {specPath, json, rules, refused} from build-spec --sacl-plan
  outputName: 'permissionreset-spec.yaml',
};

// ---------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------

function el(tag, props, children) {
  const node = document.createElement(tag);
  props = props || {};
  for (const key in props) {
    if (key === 'class') node.className = props[key];
    else if (key === 'html') node.innerHTML = props[key]; // only used for trusted inline svg use-refs
    else if (key.slice(0, 2) === 'on') node.addEventListener(key.slice(2), props[key]);
    else if (key === 'value' && (tag === 'input' || tag === 'select')) node.value = props[key];
    else if (key === 'checked') node.checked = props[key];
    else if (key === 'disabled') node.disabled = props[key];
    else node.setAttribute(key, props[key]);
  }
  (children || []).forEach((c) => {
    if (c === null || c === undefined) return;
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  });
  return node;
}

function icon(name, size) {
  size = size || 14;
  const span = document.createElement('span');
  span.className = 'svgicon';
  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('viewBox', '0 0 24 24');
  const use = document.createElementNS(svgNS, 'use');
  use.setAttributeNS('http://www.w3.org/1999/xlink', 'href', '#i-' + name);
  use.setAttribute('href', '#i-' + name);
  svg.appendChild(use);
  span.appendChild(svg);
  return span;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function mount(id, children) {
  const node = document.getElementById(id);
  clear(node);
  children.forEach((c) => c && node.appendChild(c));
}

// ---------------------------------------------------------------------
// Derived helpers
// ---------------------------------------------------------------------

function identityReady() {
  if (state.caps.credentialFromProcess) return true;
  return state.rail.uid !== '' && state.rail.gid !== '' && !isNaN(Number(state.rail.uid)) && !isNaN(Number(state.rail.gid));
}

function connectDisabled() {
  if (state.rail.transport === 'kernel' && !state.rail.mountPath) return true;
  if (state.rail.transport === 'userspace' && (!state.rail.server || !state.rail.export)) return true;
  if (!identityReady()) return true;
  return false;
}

function runDisabled() {
  if (!state.session.connected) return true;
  if (!state.marks.dir || !state.marks.file) return true;
  if (state.verify.enabled && (!state.verify.scratch || scratchCollides())) return true;
  if (state.busy) return true;
  return false;
}

// The backend rejects a scratch directory that is also one of the exemplars,
// which a tree pick makes easy to land on.
function scratchCollides() {
  const p = state.verify.scratch;
  return !!p && (p === state.marks.dir || p === state.marks.file);
}

function classifyError(err) {
  const msg = err ? String(err.message || err) : '';
  if (/4\.1|minorversion/.test(msg)) return 'mount';
  if (/reversed|is a directory|is not a directory/.test(msg)) return 'reversed';
  if (/cannot be replayed|replayable|identity/.test(msg)) return 'replay';
  return 'other';
}

// ---------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------

function setState(patch) {
  Object.assign(state, patch);
  render(state);
}

async function loadCapabilities() {
  try {
    const caps = await api.capabilities();
    state.caps = caps;
    if (!caps.kernelTransport && state.rail.transport === 'kernel') state.rail.transport = 'userspace';
    render(state);
  } catch (e) {
    render(state);
  }
}

async function loadExports() {
  try {
    const res = await api.exports();
    state.exports = { list: res.exports || [], supported: !!res.supported };
    render(state);
  } catch (e) {
    // non-fatal
  }
}

async function doConnect() {
  state.error = null;
  const req = {
    transport: state.rail.transport,
    server: state.rail.server,
    export: state.rail.export,
    mountPath: state.rail.mountPath,
    authUid: state.rail.uid === '' ? -1 : Number(state.rail.uid),
    authGid: state.rail.gid === '' ? -1 : Number(state.rail.gid),
    authGids: state.rail.gids,
    rpcTimeoutMs: Number(state.rail.rpcTimeoutMs),
    retryBudget: Number(state.rail.retryBudget),
    retryBaseMs: Number(state.rail.retryBaseMs),
  };
  try {
    const res = await api.connect(req);
    state.session = {
      connected: true,
      root: res.root,
      transport: state.rail.transport,
      warnings: res.warnings || [],
      lostReason: '',
    };
    state.tree = { nodes: {} };
    state.marks = { dir: null, file: null };
    state.result = null;
    render(state);
    await loadDir(res.root, true);
  } catch (e) {
    state.error = e;
    render(state);
  }
}

async function doDisconnect() {
  try {
    await api.disconnect();
  } catch (e) {
    // ignore
  }
  state.session = { connected: false, root: '', transport: '', warnings: [], lostReason: '' };
  state.tree = { nodes: {} };
  state.marks = { dir: null, file: null };
  state.result = null;
  state.error = null;
  render(state);
}

async function loadDir(path, expand) {
  try {
    const res = await api.listDir(path, 500);
    state.tree.nodes[path] = {
      entries: res.entries || [],
      truncated: !!res.truncated,
      expanded: expand !== undefined ? expand : (state.tree.nodes[path] ? state.tree.nodes[path].expanded : true),
      loaded: true,
    };
    render(state);
  } catch (e) {
    state.error = e;
    render(state);
  }
}

function toggleExpand(path) {
  const node = state.tree.nodes[path];
  if (!node) {
    state.tree.nodes[path] = { entries: [], truncated: false, expanded: true, loaded: false };
    render(state);
    loadDir(path, true);
    return;
  }
  node.expanded = !node.expanded;
  if (node.expanded && !node.loaded) {
    render(state);
    loadDir(path, true);
    return;
  }
  render(state);
}

async function refreshTree() {
  const paths = Object.keys(state.tree.nodes).filter((p) => state.tree.nodes[p].expanded);
  for (const p of paths) {
    await loadDir(p, true);
  }
}

function mark(kind, path) {
  const next = { ...state.marks };
  const toggled = next[kind] === path ? null : path;
  if (next[kind] === toggled) return;
  next[kind] = toggled;
  state.marks = next;
  state.result = null;
  state.error = null;
  render(state);
}

async function doRun() {
  if (runDisabled()) return;
  state.error = null;
  try {
    const res = state.verify.enabled
      ? await api.verify(state.verify.scratch, state.marks.dir, state.marks.file, state.withDacl)
      : await api.capture(state.marks.dir, state.marks.file, state.withDacl, state.acceptUnproven);
    state.result = res;
    state.plan = null;
    render(state);
  } catch (e) {
    state.result = null;
    state.plan = null;
    state.error = e;
    render(state);
  }
}

async function doChooseScratch() {
  try {
    const res = await api.chooseScratch();
    if (res && res.path) {
      applyScratch(res.path);
      render(state);
    }
  } catch (e) {
    // ignore
  }
}

// A result carries the verdict of a replay through one specific scratch
// directory, so changing that directory invalidates it the same way changing
// an exemplar does.
function applyScratch(path) {
  if (state.verify.scratch === path) return;
  state.verify.scratch = path;
  state.result = null;
  state.error = null;
}

// The replay verdict a result carries is only meaningful for the mode that
// produced it, and the footer's CLI line gains or loses --verify-write with
// this switch, so the two must not be left disagreeing.
function toggleVerify() {
  state.verify.enabled = !state.verify.enabled;
  if (!state.verify.enabled) state.verify.picking = false;
  state.result = null;
  state.error = null;
}

// --with-dacl changes the YAML a capture emits whenever the exemplars carry
// audit ACEs, so a result taken under the other setting is stale.
function toggleWithDacl() {
  state.withDacl = !state.withDacl;
  state.result = null;
  state.error = null;
}

// The SACL plan is build-spec --sacl-plan: it reads a spec file chosen here,
// not the exemplars, and needs no session.
async function doSaclPlan() {
  state.error = null;
  try {
    const res = await api.saclPlan();
    if (res && res.specPath) {
      state.plan = res;
      state.savedPath = '';
    }
    render(state);
  } catch (e) {
    state.plan = null;
    state.error = e;
    render(state);
  }
}

async function doSavePlan() {
  if (!state.plan) return;
  try {
    const name = state.plan.specPath.split(/[\\/]/).pop().replace(/\.ya?ml$/i, '') + '-plan.json';
    const res = await api.savePlan(state.plan.json, name);
    if (res && res.path) {
      state.savedPath = res.path;
      render(state);
    }
  } catch (e) {
    state.error = e;
    render(state);
  }
}

function setScratch(path) {
  applyScratch(state.verify.scratch === path ? '' : path);
  state.verify.picking = false;
  render(state);
}

async function doSave() {
  if (!state.result) return;
  try {
    const res = await api.saveSpec(state.result.yaml, state.outputName);
    if (res && res.path) {
      state.savedPath = res.path;
      render(state);
    }
  } catch (e) {
    state.error = e;
    render(state);
  }
}

function doCopy() {
  const text = state.plan ? state.plan.json : state.result ? state.result.yaml : '';
  if (!text) return;
  navigator.clipboard && navigator.clipboard.writeText(text).catch(() => {});
  state.copied = true;
  render(state);
  setTimeout(() => {
    state.copied = false;
    render(state);
  }, 1400);
}

function applyErrorFix(kind) {
  if (kind === 'mount') {
    state.rail.transport = 'userspace';
    state.error = null;
  } else if (kind === 'reversed') {
    state.marks = { ...state.marks, file: null };
    state.error = null;
  }
  render(state);
}

onSessionLost((reason) => {
  state.session = { connected: false, root: '', transport: '', warnings: [], lostReason: reason || 'unknown' };
  state.tree = { nodes: {} };
  state.marks = { dir: null, file: null };
  state.result = null;
  state.error = null;
  render(state);
});

onBusy((phase) => {
  state.busy = phase || '';
  render(state);
});

// ---------------------------------------------------------------------
// Render: titlebar
// ---------------------------------------------------------------------

function renderTitlebar(s) {
  return [
    el('span', { class: 'titlebar__name' }, ['build-spec']),
    el('span', { class: 'titlebar__tagline' }, ['— capture a permissionreset spec from two exemplars']),
    el('span', { class: 'titlebar__spacer' }, []),
    el('button', {
      class: 'btn btn--ghost btn--sm titlebar__action',
      title: 'build-spec --sacl-plan: turn a permissionreset spec into the JSON plan Set-SaclOnly -Plan reads',
      disabled: !!s.busy,
      onclick: doSaclPlan,
    }, [icon('file', 12), document.createTextNode('SACL plan from spec…')]),
    el('span', { class: 'titlebar__version' }, [s.caps.version ? 'v' + s.caps.version.replace(/^v/, '') : (isMock ? 'mock' : '')]),
  ];
}

// ---------------------------------------------------------------------
// Render: rail
// ---------------------------------------------------------------------

function renderRail(s) {
  const out = [];

  if (s.session.lostReason) {
    out.push(
      el('div', { class: 'rail-notice' }, [
        el('strong', {}, ['Session lost']),
        el('span', {}, [': ' + s.session.lostReason + '. Reconnect to continue.']),
      ])
    );
  }

  out.push(
    el('div', { style: 'display:flex;flex-direction:column;gap:11px' }, [
      el('div', { style: 'display:flex;align-items:center;justify-content:space-between' }, [
        el('span', { class: 'ep-eyebrow' }, ['Connection']),
        el('span', { class: 'session-dot' + (s.session.connected ? ' is-connected' : '') }, [
          el('span', { class: 'session-dot__led' }, []),
          document.createTextNode('NFSv4.1 session'),
        ]),
      ]),
      renderTransportField(s),
      s.rail.transport === 'kernel' ? renderMountField(s) : renderServerExportFields(s),
    ])
  );

  out.push(el('div', { class: 'hr' }, []));

  out.push(
    el('div', { style: 'display:flex;flex-direction:column;gap:11px' }, [
      el('div', { style: 'display:flex;align-items:center;justify-content:space-between' }, [
        el('span', { class: 'ep-eyebrow' }, ['Identity — AUTH_SYS']),
        el('span', { style: 'font-size:10px;color:var(--ep-walnut)' }, [s.caps.credentialFromProcess ? 'optional' : 'required']),
      ]),
      el('div', { class: 'row-2' }, [
        el('label', { class: 'field' }, [
          el('span', { class: 'field__label' }, ['uid']),
          el('span', { class: 'field__input-row' }, [
            el('input', {
              value: s.rail.uid,
              placeholder: s.caps.credentialFromProcess ? 'process default' : '',
              'data-focus': 'rail.uid',
              oninput: (e) => { state.rail.uid = e.target.value; render(state); },
            }),
          ]),
        ]),
        el('label', { class: 'field' }, [
          el('span', { class: 'field__label' }, ['gid']),
          el('span', { class: 'field__input-row' }, [
            el('input', {
              value: s.rail.gid,
              placeholder: s.caps.credentialFromProcess ? 'process default' : '',
              'data-focus': 'rail.gid',
              oninput: (e) => { state.rail.gid = e.target.value; render(state); },
            }),
          ]),
        ]),
      ]),
      el('label', { class: 'field' }, [
        el('span', { class: 'field__label' }, ['Auxiliary gids']),
        el('span', { class: 'field__input-row' }, [
          el('input', {
            value: s.rail.gids,
            placeholder: '10000,10020',
            'data-focus': 'rail.gids',
            oninput: (e) => { state.rail.gids = e.target.value; render(state); },
          }),
        ]),
      ]),
      el('p', { class: 'hint' }, ['These authorize the read. They are the client credential — never written into the spec.']),
    ])
  );

  out.push(el('div', { class: 'hr' }, []));

  out.push(renderAdvanced(s));

  out.push(el('div', { class: 'hr' }, []));

  out.push(
    el('div', { style: 'display:flex;gap:8px' }, [
      s.session.connected
        ? el('button', { class: 'btn btn--secondary', style: 'flex:1;height:36px', onclick: doDisconnect }, ['Disconnect'])
        : el('button', {
            class: 'btn btn--primary',
            style: 'flex:1;height:36px',
            disabled: connectDisabled(),
            onclick: doConnect,
          }, [s.busy === 'connecting' ? el('span', { class: 'spinner' }, []) : null, document.createTextNode(s.busy === 'connecting' ? 'Connecting…' : 'Connect')]),
    ])
  );

  return out;
}

function renderTransportField(s) {
  const kernelAllowed = s.caps.kernelTransport;
  return el('div', { style: 'display:flex;flex-direction:column;gap:9px' }, [
    el('span', { class: 'ep-eyebrow' }, ['Transport']),
    el('div', { class: 'pillgroup' }, [
      el('button', {
        class: s.rail.transport === 'userspace' ? 'is-active' : '',
        disabled: s.session.connected,
        onclick: () => { state.rail.transport = 'userspace'; render(state); },
      }, ['userspace']),
      kernelAllowed
        ? el('button', {
            class: s.rail.transport === 'kernel' ? 'is-active' : '',
            disabled: s.session.connected,
            onclick: () => { state.rail.transport = 'kernel'; render(state); },
          }, ['kernel'])
        : null,
    ]),
    el('p', { class: 'hint' }, [
      s.rail.transport === 'kernel'
        ? 'Reads system.nfs4_acl from a mounted export. Linux only, and the mount must be vers=4.1.'
        : 'Talks NFSv4.1 straight to FlashBlade with AUTH_SYS. No mount needed — the default on macOS and Windows.',
    ]),
  ]);
}

function renderMountField(s) {
  return el('label', { class: 'field' }, [
    el('span', { class: 'field__label' }, ['Mount point']),
    el('span', { class: 'field__input-row' }, [
      el('input', {
        value: s.rail.mountPath,
        disabled: s.session.connected,
        'data-focus': 'rail.mountPath',
        oninput: (e) => { state.rail.mountPath = e.target.value; render(state); },
      }),
    ]),
  ]);
}

function renderServerExportFields(s) {
  const exportField = s.exports.supported
    ? renderExportSelect(s)
    : el('label', { class: 'field' }, [
        el('span', { class: 'field__label' }, ['Export']),
        el('span', { class: 'field__input-row' }, [
          el('input', {
            value: s.rail.export,
            placeholder: '/data',
            disabled: s.session.connected,
            'data-focus': 'rail.export',
            oninput: (e) => { state.rail.export = e.target.value; render(state); },
          }),
        ]),
      ]);

  return el('div', { style: 'display:flex;flex-direction:column;gap:11px' }, [
    el('label', { class: 'field' }, [
      el('span', { class: 'field__label' }, ['Server']),
      el('span', { class: 'field__input-row' }, [
        el('input', {
          value: s.rail.server,
          disabled: s.session.connected,
          'data-focus': 'rail.server',
          oninput: (e) => { state.rail.server = e.target.value; render(state); },
        }),
      ]),
    ]),
    exportField,
  ]);
}

function renderExportSelect(s) {
  if (s.rail.exportCustom) {
    return el('label', { class: 'field' }, [
      el('span', { class: 'field__label' }, ['Export']),
      el('span', { class: 'field__input-row' }, [
        el('input', {
          value: s.rail.export,
          placeholder: '/data',
          disabled: s.session.connected,
          'data-focus': 'rail.export',
          oninput: (e) => { state.rail.export = e.target.value; render(state); },
        }),
        el('button', {
          class: 'btn btn--ghost btn--sm',
          disabled: s.session.connected,
          onclick: () => { state.rail.exportCustom = false; render(state); },
        }, ['list']),
      ]),
    ]);
  }
  const options = s.exports.list.map((p) =>
    el('option', { value: p }, [p])
  );
  const select = el('select', {
    value: s.exports.list.indexOf(s.rail.export) >= 0 ? s.rail.export : '',
    disabled: s.session.connected,
    onchange: (e) => {
      if (e.target.value === '__custom__') {
        state.rail.exportCustom = true;
      } else {
        state.rail.export = e.target.value;
      }
      render(state);
    },
  }, [
    el('option', { value: '' }, ['— choose —']),
    ...options,
    el('option', { value: '__custom__' }, ['Custom…']),
  ]);
  select.value = s.exports.list.indexOf(s.rail.export) >= 0 ? s.rail.export : '';
  return el('label', { class: 'field' }, [
    el('span', { class: 'field__label' }, ['Export']),
    el('span', { class: 'field__input-row' }, [select]),
  ]);
}

function renderAdvanced(s) {
  const chev = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  chev.setAttribute('width', '12');
  chev.setAttribute('height', '12');
  chev.setAttribute('viewBox', '0 0 24 24');
  chev.setAttribute('class', 'advtoggle__chev' + (s.rail.advancedOpen ? ' is-open' : ''));
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#i-chev-r');
  chev.appendChild(use);

  const children = [
    el('button', { class: 'advtoggle', onclick: () => { state.rail.advancedOpen = !state.rail.advancedOpen; render(state); } }, [
      chev,
      document.createTextNode('Advanced'),
    ]),
  ];
  if (s.rail.advancedOpen) {
    children.push(
      el('div', { class: 'advpanel' }, [
        el('label', {}, [
          document.createTextNode('rpc-timeout (ms)'),
          el('input', { value: String(s.rail.rpcTimeoutMs), 'data-focus': 'rail.rpcTimeoutMs', oninput: (e) => { state.rail.rpcTimeoutMs = e.target.value; render(state); } }),
        ]),
        el('label', {}, [
          document.createTextNode('retry-budget'),
          el('input', { value: String(s.rail.retryBudget), 'data-focus': 'rail.retryBudget', oninput: (e) => { state.rail.retryBudget = e.target.value; render(state); } }),
        ]),
        el('label', {}, [
          document.createTextNode('retry-base-delay (ms)'),
          el('input', { value: String(s.rail.retryBaseMs), 'data-focus': 'rail.retryBaseMs', oninput: (e) => { state.rail.retryBaseMs = e.target.value; render(state); } }),
        ]),
      ])
    );
  }
  return el('div', { style: 'display:flex;flex-direction:column;gap:9px' }, children);
}

// ---------------------------------------------------------------------
// Render: explorer
// ---------------------------------------------------------------------

function matchesFilter(name) {
  if (!state.filter) return true;
  return name.toLowerCase().indexOf(state.filter.toLowerCase()) >= 0;
}

function renderExplorer(s) {
  const picking = s.verify.enabled && s.verify.picking;
  const head = el('div', { class: 'explorer__head' }, [
    el('div', { class: 'explorer__title-row' }, [
      el('div', { style: 'display:flex;flex-direction:column;gap:4px' }, [
        el('span', { class: 'ep-eyebrow' }, [picking ? 'Choosing scratch directory' : 'Step 2 — mark two exemplars']),
        el('h1', { class: 'explorer__title' }, [picking ? 'Click a folder to hold the probes' : 'Pick one folder and one file']),
      ]),
      el('div', { class: 'explorer__tools' }, [
        el('span', { class: 'filterbox' }, [
          icon('search', 13),
          el('input', {
            placeholder: 'Filter this folder',
            value: s.filter,
            'data-focus': 'filter',
            oninput: (e) => { state.filter = e.target.value; render(state); },
          }),
        ]),
        el('button', { class: 'iconbtn', title: 'Refresh', onclick: refreshTree }, [icon('refresh', 14)]),
      ]),
    ]),
    el('p', { class: 'explorer__blurb' }, [
      picking
        ? 'Two probe objects are written into the folder you pick, read back, then removed. Pick a folder you can write to — it must not be either exemplar.'
        : "build-spec reads the ACL from these two objects only — nothing is scanned, nothing is changed. The folder's ACL becomes the rule for every directory; the file's ACL becomes the rule for every file.",
    ]),
    picking
      ? el('div', { class: 'pickbar' }, [
          el('span', { class: 'pickbar__text' }, [s.verify.scratch || 'No scratch folder chosen yet']),
          el('button', { class: 'btn btn--ghost btn--sm', onclick: () => { state.verify.picking = false; render(state); } }, ['Cancel']),
        ])
      : el('div', { class: 'slots' }, [
          renderSlot('dir', s),
          renderSlot('file', s),
        ]),
    renderBreadcrumb(s),
  ]);

  const treeEl = el('div', { class: 'tree' }, renderTreeRows(s));

  return [head, treeEl];
}

function renderSlot(kind, s) {
  const path = s.marks[kind];
  const bad = kind === 'file' && s.error && classifyError(s.error) === 'reversed';
  const cls = 'slot' + (path ? ' is-filled' : '') + (bad ? ' is-bad' : '');
  return el('div', { class: cls }, [
    el('div', { class: 'slot__label' }, [
      icon(kind === 'dir' ? 'folder' : 'file', 15),
      document.createTextNode(kind === 'dir' ? 'Directory exemplar' : 'File exemplar'),
    ]),
    el('span', { class: 'slot__path' }, [path || (kind === 'dir' ? 'Click a folder in the tree' : 'Click a file in the tree')]),
  ]);
}

function renderBreadcrumb(s) {
  const root = s.session.root || '';
  const parts = root.split('/').filter(Boolean);
  const items = [document.createTextNode(s.rail.server || '')];
  parts.forEach((p) => {
    items.push(el('span', { style: 'opacity:.5' }, ['/']));
    items.push(el('b', {}, [p]));
  });
  return el('div', { class: 'breadcrumb' }, items);
}

function renderTreeRows(s) {
  const root = s.session.root;
  if (!root) {
    return [el('div', { style: 'padding:20px;color:var(--ep-walnut);font-size:12.5px' }, ['Connect to browse the export.'])];
  }
  const rows = [];
  function walk(path, depth) {
    const node = state.tree.nodes[path];
    if (!node) return;
    let visible = node.entries;
    const anyFilter = !!state.filter;
    if (anyFilter) visible = visible.filter((e) => matchesFilter(e.name));
    if (node.truncated) {
      rows.push(
        el('div', { class: 'filter-notice', style: 'padding-left:' + (10 + depth * 20) + 'px' }, [
          'Showing first ' + node.entries.length + ' entries; type to filter',
        ])
      );
    }
    visible.forEach((entry) => {
      const childPath = (path === '/' ? '' : path) + '/' + entry.name;
      const excluded = entry.name === '.snapshot';
      const picking = s.verify.enabled && s.verify.picking;
      const selectable = !excluded && !entry.isSymlink && (!picking || entry.isDir);
      const isScratch = s.verify.enabled && s.verify.scratch === childPath;
      const markedKind = s.marks.dir === childPath ? 'dir' : s.marks.file === childPath ? 'file' : null;
      const bad = markedKind === 'file' && s.error && classifyError(s.error) === 'reversed';
      const rowCls = ['row'];
      if ((markedKind || isScratch) && !bad) rowCls.push('is-marked');
      if (isScratch) rowCls.push('is-scratch');
      if (bad) rowCls.push('is-bad');
      if (excluded) rowCls.push('is-excluded');
      if (entry.isSymlink) rowCls.push('is-symlink');
      if (picking && !selectable) rowCls.push('is-excluded');

      const childNode = state.tree.nodes[childPath];
      const expanded = !!(childNode && childNode.expanded);

      const twisty = entry.isDir
        ? el('button', {
            class: 'row__twisty',
            onclick: (e) => { e.stopPropagation(); toggleExpand(childPath); },
          }, [icon(expanded ? 'chev-d' : 'chev-r', 12)])
        : el('span', { class: 'row__twisty is-hidden' }, []);

      const checked = markedKind || isScratch;
      const check = el('span', { class: 'row__check' + (checked ? (bad ? ' is-bad' : ' is-marked') : '') + (selectable ? '' : ' is-hidden') },
        checked ? [icon('check', 11)] : []);

      let tag = excluded ? 'excluded by default' : entry.isSymlink ? 'symlink' : entry.isDir ? 'directory' : 'file';
      if (markedKind === 'dir') tag = 'directory exemplar';
      if (markedKind === 'file') tag = bad ? 'not a file' : 'file exemplar';
      if (isScratch) tag = markedKind === 'dir' ? 'directory exemplar · scratch' : 'scratch';

      const row = el('div', {
        class: rowCls.join(' '),
        style: 'padding-left:' + (12 + depth * 20) + 'px',
        onclick: () => {
          if (!selectable) return;
          if (picking) { setScratch(childPath); return; }
          mark(entry.isDir ? 'dir' : 'file', childPath);
        },
      }, [
        check,
        twisty,
        el('span', { class: 'row__icon is-' + (entry.isDir ? 'dir' : 'file') + (checked ? ' is-marked' : '') }, [icon(entry.isDir ? 'folder' : 'file', 16)]),
        el('span', { class: 'row__name' + (checked || entry.isDir ? ' is-strong' : '') }, [entry.name]),
        el('span', { class: 'row__spacer' }, []),
        entry.isSymlink ? el('span', { class: 'row__tag' }, [icon('link', 11), document.createTextNode(' ' + tag)]) : el('span', { class: 'row__tag' + (checked ? ' is-marked' : '') + (bad ? ' is-bad' : '') }, [tag]),
      ]);
      rows.push(row);

      if (entry.isDir && expanded) {
        walk(childPath, depth + 1);
      }
    });
  }
  if (!state.tree.nodes[root]) {
    rows.push(el('div', { style: 'padding:20px;color:var(--ep-walnut);font-size:12.5px' }, ['Loading…']));
  } else {
    walk(root, 0);
  }
  return rows;
}

// ---------------------------------------------------------------------
// Render: inspector
// ---------------------------------------------------------------------

function renderInspector(s) {
  const out = [];

  if (s.error) {
    const kind = classifyError(s.error);
    const titles = {
      mount: 'Mount is not NFSv4.1',
      reversed: 'Both exemplars are directories',
      replay: 'ACL cannot be replayed over NFSv4.1',
      other: 'build-spec failed',
    };
    const fixLabels = { mount: 'Switch to userspace', reversed: 'Clear the file slot' };
    const actions = [];
    if (fixLabels[kind]) {
      actions.push(el('button', { class: 'btn btn--secondary btn--sm', onclick: () => applyErrorFix(kind) }, [fixLabels[kind]]));
    }
    actions.push(el('button', { class: 'btn btn--ghost btn--sm', onclick: () => api.openRunbook() }, ['Open runbook']));

    out.push(
      el('div', { class: 'errcard' }, [
        el('div', { class: 'errcard__head' }, [icon('alert', 17), el('span', { class: 'errcard__title' }, [titles[kind]])]),
        el('pre', { class: 'errcard__body' }, [String(s.error.message || s.error)]),
        el('div', { class: 'errcard__actions' }, actions),
      ])
    );
  }

  if (s.plan) {
    out.push(renderPlan(s));
    return out;
  }

  if (s.result) {
    const id = s.result.identity || {};
    out.push(
      el('div', { style: 'display:flex;flex-direction:column;gap:16px' }, [
        el('div', { style: 'display:flex;flex-direction:column;gap:11px' }, [
          el('span', { class: 'ep-eyebrow' }, ['ACL identity summary — distinct DACL principals']),
          el('div', { class: 'idcards' }, [
            idCard(id.special, 'Special', principalNames(id, 'special', 'dacl') || 'no OWNER@ GROUP@ EVERYONE@', false),
            idCard(id.named, 'Named', 'name@domain', false),
            idCard(id.numericUser, 'Numeric user', 'uid as the server returned it', true),
            idCard(id.numericGroup, 'Numeric group', 'gid as the server returned it', true),
          ]),
          renderSaclIdentity(id),
          renderPrincipals(id.principals),
          renderVerifyBanner(id.verified),
          s.result.hasSacl ? renderSaclBanner(s.result) : null,
          renderNotes(s.result.notes),
        ]),
        renderSpecBlock(s),
      ])
    );
  }

  if (!s.error && !s.result) {
    out.push(
      el('div', { class: 'idle' }, [
        el('span', { class: 'idle__icon' }, [icon('shield', 22)]),
        el('span', { class: 'idle__title' }, ['No spec yet']),
        el('span', { class: 'idle__body' }, ['Mark a folder and a file, then run. The ACL summary and the generated YAML appear here.']),
        el('span', { class: 'idle__note' }, ['Two metadata reads. Nothing is written.']),
      ])
    );
  }

  return out;
}

// The principals of one kind in one ACL ('dacl' or 'sacl'), joined for a hint.
function principalNames(id, kind, acl) {
  return (id.principals || [])
    .filter((p) => p.kind === kind && p.where.indexOf(acl === 'dacl' ? 'DACL' : 'SACL') >= 0)
    .map((p) => (p.group && kind !== 'special' ? 'g:' : '') + p.who)
    .join(' ');
}

// The audit ACEs' principals, counted apart from the DACL's cards.
function renderSaclIdentity(id) {
  const c = id.sacl || {};
  const parts = [
    [c.special, 'special'], [c.named, 'named'], [c.numericUser, 'numeric user'], [c.numericGroup, 'numeric group'],
  ].filter((e) => e[0] > 0).map((e) => e[0] + ' ' + e[1]);
  if (parts.length === 0) return null;
  return el('span', { class: 'hint' }, ['Audit (SACL) principals: ' + parts.join(', ') + '.']);
}

// Every distinct principal and the ACLs it appears in.
function renderPrincipals(principals) {
  if (!principals || principals.length === 0) return null;
  return el('div', { class: 'plist' }, principals.map((p) =>
    el('div', { class: 'plist__row' }, [
      el('span', { class: 'plist__who' }, [(p.group && p.kind !== 'special' ? 'g:' : '') + p.who]),
      el('span', { class: 'plist__kind' }, [p.kind]),
      el('span', { class: 'plist__where' }, [p.where]),
    ])
  ));
}

function idCard(count, label, hint, warn) {
  const n = count || 0;
  return el('div', { class: 'idcard' + (warn && n > 0 ? ' is-warn' : '') }, [
    el('span', { class: 'idcard__count' }, [String(n)]),
    el('span', { class: 'idcard__label' }, [label]),
    el('span', { class: 'idcard__hint' }, [hint]),
  ]);
}

// Capture notes from speccapture (audit ACEs, the bypass, dropped alarm ACEs).
function renderNotes(notes) {
  if (!notes || notes.length === 0) return el('span', {}, []);
  return el('div', { class: 'capnotes' }, notes.map((n) => el('span', { class: 'capnotes__line' }, ['NOTE: ' + n])));
}

function renderVerifyBanner(verified) {
  return el('div', { class: 'verifybanner' + (verified ? ' is-passed' : '') }, [
    icon(verified ? 'shield' : 'alert', 16),
    el('span', { style: 'display:flex;flex-direction:column;gap:2px' }, [
      el('span', { class: 'verifybanner__title' }, [verified ? 'Write verification: passed' : 'Write verification: not performed']),
      el('span', { class: 'verifybanner__body' }, [
        verified
          ? 'Both ACLs were written and read back twice on temporary probes and reached the same canonical form. Safe to apply.'
          : 'This is a structural snapshot of what the array returned. Apply it to a small tree first, or turn on Verify by replay.',
      ]),
    ]),
  ]);
}

// The exemplars carried audit (U) ACEs, so the spec has sacl: rules. Which
// kind decides what applying it does to every object's DACL.
function renderSaclBanner(r) {
  const n = (r.dirSacl || []).length + (r.fileSacl || []).length;
  return el('div', { class: 'verifybanner is-sacl' }, [
    icon('shield', 16),
    el('span', { style: 'display:flex;flex-direction:column;gap:2px' }, [
      el('span', { class: 'verifybanner__title' }, [
        r.keepsDacl ? n + ' audit ACE(s): SACL only, DACLs kept' : n + ' audit ACE(s): SACL and DACL (--with-dacl)',
      ]),
      el('span', { class: 'verifybanner__body' }, [
        r.keepsDacl
          ? 'The rules are sacl: with no acl:, so applying the spec replaces each object\'s SACL and leaves its DACL as it is. Apply with permissionreset --sacl, or over SMB with Set-SaclOnly -Spec.'
          : 'The rules carry acl: and sacl:, so applying the spec replaces every object\'s DACL as well. Apply with permissionreset --sacl.',
      ]),
    ]),
  ]);
}

function renderPlan(s) {
  const p = s.plan;
  const refused = p.refused || [];
  return el('div', { style: 'display:flex;flex-direction:column;gap:16px' }, [
    el('div', { style: 'display:flex;flex-direction:column;gap:11px' }, [
      el('span', { class: 'ep-eyebrow' }, ['SACL plan — build-spec --sacl-plan']),
      el('div', { class: 'verifybanner' + (refused.length ? '' : ' is-passed') }, [
        icon(refused.length ? 'alert' : 'shield', 16),
        el('span', { style: 'display:flex;flex-direction:column;gap:2px' }, [
          el('span', { class: 'verifybanner__title' }, [
            refused.length ? 'Set-SaclOnly will refuse this plan' : 'Ready for Set-SaclOnly -Plan',
          ]),
          el('span', { class: 'verifybanner__body' }, [
            refused.length
              ? refused.join(', ') + ' carry acl: or dacl:. That spec is for permissionreset; Set-SaclOnly writes only sacl: rules.'
              : p.rules + ' rule(s) plus the default, read from ' + p.specPath + '. Only the spec file was read.',
          ]),
        ]),
      ]),
    ]),
    el('div', { class: 'specblock' }, [
      el('div', { class: 'specblock__head' }, [
        el('span', { class: 'ep-eyebrow' }, ['Plan JSON']),
        el('div', { class: 'specblock__actions' }, [
          el('button', { class: 'btn btn--secondary btn--sm', onclick: doCopy }, [icon('copy', 12), document.createTextNode(state.copied ? 'Copied' : 'Copy')]),
          el('button', { class: 'btn btn--secondary btn--sm', onclick: doSavePlan }, [icon('download', 12), document.createTextNode('Save')]),
          el('button', { class: 'btn btn--ghost btn--sm', onclick: () => { state.plan = null; state.savedPath = ''; render(state); } }, ['Close']),
        ]),
      ]),
      el('pre', {}, [p.json]),
      state.savedPath ? el('span', { class: 'hint' }, ['Saved ' + state.savedPath]) : null,
    ]),
  ]);
}

function renderSpecBlock(s) {
  const dirCount = (s.result.dirAces || []).length;
  const fileCount = (s.result.fileAces || []).length;
  const saclCount = (s.result.dirSacl || []).length + (s.result.fileSacl || []).length;
  return el('div', { class: 'specblock' }, [
    el('div', { class: 'specblock__head' }, [
      el('span', { class: 'ep-eyebrow' }, ['Generated spec']),
      el('div', { class: 'specblock__actions' }, [
        el('button', { class: 'btn btn--secondary btn--sm', onclick: doCopy }, [icon('copy', 12), document.createTextNode(state.copied ? 'Copied' : 'Copy')]),
        el('button', { class: 'btn btn--secondary btn--sm', onclick: doSave }, [icon('download', 12), document.createTextNode('Save')]),
      ]),
    ]),
    el('pre', {}, [s.result.yaml]),
    el('div', { class: 'chips' }, [
      s.result.keepsDacl ? el('span', { class: 'chip' }, ['DACLs kept, not written']) : el('span', { class: 'chip' }, [dirCount + ' directory ACEs']),
      s.result.keepsDacl ? null : el('span', { class: 'chip' }, [fileCount + ' file ACEs']),
      s.result.hasSacl ? el('span', { class: 'chip' }, [saclCount + ' audit ACEs']) : null,
      el('span', { class: 'chip' }, ['ACE order preserved']),
    ]),
  ]);
}

// ---------------------------------------------------------------------
// Render: footer + cli
// ---------------------------------------------------------------------

function busyLabel(phase) {
  const labels = { connecting: 'Connecting…', listing: 'Listing…', capturing: 'Capturing…', verifying: 'Verifying…', saving: 'Saving…', planning: 'Planning…' };
  return labels[phase] || '';
}

function renderFooter(s) {
  const out = [];
  out.push(
    el('label', { class: 'footer__output' }, [
      el('span', { class: 'field__label', style: 'text-transform:uppercase;letter-spacing:.1em;font-size:10.5px' }, ['Output file']),
      el('span', { class: 'footer__output-row' }, [
        el('input', {
          value: s.outputName,
          'data-focus': 'outputName',
          oninput: (e) => { state.outputName = e.target.value; render(state); },
        }),
        el('span', { class: 'footer__output-note' }, ['never overwrites an existing file']),
      ]),
    ])
  );

  out.push(
    el('label', { class: 'footer__verify', onclick: () => { toggleVerify(); render(state); } }, [
      el('span', { class: 'switch' + (s.verify.enabled ? ' is-on' : '') }, [el('span', { class: 'switch__knob' }, [])]),
      el('span', {}, [
        el('span', { class: 'footer__verify-title', style: 'display:block' }, ['Verify by replay']),
        el('span', { class: 'footer__verify-body', style: 'display:block' }, ['Writes two temporary probes, then removes them']),
      ]),
    ])
  );

  out.push(
    el('label', { class: 'footer__verify', onclick: () => { toggleWithDacl(); render(state); } }, [
      el('span', { class: 'switch' + (s.withDacl ? ' is-on' : '') }, [el('span', { class: 'switch__knob' }, [])]),
      el('span', {}, [
        el('span', { class: 'footer__verify-title', style: 'display:block' }, ['Also write the DACL']),
        el('span', { class: 'footer__verify-body', style: 'display:block' }, ['With audit ACEs only: acl: beside sacl:']),
      ]),
    ])
  );

  if (!s.verify.enabled) {
    out.push(
      el('label', { class: 'footer__verify', onclick: () => { state.acceptUnproven = !state.acceptUnproven; render(state); } }, [
        el('span', { class: 'switch' + (s.acceptUnproven ? ' is-on' : '') }, [el('span', { class: 'switch__knob' }, [])]),
        el('span', {}, [
          el('span', { class: 'footer__verify-title', style: 'display:block' }, ['Read without proof']),
          el('span', { class: 'footer__verify-body', style: 'display:block' }, ['Unsafe on some arrays: the read can empty inherited auditing. Verify by replay proves it first']),
        ]),
      ])
    );
  }

  if (s.verify.enabled) {
    const chosen = !!s.verify.scratch;
    const row = [
      el('span', { class: 'scratchpath' + (chosen ? ' is-set' : ''), title: chosen ? s.verify.scratch : '' }, [
        chosen ? s.verify.scratch : 'No folder chosen',
      ]),
      el('button', {
        class: 'btn btn--secondary btn--sm',
        disabled: !s.session.connected,
        onclick: () => { state.verify.picking = !state.verify.picking; render(state); },
      }, [s.verify.picking ? 'Cancel' : chosen ? 'Change…' : 'Pick folder…']),
    ];
    if (s.rail.transport === 'kernel') {
      row.push(el('button', { class: 'btn btn--ghost btn--sm', onclick: doChooseScratch }, ['Browse…']));
    }
    out.push(
      el('label', { class: 'footer__scratch' }, [
        el('span', { class: 'field__label' }, ['Scratch']),
        el('span', { class: 'footer__scratch-row' }, row),
      ])
    );
  }

  out.push(el('span', { class: 'footer__spacer' }, []));

  const hintText = s.result
    ? (state.savedPath ? 'Saved ' + state.savedPath : 'Capture complete')
    : scratchCollides() ? 'Scratch must differ from both exemplars'
    : (s.verify.enabled && !s.verify.scratch && s.marks.dir && s.marks.file) ? 'Pick a scratch folder'
    : (s.marks.dir && s.marks.file ? '2 exemplars marked' : 'Mark a folder and a file');
  out.push(
    el('div', { class: 'footer__run' }, [
      el('span', { class: 'footer__ready-hint' + (s.result ? ' is-done' : '') }, [hintText]),
      el('button', {
        class: 'btn btn--primary btn--lg',
        disabled: runDisabled(),
        onclick: doRun,
      }, [
        s.busy ? el('span', { class: 'spinner' }, []) : null,
        document.createTextNode(s.busy ? busyLabel(s.busy) : (s.verify.enabled ? 'Capture and verify' : 'Capture')),
      ]),
    ])
  );

  return out;
}

// shq single-quotes an argument for a POSIX shell. The CLI line is text an
// operator copies into a terminal, so any path with a space or a glob
// character has to survive the paste intact.
function shq(v) {
  const s = String(v);
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s)) return s;
  return "'" + s.split("'").join("'\\''") + "'";
}

function buildCliLine(s) {
  if (s.plan) return 'build-spec --sacl-plan ' + shq(s.plan.specPath);
  const parts = ['build-spec', '--transport', s.rail.transport];
  if (s.rail.transport === 'kernel') {
    // mount point implied by kernel session, nothing to add
  } else {
    parts.push('--server', s.rail.server || '<SERVER>', '--export', shq(s.rail.export || '<EXPORT>'));
  }
  if (s.rail.uid !== '' || s.rail.gid !== '') {
    parts.push('--auth-uid', s.rail.uid || '<UID>', '--auth-gid', s.rail.gid || '<GID>');
    if (s.rail.gids) parts.push('--auth-gids', s.rail.gids);
  }
  if (Number(s.rail.rpcTimeoutMs) !== 30000) parts.push('--rpc-timeout', Number(s.rail.rpcTimeoutMs) + 'ms');
  if (Number(s.rail.retryBudget) !== 5) parts.push('--retry-budget', String(Number(s.rail.retryBudget)));
  if (Number(s.rail.retryBaseMs) !== 100) parts.push('--retry-base-delay', Number(s.rail.retryBaseMs) + 'ms');
  parts.push('--output', shq(s.outputName));
  if (s.withDacl) parts.push('--with-dacl');
  if (s.verify.enabled) parts.push('--verify-write', shq(s.verify.scratch || '<SCRATCH>'));
  parts.push(shq(s.marks.dir || '<DIRECTORY>'), shq(s.marks.file || '<FILE>'));
  return parts.join(' ');
}

// ---------------------------------------------------------------------
// Root render
// ---------------------------------------------------------------------

export function render(s) {
  const active = document.activeElement;
  const focusKey = active && active.getAttribute && active.getAttribute('data-focus');
  const selStart = focusKey && typeof active.selectionStart === 'number' ? active.selectionStart : null;
  const selEnd = focusKey && typeof active.selectionEnd === 'number' ? active.selectionEnd : null;

  const treeEl = document.querySelector('#explorer .tree');
  const treeScrollTop = treeEl ? treeEl.scrollTop : null;

  mount('titlebar', renderTitlebar(s));
  mount('rail', renderRail(s));
  mount('explorer', renderExplorer(s));
  mount('inspector', renderInspector(s));
  mount('footer', renderFooter(s));
  document.getElementById('cliline').textContent = buildCliLine(s);

  if (treeScrollTop !== null) {
    const nextTree = document.querySelector('#explorer .tree');
    if (nextTree) nextTree.scrollTop = treeScrollTop;
  }

  if (focusKey) {
    const next = document.querySelector(`[data-focus="${focusKey}"]`);
    if (next) {
      next.focus();
      if (selStart !== null) next.setSelectionRange(selStart, selEnd);
    }
  }
}

// ---------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------

render(state);
loadCapabilities();
loadExports();
