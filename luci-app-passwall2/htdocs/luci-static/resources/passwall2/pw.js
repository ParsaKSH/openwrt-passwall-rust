'use strict';
'require baseclass';
'require rpc';
'require uci';
'require ui';
'require form';
'require dom';
'require fs';
'require validation';

/*
 * Shared frontend library of luci-app-passwall2 (Rust rewrite).
 *
 *   'require passwall2.pw as pw';
 *
 * Exports (see the bottom of this file): call, loadCSS, wrap, url, getNodes,
 * getNodeList, nodeLabel, badge, card, icon, pageHeader, poll, unpoll, notify,
 * confirm, addNodeOption, addShuntOptions, HideValue, NodePicker, ...
 */

const APPNAME = 'passwall2';
const UCI_CONF = 'passwall2';
const BASE_PATH = 'admin/services/passwall2';
const TMP_PATH = '/tmp/etc/passwall2';
const SPECIAL_PROTOCOLS = [ '_balancing', '_shunt', '_iface', '_urltest' ];
const SPECIAL_TARGETS = [ '_default', '_direct', '_blackhole' ];

/* ------------------------------------------------------------------ validators (upstream cbi.js) */

function isJSONText(str) {
	try {
		const v = JSON.parse(str);
		return v !== null && typeof(v) === 'object';
	}
	catch (e) {
		return false;
	}
}

function isTimeHHMM(str) {
	const m = /^(\d?\d):(\d\d)$/.exec(String(str));
	if (!m)
		return false;
	const h = +m[1], mi = +m[2];
	return h >= 0 && h <= 23 && mi >= 0 && mi <= 59;
}

/* 26.4-era schedule values are whole hours ('3'); the current schema stores 'H:MM'. */
function legacyHour(v) {
	return (typeof v == 'string' && /^\d{1,2}$/.test(v)) ? v + ':00' : v;
}

/* 26.4-era port lists used 'disable' (and 'default' in ACL rules) for "no ports"/"inherit". */
function legacyPorts(v) {
	return (v === 'disable' || v === 'default') ? '' : v;
}

/*
 * Mode of an ACL rule. A rule without 'mode' is 26.4-era and is resolved the way the backend
 * (firewall/acl.rs legacy_acl_mode) and `passwall2 migrate` resolve it: both no-redir lists
 * "all ports" (unset/'default' = the global value) -> 0, node unset/'default' -> 2, else 1.
 */
function aclMode(config, section_id) {
	const m = uci.get(config, section_id, 'mode');
	if (m != null)
		return m;
	const all = (k) => {
		let v = uci.get(config, section_id, k);
		if (v == null || v === '' || v === 'default')
			v = uci.get_first(config, 'global_forwarding', k);
		return (',' + String(v || '').replace(/\s+/g, '').replace(/:/g, '-') + ',').indexOf(',1-65535,') >= 0;
	};
	if (all('tcp_no_redir_ports') && all('udp_no_redir_ports'))
		return '0';
	const node = uci.get(config, section_id, 'node');
	return (node == null || node === '' || node === 'default') ? '2' : '1';
}

function isBase64(str) {
	return /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/.test(String(str));
}

function isUUID(str) {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(str));
}

if (validation && validation.types) {
	if (!validation.types.base64)
		validation.types.base64 = function() { return this.assert(isBase64(this.value), _('Must be Base64 text!')); };
	if (!validation.types.json)
		validation.types.json = function() { return this.assert(isJSONText(this.value), _('Must be JSON text!')); };
	if (!validation.types.timehhmm)
		validation.types.timehhmm = function() { return this.assert(isTimeHHMM(this.value), _('valid time (hh:mm)')); };
	if (!validation.types.uuid)
		validation.types.uuid = function() { return this.assert(isUUID(this.value), _('Must be UUID format!')); };
}

/* Run a LuCI datatype expression (e.g. "ipmask4", "or(ipaddr,ipaddrport(1))") against a value
 * outside of any DOM field. */
function checkDatatype(type, value) {
	const dummy = {
		value: String(value == null ? '' : value),
		classList: { add() {}, remove() {} },
		setAttribute() {}, removeAttribute() {}, dispatchEvent() {}
	};
	try {
		const v = validation.create(dummy, type, true);
		v.value = dummy.value;
		v.error = null;
		return v.vstack[0].apply(v, v.vstack[1]) === true;
	}
	catch (e) {
		return false;
	}
}

/* ------------------------------------------------------------------ rpc */

const rpcCache = {};

function call(method, params) {
	params = (params != null && typeof(params) === 'object') ? params : {};
	const keys = Object.keys(params);
	const cacheKey = method + '\x00' + keys.join('\x00');

	if (!rpcCache[cacheKey]) {
		rpcCache[cacheKey] = rpc.declare({
			object: 'luci.' + APPNAME,
			method: method,
			params: keys,
			reject: true
		});
	}

	return rpcCache[cacheKey].apply(null, keys.map((k) => params[k])).then((res) => {
		if (res == null)
			return {};
		if (typeof(res) !== 'object' || Array.isArray(res))
			return { result: res };
		return res;
	});
}

/* ------------------------------------------------------------------ paths / misc helpers */

function url(...parts) {
	return L.url(BASE_PATH, ...parts.filter((p) => p != null && p !== ''));
}

let cssLoaded = false;

function loadCSS() {
	if (cssLoaded || document.querySelector('link[data-pw-css]')) {
		cssLoaded = true;
		return;
	}
	const link = E('link', {
		'rel': 'stylesheet',
		'type': 'text/css',
		'href': L.resource('passwall2/pw.css'),
		'data-pw-css': 'true'
	});
	document.head.appendChild(link);
	cssLoaded = true;
}

function wrap(...children) {
	loadCSS();
	return E('div', { 'class': 'pw-root' }, children.flat());
}

function escapeHTML(s) {
	return String(s == null ? '' : s)
		.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function trim(s) {
	return String(s == null ? '' : s).replace(/^\s+|\s+$/g, '');
}

function randomChars(n) {
	const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	const len = n || 16;
	let out = '';
	const buf = new Uint8Array(len * 2);
	(window.crypto || window.msCrypto).getRandomValues(buf);
	for (let i = 0; i < buf.length && out.length < len; i++) {
		if (buf[i] < 248)
			out += chars[buf[i] % 62];
	}
	while (out.length < len)
		out += chars[Math.floor(Math.random() * 62)];
	return out;
}

function globalSid(type) {
	const s = uci.sections(UCI_CONF, type || 'global');
	return (s && s.length) ? s[0]['.name'] : null;
}

function latencyKind(ms, okBelow, warnBelow) {
	const v = Number(ms);
	if (!isFinite(v))
		return 'err';
	if (v < okBelow)
		return 'ok';
	if (v < warnBelow)
		return 'warn';
	return 'err';
}

/* ------------------------------------------------------------------ icons */

const ICONS = {
	play: '<polygon points="6 4 20 12 6 20 6 4"/>',
	stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
	refresh: '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
	edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/>',
	'delete': '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
	copy: '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
	add: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>',
	ping: '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
	link: '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
	upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
	download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
	globe: '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
	shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
	server: '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
	list: '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
	settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
	log: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/>',
	check: '<polyline points="20 6 9 17 4 12"/>',
	close: '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
	search: '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
	chevron: '<polyline points="6 9 12 15 18 9"/>',
	drag: '<circle cx="9" cy="6" r="1"/><circle cx="15" cy="6" r="1"/><circle cx="9" cy="12" r="1"/><circle cx="15" cy="12" r="1"/><circle cx="9" cy="18" r="1"/><circle cx="15" cy="18" r="1"/>',
	cpu: '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>',
	info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
	dns: '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2v20"/>',
	plug: '<path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a6 6 0 0 1-12 0V8z"/>'
};

function icon(name, size) {
	const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
	const px = String(size || 16);
	svg.setAttribute('viewBox', '0 0 24 24');
	svg.setAttribute('width', px);
	svg.setAttribute('height', px);
	svg.setAttribute('fill', 'none');
	svg.setAttribute('stroke', 'currentColor');
	svg.setAttribute('stroke-width', '2');
	svg.setAttribute('stroke-linecap', 'round');
	svg.setAttribute('stroke-linejoin', 'round');
	svg.setAttribute('aria-hidden', 'true');
	svg.setAttribute('class', 'pw-icon pw-icon-' + name);
	svg.innerHTML = ICONS[name] || ICONS.info;
	return svg;
}

/* ------------------------------------------------------------------ DOM building blocks */

const BADGE_KINDS = [ 'ok', 'err', 'warn', 'info', 'muted' ];

function badge(text, kind) {
	const k = BADGE_KINDS.indexOf(kind) >= 0 ? kind : 'muted';
	return E('span', { 'class': 'pw-badge pw-badge-' + k }, [ text != null ? String(text) : '' ]);
}

function setBadge(node, text, kind) {
	if (!node)
		return node;
	const k = BADGE_KINDS.indexOf(kind) >= 0 ? kind : 'muted';
	node.className = 'pw-badge pw-badge-' + k;
	node.textContent = text != null ? String(text) : '';
	return node;
}

function card(title, ...children) {
	const body = E('div', { 'class': 'pw-card-body' }, children.flat().filter((c) => c != null));
	const el = E('div', { 'class': 'pw-card' });
	if (title != null && title !== '') {
		el.appendChild(E('div', { 'class': 'pw-card-header' }, [
			E('h3', { 'class': 'pw-card-title' }, [ title ])
		]));
	}
	el.appendChild(body);
	return el;
}

function button(label, opts) {
	opts = opts || {};
	const kind = opts.kind || 'neutral';
	return E('button', {
		'class': 'btn cbi-button cbi-button-' + kind + ' pw-btn' + (opts['class'] ? ' ' + opts['class'] : ''),
		'type': 'button',
		'title': opts.title || null,
		'disabled': opts.disabled ? '' : null,
		'click': opts.click ? ui.createHandlerFn(opts.scope || null, opts.click) : null
	}, [ opts.icon ? icon(opts.icon) : '', label != null ? E('span', {}, [ label ]) : '' ]);
}

function pageHeader(title, subtitle, actions) {
	loadCSS();
	return E('div', { 'class': 'pw-header' }, [
		E('div', { 'class': 'pw-header-text' }, [
			E('h2', { 'class': 'pw-header-title', 'name': 'content' }, [ title ]),
			(subtitle != null && subtitle !== '') ? E('div', { 'class': 'pw-header-sub' }, [ subtitle ]) : ''
		]),
		E('div', { 'class': 'pw-header-actions' }, (actions || []).filter((a) => a != null))
	]);
}

function poll(fn, intervalSec) {
	L.Poll.add(fn, intervalSec || 5);
	if (!L.Poll.active())
		L.Poll.start();
	return fn;
}

function unpoll(fn) {
	try { L.Poll.remove(fn); } catch (e) {}
}

function notify(msg, kind) {
	const map = { ok: 'success', err: 'danger', warn: 'warning', info: 'info', muted: 'info' };
	const cls = map[kind] || 'info';
	const content = (msg != null && typeof(msg) === 'object' && 'nodeType' in msg) ? msg : E('p', {}, [ String(msg) ]);
	if (typeof(ui.addTimeLimitedNotification) === 'function')
		return ui.addTimeLimitedNotification(null, content, (kind === 'err') ? 8000 : 4000, cls);
	return ui.addNotification(null, content, cls);
}

/* ui.showModal() puts a string title into an <h4> through innerHTML, so a string here is turned
 * into a text node first: modal titles regularly carry node / server remarks and other data that
 * came from subscriptions or share links. Pass a DOM node to get markup on purpose. */
function textNode(v) {
	if (v == null)
		return v;
	if (typeof(v) === 'object' && 'nodeType' in v)
		return v;
	if (Array.isArray(v))
		return v.map(textNode);
	return document.createTextNode(String(v));
}

function showModal(title, children, ...classes) {
	return ui.showModal(textNode(title), children, ...classes);
}

function confirmDialog(title, msg) {
	return new Promise((resolve) => {
		const done = (v) => { ui.hideModal(); resolve(v); };
		showModal(title, [
			E('div', { 'class': 'pw-root pw-modal' }, [
				(msg != null && typeof(msg) === 'object' && 'nodeType' in msg) ? msg : E('p', {}, [ String(msg != null ? msg : '') ])
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', 'click': () => done(false) }, [ _('Cancel') ]),
				' ',
				E('button', { 'class': 'btn cbi-button-action important', 'click': () => done(true) }, [ _('OK') ])
			])
		]);
	});
}

function alertDialog(title, msg) {
	return new Promise((resolve) => {
		showModal(title, [
			E('div', { 'class': 'pw-root pw-modal' }, [
				(msg != null && typeof(msg) === 'object' && 'nodeType' in msg) ? msg : E('p', {}, [ String(msg != null ? msg : '') ])
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', 'click': () => { ui.hideModal(); resolve(); } }, [ _('Dismiss') ])
			])
		]);
	});
}

/* Turn an upstream log endpoint reply into plain text ("<br />" → newline; the
 * "Not enabled log" alert script → null). */
function logText(res) {
	let t = (res && res.result != null) ? String(res.result) : '';
	if (/<script>/i.test(t) && /alert\(/i.test(t))
		return null;
	return t.replace(/<br\s*\/?>/gi, '\n');
}

/* Fetch a log through an rpc method (get_redir_log / get_socks_log / server_log / get_log)
 * and show it in a modal. */
function showLog(title, method, params) {
	const pre = E('pre', { 'class': 'pw-log' }, [ _('Collecting data...') ]);
	const reload = () => call(method, params || {}).then((res) => {
		const t = logText(res);
		if (t == null) {
			pre.textContent = _('Not enabled log');
			return;
		}
		pre.textContent = t;
		pre.scrollTop = pre.scrollHeight;
	}).catch((e) => { pre.textContent = String(e && e.message || e); });
	/* Close comes first: LuCI's Escape handler clicks the first `.right > button`. */
	showModal(title, [
		E('div', { 'class': 'pw-root pw-modal pw-modal-log' }, [ pre ]),
		E('div', { 'class': 'right' }, [
			E('button', { 'class': 'btn cbi-button', 'click': ui.hideModal }, [ _('Close') ]),
			' ',
			E('button', { 'class': 'btn cbi-button cbi-button-action', 'click': () => reload() }, [ _('Refresh') ])
		])
	], 'pw-log-modal');
	return reload();
}

/* After the next successful "Save & Apply", land on `target` instead of reloading the
 * current page (upstream: map footer redirects to the log page). */
let applyRedirectHandler = null;

function redirectAfterApply(target) {
	if (applyRedirectHandler)
		document.removeEventListener('uci-applied', applyRedirectHandler);
	applyRedirectHandler = function() {
		document.removeEventListener('uci-applied', applyRedirectHandler);
		applyRedirectHandler = null;
		try {
			window.history.replaceState(null, '', target);
		}
		catch (e) {
			window.setTimeout(() => { window.location.href = target; }, 0);
		}
	};
	document.addEventListener('uci-applied', applyRedirectHandler);
}

function b64ToBytes(b64) {
	const bin = atob(String(b64 || '').replace(/\s+/g, ''));
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++)
		out[i] = bin.charCodeAt(i);
	return out;
}

function bytesToB64(bytes) {
	let bin = '';
	const step = 0x8000;
	for (let i = 0; i < bytes.length; i += step)
		bin += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
	return btoa(bin);
}

function downloadBlob(blob, filename) {
	const href = window.URL.createObjectURL(blob);
	const a = E('a', { 'href': href, 'download': filename, 'style': 'display:none' });
	document.body.appendChild(a);
	a.click();
	a.remove();
	window.setTimeout(() => window.URL.revokeObjectURL(href), 1000);
}

/* ------------------------------------------------------------------ runtime probes */

/* utils.sh get_cache_var: last line "KEY=..." of $TMP_PATH/var, value between the first quotes. */
function parseCacheVar(text, key) {
	if (!key || !text)
		return null;
	let val = null;
	String(text).split('\n').forEach((line) => {
		if (line.indexOf(key + '=') === 0) {
			const rest = line.substr(key.length + 1);
			const parts = rest.split('"');
			val = parts.length > 1 ? parts[1] : '';
		}
	});
	return (val == null || val === '') ? null : val;
}

function getCacheVar(key) {
	return L.resolveDefault(fs.read(TMP_PATH + '/var'), '').then((t) => parseCacheVar(t, key));
}

function isExecutable(path) {
	if (!path)
		return Promise.resolve(false);
	return L.resolveDefault(fs.stat(path), null).then((st) => {
		if (!st || st.type !== 'file')
			return false;
		if (typeof(st.mode) === 'number')
			return (st.mode & 0o111) !== 0;
		return true;
	});
}

const COM_DEFAULT_PATH = { 'geoview': '/usr/bin/geoview', 'xray': '/usr/bin/xray', 'sing-box': '/usr/bin/sing-box' };

/* api.get_app_path(com): @global_app[0].<com with - → _>_file, else the default path. */
function comPath(com) {
	const p = uci.get_first(UCI_CONF, 'global_app', com.replace(/-/g, '_') + '_file');
	return (p && p.length) ? p : (COM_DEFAULT_PATH[com] || '/usr/bin/' + com);
}

/* api.finded_com(com): is the configured component binary present? */
function findedCom(com) {
	return Promise.resolve(uci.load(UCI_CONF)).then(() => isExecutable(comPath(com))).then((ok) => {
		if (ok)
			return true;
		return L.resolveDefault(call('com_version', { com: com }), {}).then((r) => !!(r && r.code == 1 && r.data));
	});
}

/* api.is_finded(bin): binary in /bin, /usr/bin or PATH. */
function isFinded(bin) {
	const dirs = [ '/bin/', '/usr/bin/', '/usr/sbin/', '/sbin/' ];
	return Promise.all(dirs.map((d) => isExecutable(d + bin))).then((r) => r.indexOf(true) >= 0);
}

/* global.lua / other.lua lsmod test. */
function getModules() {
	return L.resolveDefault(fs.read('/proc/modules'), '').then((t) => String(t || ''));
}

function tproxyOk(mods) {
	const m = String(mods || '');
	return (m.indexOf('REDIRECT') >= 0 && m.indexOf('TPROXY') >= 0) ||
		(m.indexOf('nft_redir') >= 0 && m.indexOf('nft_tproxy') >= 0);
}

/* ------------------------------------------------------------------ nodes */

function protocolLabel(protocol) {
	switch (protocol) {
	case 'vmess': return 'VMess';
	case 'vless': return 'VLESS';
	case 'shadowsocks': return 'SS';
	case 'shadowsocksr': return 'SSR';
	case 'wireguard': return 'WG';
	case 'hysteria': return 'HY';
	case 'hysteria2': return 'HY2';
	case 'anytls': return 'AnyTLS';
	case 'ssh': return 'SSH';
	case '_json': return 'JSON';
	default:
		return String(protocol || '').replace(/^[a-z]/, (c) => c.toUpperCase());
	}
}

function typeName(type) {
	return type === 'sing-box' ? 'Sing-Box' : String(type || '');
}

function isIPv6(addr) {
	const s = trim(addr).toLowerCase();
	const m = /\[(.*?)\]/.exec(s);
	return checkDatatype('ip6addr', m ? m[1] : s);
}

function isIP(addr) {
	return checkDatatype('ip4addr', addr) || isIPv6(addr);
}

function ipv6Full(addr) {
	if (!isIPv6(addr))
		return '';
	return /\[.*?\]/.test(addr) ? addr : '[' + addr + ']';
}

function showNodeInfo() {
	return (uci.get_first(UCI_CONF, 'global_other', 'show_node_info') || '0') === '1';
}

/* Classify a nodes section exactly like api.get_valid_nodes(); returns
 * { valid, node_type, label } — label is upstream's display remark. */
function classifyNode(s, info) {
	const res = { valid: false, node_type: null, label: '' };
	if (!s || !s.type || !s.remarks)
		return res;
	const tn = typeName(s.type);
	if (SPECIAL_PROTOCOLS.indexOf(s.protocol) >= 0) {
		res.valid = true;
		res.node_type = 'special';
		res.label = trim('%s：[%s]'.format(tn + ' ' + _(s.protocol), s.remarks));
		return res;
	}
	if (s.protocol === '_json' && (s.type === 'sing-box' || s.type === 'Xray')) {
		/* custom-JSON node: the server lives inside custom_json; stale address/port are ignored */
		res.valid = true;
		res.node_type = 'normal';
		res.label = trim('%s：[%s]'.format(tn + ' JSON', s.remarks));
		return res;
	}
	let port = s.port || s.hysteria_hop || s.hysteria2_hop;
	const isRealm = s.protocol === 'hysteria2' && !!s.hysteria2_realms;
	if ((port && s.address) || isRealm) {
		let address = s.address;
		if (isRealm || isIP(address) || checkDatatype('hostname', address)) {
			let name = tn;
			if ((s.type === 'sing-box' || s.type === 'Xray') && s.protocol)
				name += ' ' + protocolLabel(s.protocol);
			if (address && isIPv6(address))
				address = ipv6Full(address);
			if (isRealm)
				name += ' Realm';
			res.label = trim('%s：[%s]'.format(name, s.remarks));
			if (info && !isRealm) {
				port = String(port || '').replace(/:/g, '-');
				res.label = trim('%s：[%s] %s:%s'.format(name, s.remarks, address, port));
			}
			res.valid = true;
			res.node_type = 'normal';
		}
	}
	return res;
}

/* api.get_node_remarks(): display name of any node section (also invalid ones). */
function nodeRemarks(s) {
	if (!s)
		return '';
	const tn = typeName(s.type);
	if (SPECIAL_PROTOCOLS.indexOf(s.protocol) >= 0)
		return trim('%s：[%s]'.format(tn + ' ' + _(s.protocol), s.remarks || ''));
	let name = tn;
	if ((s.type === 'sing-box' || s.type === 'Xray') && s.protocol)
		name += ' ' + protocolLabel(s.protocol);
	if (s.protocol === 'hysteria2' && s.hysteria2_realms)
		name += ' Realm';
	return trim('%s：[%s]'.format(name, s.remarks || ''));
}

/* Node display name in upstream format (get_valid_nodes remark, honours show_node_info);
 * falls back to get_node_remarks for nodes that are not "valid". */
function nodeLabel(s, info) {
	if (s == null)
		return '';
	if (typeof(s) === 'string')
		s = uci.get(UCI_CONF, s);
	if (!s)
		return '';
	const c = classifyNode(s, info != null ? info : showNodeInfo());
	return c.valid ? c.label : nodeRemarks(s);
}

function nodeEntry(s, c) {
	return {
		id: s['.name'],
		remarks: s.remarks,
		type: s.type,
		protocol: s.protocol,
		address: s.address,
		port: s.port || s.hysteria_hop || s.hysteria2_hop,
		group: s.group || '',
		chain_proxy: s.chain_proxy,
		add_mode: s.add_mode,
		label: c.valid ? c.label : nodeRemarks(s),
		node_type: c.node_type,
		valid: c.valid,
		section: s
	};
}

/* Synchronous variant (requires uci.load('passwall2') to have completed). */
function getNodesSync(all) {
	const info = showNodeInfo();
	const defaults = [], others = [];
	(uci.sections(UCI_CONF, 'nodes') || []).forEach((s) => {
		const c = classifyNode(s, info);
		if (!all && !c.valid)
			return;
		const e = nodeEntry(s, c);
		if (all)
			defaults.push(e);
		else if (!s.group)
			defaults.push(e);
		else
			others.push(e);
	});
	return defaults.concat(others);
}

/* getNodes() → valid nodes in api.get_valid_nodes() order (ungrouped first);
 * getNodes(true) → every nodes section in UCI order. */
function getNodes(all) {
	return Promise.resolve(uci.load(UCI_CONF)).then(() => getNodesSync(!!all));
}

/* api.get_node_list(): { socks_list, normal_list, balancing_list, shunt_list, urltest_list, iface_list } */
function getNodeListSync() {
	const list = { socks_list: [], normal_list: [] };
	(uci.sections(UCI_CONF, 'socks') || []).forEach((s) => {
		if (s.node) {
			list.socks_list.push({
				id: s['.name'],
				label: _('Socks Config') + ' [' + (s.port || '') + _('Port') + ']',
				remark: _('Socks Config') + ' [' + (s.port || '') + _('Port') + ']',
				group: 'Socks'
			});
		}
	});
	getNodesSync(false).forEach((n) => {
		if (n.node_type === 'normal')
			list.normal_list.push(Object.assign({ remark: n.label }, n));
		if (n.protocol && n.protocol.charAt(0) === '_') {
			const key = n.protocol.substr(1) + '_list';
			list[key] = list[key] || [];
			list[key].push(Object.assign({ remark: n.label }, n));
		}
	});
	[ 'balancing_list', 'shunt_list', 'urltest_list', 'iface_list' ].forEach((k) => { list[k] = list[k] || []; });
	return list;
}

function getNodeList() {
	return Promise.resolve(uci.load(UCI_CONF)).then(() => getNodeListSync());
}

function isSpecialTarget(v) {
	if (!v)
		return true;
	for (let i = 0; i < SPECIAL_TARGETS.length; i++)
		if (String(v).indexOf(SPECIAL_TARGETS[i]) === 0)
			return true;
	return false;
}

function editUrlFor(id) {
	if (isSpecialTarget(id))
		return null;
	return String(id).indexOf('socks_') === 0 ? url('socks_config', id) : url('node_config', id);
}

/* ------------------------------------------------------------------ node picker widget */

let openPicker = null;

function findBackground(el) {
	for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
		const st = window.getComputedStyle(n);
		const bg = st.backgroundColor;
		if (bg && bg !== 'transparent' && !/rgba\([^)]*,\s*0\)$/.test(bg))
			return { bg: bg, fg: window.getComputedStyle(el).color };
	}
	const b = window.getComputedStyle(document.body);
	return { bg: b.backgroundColor || '#fff', fg: b.color || '#000' };
}

/*
 * Grouped, searchable node selector (upstream nodes_listvalue / nodes_value / nodes_dynamiclist).
 *   new NodePicker(value, entries, { id, mode: 'single'|'multi'|'custom', disabled, optional })
 *   entries: [{ key, label, group }]   group '' = ungrouped
 * Emits 'widget-change' (LuCI form dependency updates) when the value changes.
 */
const NodePicker = ui.AbstractElement.extend({
	__name__: 'PW.NodePicker',

	__init__(value, entries, options) {
		this.options = Object.assign({ mode: 'single', optional: false }, options);
		this.entries = Array.isArray(entries) ? entries.slice() : [];
		this.mode = this.options.mode;
		this.collapsed = {};

		if (this.mode === 'custom') {
			this.entries = this.entries.filter((e) => e.key !== '');
			const v = (value == null) ? '' : (Array.isArray(value) ? value.join(' ') : String(value));
			if (v !== '' && !this.findEntry(v))
				this.entries.push({ key: v, label: v, group: '' });
			this.value = v;
		}
		else if (this.mode === 'multi') {
			const items = [];
			L.toArray(value).forEach((v) => String(v).split(',').forEach((x) => {
				x = trim(x);
				if (x !== '' && this.findEntry(x) && items.indexOf(x) < 0)
					items.push(x);
			}));
			this.values = items;
		}
		else {
			let v = Array.isArray(value) ? value[0] : value;
			if (v != null)
				v = String(v).split(/\s+/)[0];
			if ((v == null || v === '') && !this.findEntry('')) {
				const first = this.entries.filter((e) => !e.group)[0] || this.entries[0];
				v = first ? first.key : '';
			}
			this.value = (v == null) ? '' : v;
		}
	},

	findEntry(key) {
		for (let i = 0; i < this.entries.length; i++)
			if (this.entries[i].key === key)
				return this.entries[i];
		return null;
	},

	labelOf(key) {
		const e = this.findEntry(key);
		return e ? e.label : key;
	},

	groups() {
		const order = [], map = {};
		this.entries.forEach((e) => {
			if (!e.group)
				return;
			if (!map[e.group]) {
				map[e.group] = [];
				order.push(e.group);
			}
			map[e.group].push(e);
		});
		return { order: order, map: map };
	},

	render() {
		const root = E('div', {
			'id': this.options.id,
			'class': 'pw-np pw-np-' + this.mode + (this.options.disabled ? ' pw-np-disabled' : '')
		});

		if (this.mode === 'multi') {
			this.chipsEl = E('div', { 'class': 'pw-np-chips' });
			root.appendChild(this.chipsEl);
		}

		this.labelEl = E('span', { 'class': 'pw-np-label' });
		this.toggleEl = E('button', {
			'type': 'button',
			'class': 'pw-np-toggle cbi-input-select',
			'id': this.options.id ? 'widget.' + this.options.id : null,
			'disabled': this.options.disabled ? '' : null,
			'click': (ev) => { ev.preventDefault(); ev.stopPropagation(); this.isOpen() ? this.close() : this.open(); },
			'keydown': (ev) => {
				if (ev.key === 'ArrowDown' || ev.key === 'Enter' || ev.key === ' ') {
					ev.preventDefault();
					if (!this.isOpen())
						this.open();
				}
			}
		}, [ this.labelEl, E('span', { 'class': 'pw-np-caret' }, [ icon('chevron', 14) ]) ]);
		root.appendChild(this.toggleEl);

		this.node = root;
		dom.bindClassInstance(root, this);
		this.setUpdateEvents(root, 'pw-np-change');
		this.setChangeEvents(root, 'pw-np-change');
		this.refresh();
		return root;
	},

	refresh() {
		if (!this.labelEl)
			return;
		if (this.mode === 'multi') {
			dom.content(this.chipsEl, this.values.map((k, idx) => this.renderChip(k, idx)));
			this.chipsEl.style.display = this.values.length ? '' : 'none';
			this.labelEl.textContent = _('-- Please choose --');
			this.toggleEl.title = '';
		}
		else {
			const v = this.value;
			const text = (this.mode === 'custom' && v === '') ? _('-- Please choose --') : this.labelOf(v);
			this.labelEl.textContent = (text === '' && v === '') ? _('-- Please choose --') : text;
			this.toggleEl.title = text;
		}
	},

	renderChip(key, idx) {
		const chip = E('div', {
			'class': 'pw-np-chip',
			'draggable': this.options.disabled ? null : 'true',
			'data-key': key,
			'title': this.labelOf(key),
			'dragstart': (ev) => { this.dragIdx = idx; ev.dataTransfer.effectAllowed = 'move'; try { ev.dataTransfer.setData('text/plain', key); } catch (e) {} chip.classList.add('dragging-row'); },
			'dragend': () => { chip.classList.remove('dragging-row'); },
			'dragover': (ev) => { ev.preventDefault(); ev.dataTransfer.dropEffect = 'move'; },
			'drop': (ev) => {
				ev.preventDefault();
				const from = this.dragIdx;
				if (from == null || from === idx)
					return;
				const item = this.values.splice(from, 1)[0];
				this.values.splice(idx, 0, item);
				this.dragIdx = null;
				this.changed();
			}
		}, [
			E('span', { 'class': 'pw-np-chip-handle' }, [ icon('drag', 12) ]),
			E('span', { 'class': 'pw-np-chip-label' }, [ this.labelOf(key) ]),
			E('button', {
				'type': 'button', 'class': 'pw-np-chip-remove', 'title': _('Delete'),
				'disabled': this.options.disabled ? '' : null,
				'click': (ev) => { ev.preventDefault(); this.values.splice(idx, 1); this.changed(); }
			}, [ '×' ])
		]);
		return chip;
	},

	changed() {
		this.refresh();
		if (this.node)
			this.node.dispatchEvent(new CustomEvent('pw-np-change', { bubbles: true }));
	},

	isOpen() {
		return openPicker === this && this.panel != null;
	},

	isSelected(key) {
		return this.mode === 'multi' ? this.values.indexOf(key) >= 0 : this.value === key;
	},

	select(key, label) {
		if (this.mode === 'multi') {
			if (this.values.indexOf(key) < 0)
				this.values.push(key);
			this.close();
			this.changed();
			return;
		}
		if (this.mode === 'custom' && key !== '' && !this.findEntry(key))
			this.entries.push({ key: key, label: label || key, group: '' });
		const changed = this.value !== key;
		this.value = key;
		this.close();
		if (changed)
			this.changed();
		else
			this.refresh();
	},

	open() {
		if (this.options.disabled)
			return;
		if (openPicker && openPicker !== this)
			openPicker.close();
		openPicker = this;

		const colors = findBackground(this.toggleEl);
		this.searchEl = E('input', {
			'type': 'text',
			'class': 'cbi-input-text pw-np-search',
			'placeholder': '🔍 ' + _('Search nodes...'),
			'input': () => this.renderList(),
			'keydown': (ev) => { if (ev.key === 'Escape') { ev.preventDefault(); this.close(); this.toggleEl.focus(); } }
		});
		this.listEl = E('div', { 'class': 'pw-np-list' });
		this.panel = E('div', {
			'class': 'pw-root pw-np-panel',
			'style': 'background-color:%s;color:%s'.format(colors.bg, colors.fg),
			'mousedown': (ev) => ev.stopPropagation(),
			'wheel': (ev) => {
				const l = this.listEl;
				if ((ev.deltaY < 0 && l.scrollTop <= 0) || (ev.deltaY > 0 && l.scrollTop + l.clientHeight >= l.scrollHeight))
					ev.preventDefault();
			}
		}, [ E('div', { 'class': 'pw-np-search-wrap' }, [ this.searchEl ]), this.listEl ]);

		if (this.mode === 'custom') {
			this.customEl = E('input', {
				'type': 'text',
				'class': 'cbi-input-text pw-np-custom',
				'placeholder': _('-- custom --'),
				'keydown': (ev) => {
					if (ev.key === 'Enter') {
						ev.preventDefault();
						const v = trim(this.customEl.value);
						this.select(v, v);
					}
				}
			});
			this.panel.appendChild(E('div', { 'class': 'pw-np-custom-wrap' }, [ this.customEl ]));
		}

		/* collapse every group except the one holding the current value */
		const g = this.groups();
		this.collapsed = {};
		g.order.forEach((name) => {
			this.collapsed[name] = !g.map[name].some((e) => this.isSelected(e.key));
		});

		document.body.appendChild(this.panel);
		this.renderList();
		this.position();

		this.onDocDown = (ev) => {
			if (!this.panel)
				return;
			if (this.panel.contains(ev.target) || this.node.contains(ev.target))
				return;
			this.close();
		};
		this.onReposition = () => this.position();
		document.addEventListener('mousedown', this.onDocDown, true);
		document.addEventListener('touchstart', this.onDocDown, true);
		window.addEventListener('scroll', this.onReposition, true);
		window.addEventListener('resize', this.onReposition);
		this.toggleEl.classList.add('pw-np-open');

		const sel = this.listEl.querySelector('.pw-np-item.is-selected');
		if (sel && typeof(sel.scrollIntoView) === 'function')
			sel.scrollIntoView({ block: 'nearest' });
		this.searchEl.focus();
	},

	close() {
		if (this.panel) {
			this.panel.remove();
			this.panel = null;
		}
		if (this.onDocDown) {
			document.removeEventListener('mousedown', this.onDocDown, true);
			document.removeEventListener('touchstart', this.onDocDown, true);
		}
		if (this.onReposition) {
			window.removeEventListener('scroll', this.onReposition, true);
			window.removeEventListener('resize', this.onReposition);
		}
		if (this.toggleEl)
			this.toggleEl.classList.remove('pw-np-open');
		if (openPicker === this)
			openPicker = null;
	},

	position() {
		if (!this.panel || !this.toggleEl)
			return;
		if (!document.body.contains(this.toggleEl)) {
			this.close();
			return;
		}
		const r = this.toggleEl.getBoundingClientRect();
		const vh = window.innerHeight, vw = window.innerWidth;
		const maxH = Math.min(vh * 0.5, 550);
		const width = Math.max(r.width, this.mode === 'custom' ? 240 : 200);
		this.panel.style.minWidth = width + 'px';
		this.panel.style.maxWidth = Math.max(width, Math.min(vw - 16, 560)) + 'px';
		this.listEl.style.maxHeight = (maxH - 60) + 'px';
		const ph = Math.min(this.panel.offsetHeight || maxH, maxH);
		const below = vh - r.bottom;
		let top = (below >= ph + 8 || below >= r.top) ? r.bottom + 4 : Math.max(8, r.top - ph - 4);
		let left = Math.min(r.left, Math.max(8, vw - this.panel.offsetWidth - 8));
		this.panel.style.top = Math.round(top) + 'px';
		this.panel.style.left = Math.round(Math.max(8, left)) + 'px';
	},

	renderItem(e) {
		const selected = this.isSelected(e.key);
		return E('div', {
			'class': 'pw-np-item' + (selected ? ' is-selected' : '') + (e.center ? ' pw-np-item-center' : ''),
			'title': e.label,
			'data-key': e.key,
			'click': (ev) => { ev.preventDefault(); this.select(e.key, e.label); }
		}, [ e.label === '' ? ' ' : e.label ]);
	},

	renderList() {
		const q = this.searchEl ? trim(this.searchEl.value).toLowerCase() : '';
		const match = (e) => !q || String(e.label).toLowerCase().indexOf(q) >= 0;
		const nodes = [];

		if (this.mode === 'custom')
			nodes.push(this.renderItem({ key: '', label: _('-- Please choose --'), center: true }));

		this.entries.filter((e) => !e.group && match(e)).forEach((e) => nodes.push(this.renderItem(e)));

		const g = this.groups();
		g.order.forEach((name) => {
			const items = g.map[name];
			const hits = items.filter(match);
			if (q && !hits.length)
				return;
			const isCollapsed = q ? false : !!this.collapsed[name];
			let counter, ckind;
			if (q) {
				counter = '(%d/%d)'.format(hits.length, items.length);
				ckind = hits.length ? 'ok' : 'err';
			}
			else if (this.mode === 'multi') {
				counter = '(%d)'.format(items.length);
				ckind = items.some((e) => this.isSelected(e.key)) ? 'info' : 'muted';
			}
			else {
				const has = items.some((e) => this.isSelected(e.key));
				counter = '(%d/%d)'.format(has ? 1 : 0, items.length);
				ckind = has ? 'info' : 'muted';
			}
			nodes.push(E('div', {
				'class': 'pw-np-group' + (isCollapsed ? ' is-collapsed' : ''),
				'click': (ev) => {
					ev.preventDefault();
					if (q)
						return;
					const wasCollapsed = !!this.collapsed[name];
					g.order.forEach((n) => { this.collapsed[n] = true; });
					this.collapsed[name] = !wasCollapsed;
					this.renderList();
					if (!this.collapsed[name])
						this.listEl.scrollTop = 0;
				}
			}, [
				E('span', { 'class': 'pw-np-arrow' }, [ isCollapsed ? '▶' : '▼' ]),
				E('span', { 'class': 'pw-np-group-name' }, [ name ]),
				E('span', { 'class': 'pw-np-count pw-np-count-' + ckind }, [ counter ])
			]));
			if (!isCollapsed)
				(q ? hits : items).forEach((e) => nodes.push(this.renderItem(e)));
		});

		if (!nodes.length)
			nodes.push(E('div', { 'class': 'pw-np-empty' }, [ _('No results were found!') ]));

		dom.content(this.listEl, nodes);
		window.requestAnimationFrame(() => this.position());
	},

	getValue() {
		return this.mode === 'multi' ? this.values.slice() : this.value;
	},

	setValue(value) {
		if (this.mode === 'multi') {
			this.values = L.toArray(value).filter((v) => this.findEntry(v));
		}
		else {
			const v = (value == null) ? '' : String(value);
			if (this.mode === 'custom' && v !== '' && !this.findEntry(v))
				this.entries.push({ key: v, label: v, group: '' });
			this.value = v;
		}
		this.refresh();
	},

	/* upstream lv_change(): set value + label programmatically */
	setValueLabel(value, label) {
		if (value !== '' && !this.findEntry(value))
			this.entries.push({ key: value, label: label || value, group: '' });
		this.value = value;
		this.refresh();
	},

	removeEntry(key) {
		this.entries = this.entries.filter((e) => e.key !== key);
		this.refresh();
	}
});

/* Build picker entries from option settings (see addNodeOption). */
function buildNodeEntries(opts) {
	opts = opts || {};
	const entries = [];
	const seen = {};
	const push = (key, label, group) => {
		key = String(key);
		if (seen[key])
			return;
		seen[key] = true;
		entries.push({ key: key, label: String(label != null ? label : key), group: group || '' });
	};

	(opts.values || []).forEach((v) => {
		if (Array.isArray(v))
			push(v[0], v[1], '');
		else
			push(v, v, '');
	});

	let nodes;
	if (Array.isArray(opts.nodes))
		nodes = opts.nodes;
	else
		nodes = getNodesSync(false);

	const idOf = (n) => (n.id != null) ? n.id : n['.name'];
	const labelOf = (n) => (n.label != null && n.label !== '') ? n.label : ((n.remark != null && n.remark !== '') ? n.remark : nodeLabel(n.section || n));
	const kindOf = (n) => (n.protocol && n.protocol.charAt(0) === '_') ? n.protocol : 'normal';
	const accept = (n) => {
		if (Array.isArray(opts.types) && opts.types.indexOf(kindOf(n)) < 0)
			return false;
		if (typeof(opts.filter) === 'function' && !opts.filter(n))
			return false;
		return true;
	};
	const groupOf = (n) => n.group ? n.group : _('default');

	if (Array.isArray(opts.order)) {
		const list = getNodeListSync();
		opts.order.forEach((kind) => {
			if (kind === 'socks') {
				list.socks_list.forEach((s) => push(s.id, s.label, 'Socks'));
				return;
			}
			nodes.filter((n) => kindOf(n) === kind && accept(n)).forEach((n) => push(idOf(n), labelOf(n), groupOf(n)));
		});
	}
	else {
		if (opts.socks)
			getNodeListSync().socks_list.forEach((s) => push(s.id, s.label, 'Socks'));
		nodes.filter(accept).forEach((n) => push(idOf(n), labelOf(n), groupOf(n)));
	}

	return entries;
}

function renderNodeActions(opt, section_id, picker) {
	const opts = opt.pwOpts || {};
	if (!opts.edit && typeof(opts.log) !== 'function')
		return null;
	const box = E('div', { 'class': 'pw-np-actions' });
	const update = () => {
		const v = picker.getValue();
		const key = Array.isArray(v) ? null : v;
		const links = [];
		if (opts.edit && key && !isSpecialTarget(key)) {
			links.push(E('a', {
				'href': editUrlFor(key),
				'class': 'pw-link',
				'title': _('Edit')
			}, [ icon('edit', 14), ' ', _('Edit') ]));
		}
		if (typeof(opts.log) === 'function' && key && !isSpecialTarget(key)) {
			links.push(E('a', {
				'href': '#',
				'class': 'pw-link',
				'title': _('Log'),
				'click': (ev) => { ev.preventDefault(); opts.log(section_id, key); }
			}, [ icon('log', 14), ' ', _('Log') ]));
		}
		dom.content(box, links);
	};
	picker.node.addEventListener('pw-np-change', update);
	update();
	return box;
}

const NodeMixin = {
	load(section_id) {
		return Promise.resolve(uci.load(UCI_CONF)).then(() => {
			this.pwEntries = buildNodeEntries(this.pwOpts);
			this.keylist = this.pwEntries.map((e) => e.key);
			this.vallist = this.pwEntries.map((e) => e.label);
			return this.super('load', [ section_id ]);
		});
	},

	transformChoices() {
		const c = {};
		(this.pwEntries || []).forEach((e) => { c[e.key] = e.label; });
		return c;
	},

	value(key, val) {
		this.pwOpts = this.pwOpts || {};
		this.pwOpts.values = this.pwOpts.values || [];
		this.pwOpts.values.push([ String(key), (val != null) ? val : String(key) ]);
	},

	renderNodeWidget(section_id, cfgvalue, mode) {
		const value = (cfgvalue != null) ? cfgvalue : this.default;
		const picker = new NodePicker(value, this.pwEntries || [], {
			id: this.cbid(section_id),
			mode: mode,
			optional: this.optional,
			disabled: (this.readonly != null) ? this.readonly : this.map.readonly
		});
		const el = picker.render();
		const actions = renderNodeActions(this, section_id, picker);
		return actions ? E('div', { 'class': 'pw-np-wrap' }, [ el, actions ]) : el;
	},

	textvalue(section_id) {
		let v = this.cfgvalue(section_id);
		if (v == null)
			v = this.default;
		const map = this.transformChoices();
		return L.toArray(v).map((k) => '%h'.format(map[k] != null ? map[k] : k)).join('<br />');
	}
};

const CBINodeListValue = form.ListValue.extend(Object.assign({}, NodeMixin, {
	__name__: 'CBI.PwNodeListValue',
	typename: 'nodes_listvalue',
	renderWidget(section_id, option_index, cfgvalue) {
		return this.renderNodeWidget(section_id, cfgvalue, 'single');
	}
}));

const CBINodeValue = form.Value.extend(Object.assign({}, NodeMixin, {
	__name__: 'CBI.PwNodeValue',
	typename: 'nodes_value',
	renderWidget(section_id, option_index, cfgvalue) {
		return this.renderNodeWidget(section_id, cfgvalue, 'custom');
	}
}));

const CBINodeDynamicList = form.DynamicList.extend(Object.assign({}, NodeMixin, {
	__name__: 'CBI.PwNodeDynamicList',
	typename: 'nodes_dynamiclist',
	renderWidget(section_id, option_index, cfgvalue) {
		return this.renderNodeWidget(section_id, cfgvalue, 'multi');
	},
	write(section_id, value) {
		const out = [];
		L.toArray(value).forEach((v) => { if (out.indexOf(v) < 0) out.push(v); });
		return this.super('write', [ section_id, out ]);
	}
}));

/*
 * addNodeOption(section, optname, title, opts) → form option with the grouped node picker.
 * opts:
 *   tab        tab name (uses section.taboption)
 *   multiple   true → ordered multi select (DynamicList, upstream nodes_dynamiclist)
 *   custom     true → value with free text entry (upstream nodes_value, e.g. haproxy lbss)
 *   values     [[key, label], ...] leading ungrouped entries (e.g. [['', _('Close')]])
 *   socks      true → include socks instances (group "Socks") before the nodes
 *   types      kinds to include: 'normal', '_balancing', '_shunt', '_urltest', '_iface'
 *   filter     fn(node) → bool, node = getNodes() entry
 *   order      explicit kind order, e.g. ['socks','normal','_balancing','_urltest','_iface']
 *   nodes      explicit node list (getNodes() format) instead of the UCI one
 *   edit       true → "Edit" link next to the picker (node_config / socks_config)
 *   log        fn(section_id, value) → "Log" link handler
 * Extra o.value(key, label) calls append ungrouped entries.
 */
function addNodeOption(section, optname, title, opts) {
	opts = Object.assign({}, opts || {});
	const cls = opts.multiple ? CBINodeDynamicList : (opts.custom ? CBINodeValue : CBINodeListValue);
	const o = opts.tab ? section.taboption(opts.tab, cls, optname, title) : section.option(cls, optname, title);
	o.pwOpts = opts;
	return o;
}

/* ------------------------------------------------------------------ HideValue (upstream cbi HideValue) */

/* Invisible pseudo option: posts "1" while its dependencies are satisfied and never writes to
 * UCI. Other options use depends('<name>', '1') as a boolean condition. */
const HideValue = form.Value.extend({
	__name__: 'CBI.PwHideValue',
	__init__(...args) {
		this.super('__init__', args);
		this.default = '1';
	},
	load() { return null; },
	cfgvalue(section_id, set_value) { return '1'; },
	renderWidget(section_id) {
		return new ui.Hiddenfield(this.default != null ? this.default : '1', { id: this.cbid(section_id) }).render();
	},
	renderFrame(section_id, in_table, option_index, nodes) {
		const el = this.super('renderFrame', [ section_id, in_table, option_index, nodes ]);
		const box = in_table ? el.firstChild : el;
		box.classList.add('pw-hidevalue');
		box.style.display = 'none';
		return el;
	},
	formvalue(section_id) {
		const elem = this.getUIElement(section_id);
		return elem ? elem.getValue() : null;
	},
	write() {},
	remove() {}
});

/* ------------------------------------------------------------------ shunt options (include/shunt_options.lua) */

/* Rule table of one shunt node: columns Rule / Node / FakeDNS / Preproxy. Values are options on
 * the shunt node: <rule_id>, <rule_id>_fakedns, <rule_id>_proxy_tag, default_node, ... */
const CBIShuntTable = form.Value.extend({
	__name__: 'CBI.PwShuntTable',
	typename: 'shunt_options',

	load() { return null; },
	cfgvalue() { return null; },
	write() {},
	remove() {},
	isValid() { return true; },
	formvalue() { return null; },

	rowValue(row, kind) {
		const v = uci.get(UCI_CONF, this.nodeId, row[kind]);
		if (kind === 'nodeOpt')
			return (v != null) ? v : row.nodeDefault;
		return v;
	},

	currentGroup(section_id) {
		let g = null;
		if (this.groupOption) {
			const fv = this.groupOption.isActive(section_id) ? this.groupOption.formvalue(section_id) : null;
			g = (fv != null) ? fv : uci.get(UCI_CONF, this.nodeId, 'shunt_group');
		}
		else {
			g = uci.get(UCI_CONF, this.nodeId, 'shunt_group');
		}
		return String(g || '').toLowerCase();
	},

	filterRows(section_id, group) {
		const g = (group != null) ? String(group).toLowerCase() : this.currentGroup(section_id);
		(this.rowState[section_id] || []).forEach((r) => {
			const show = r.rule.id === '.default' || r.rule.group === g;
			r.el.style.display = show ? '' : 'none';
			r.visible = show;
		});
	},

	checkRow(r, val) {
		if (val == null)
			val = r.nodeW.getValue();
		/* check_fakedns */
		if (val === '' || val === '_direct') {
			r.fakeW.setValue('0');
			r.fakeCell.classList.add('pw-shunt-hidden');
		}
		else {
			r.fakeCell.classList.remove('pw-shunt-hidden');
		}
		/* check_proxy_tag */
		if (val === '' || val.charAt(0) === '_' || val.indexOf('socks_') === 0 || !this.normalIds[val]) {
			r.proxyW.setValueLabel('', _('Close (Not use)'));
			r.proxyCell.classList.add('pw-shunt-hidden');
		}
		else {
			r.proxyCell.classList.remove('pw-shunt-hidden');
		}
	},

	renderWidget(section_id) {
		const nodeEntries = buildNodeEntries({
			values: [ [ '', _('Close (Not use)') ], [ '_default', _('Use default node') ], [ '_direct', _('Direct Connection') ], [ '_blackhole', _('Blackhole (Block)') ] ],
			nodes: this.nodes,
			order: [ 'socks', 'normal', '_balancing', '_urltest', '_iface' ]
		});
		const proxyEntries = buildNodeEntries({
			values: [ [ '', _('Close (Not use)') ] ],
			nodes: this.nodes,
			order: [ 'socks', 'normal', '_balancing', '_urltest', '_iface' ]
		});
		const fakeTitle = _('Use FakeDNS work in the domain that proxy.') + '\n' +
			_('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
			_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
		const proxyTitle = _('Set the node to be used as a pre-proxy.') + '\n' +
			_('Each rule has a separate switch that controls whether this rule uses the pre-proxy or not.');

		const tbody = E('tbody');
		const table = E('table', { 'class': 'table cbi-section-table pw-shunt-table', 'id': 'cbi-passwall2-shunt_option_list-' + this.nodeId }, [
			E('thead', {}, E('tr', { 'class': 'tr cbi-section-table-titles' }, [
				E('th', { 'class': 'th' }, [ _('Rule') ]),
				E('th', { 'class': 'th' }, [ _('Node') ]),
				E('th', { 'class': 'th', 'title': fakeTitle }, [ E('span', { 'style': 'color:#FF8C00' }, [ 'FakeDNS' ]) ]),
				E('th', { 'class': 'th', 'title': proxyTitle }, [ E('span', { 'style': 'color:red' }, [ _('Preproxy') ]) ])
			])),
			tbody
		]);

		const rows = [];
		this.rules.forEach((rule, i) => {
			const isDefault = rule.id === '.default';
			const entries = isDefault ? nodeEntries.filter((e) => e.key !== '_default') : nodeEntries;
			const nodeW = new NodePicker(this.rowValue(rule, 'nodeOpt'), entries, { mode: 'single', id: 'cbid.table.%s.%d._node'.format(this.nodeId, i + 1) });
			const fakeW = new ui.Checkbox(this.rowValue(rule, 'fakeOpt'), { id: 'cbid.table.%s.%d._fakedns'.format(this.nodeId, i + 1), value_enabled: '1', value_disabled: '0' });
			const proxyW = new NodePicker(this.rowValue(rule, 'proxyOpt') || '', proxyEntries, { mode: 'single', id: 'cbid.table.%s.%d._proxy_tag'.format(this.nodeId, i + 1) });
			const nodeEl = nodeW.render();
			const fakeCell = E('td', { 'class': 'td', 'data-title': 'FakeDNS' }, [ fakeW.render() ]);
			const proxyCell = E('td', { 'class': 'td', 'data-title': _('Preproxy') }, [ proxyW.render() ]);
			const editBox = E('div', { 'class': 'pw-np-actions' });
			const updateEdit = () => {
				const v = nodeW.getValue();
				dom.content(editBox, (v && !isSpecialTarget(v)) ? E('a', { 'class': 'pw-link', 'href': editUrlFor(v) }, [ icon('edit', 14), ' ', _('Edit') ]) : '');
			};
			const tr = E('tr', { 'class': 'tr cbi-section-table-row', 'data-rule': rule.id }, [
				E('td', { 'class': 'td', 'data-title': _('Rule') }, [
					isDefault ? E('span', { 'style': 'color:red' }, [ rule.remarks ])
						: E('a', { 'href': url('shunt_rules', rule.id), 'target': '_blank' }, [ rule.remarks ])
				]),
				E('td', { 'class': 'td', 'data-title': _('Node') }, [ E('div', { 'class': 'pw-np-wrap' }, [ nodeEl, editBox ]) ]),
				fakeCell,
				proxyCell
			]);
			const r = { rule: rule, el: tr, nodeW: nodeW, fakeW: fakeW, proxyW: proxyW, fakeCell: fakeCell, proxyCell: proxyCell, visible: true };
			nodeEl.addEventListener('pw-np-change', () => { this.checkRow(r); updateEdit(); });
			updateEdit();
			this.checkRow(r, nodeW.getValue());
			tbody.appendChild(tr);
			rows.push(r);
		});

		this.rowState = this.rowState || {};
		this.rowState[section_id] = rows;
		this.filterRows(section_id);
		return E('div', { 'id': this.cbid(section_id), 'class': 'pw-shunt-wrap cbi-section cbi-tblsection' }, [ table ]);
	},

	parse(section_id) {
		if (!this.isActive(section_id))
			return Promise.resolve();
		if (this.verify && !this.verify())
			return Promise.resolve();
		const id = this.nodeId;
		(this.rowState[section_id] || []).forEach((r) => {
			if (!r.visible)
				return;
			const nv = r.nodeW.getValue();
			if (nv == null || nv === '')
				uci.unset(UCI_CONF, id, r.rule.nodeOpt);
			else if (nv !== this.rowValue(r.rule, 'nodeOpt'))
				uci.set(UCI_CONF, id, r.rule.nodeOpt, nv);

			const fv = r.fakeW.isChecked() ? '1' : '0';
			if (fv === '0')
				uci.unset(UCI_CONF, id, r.rule.fakeOpt);
			else if (fv !== uci.get(UCI_CONF, id, r.rule.fakeOpt))
				uci.set(UCI_CONF, id, r.rule.fakeOpt, fv);

			const pv = r.proxyW.getValue();
			if (pv == null || pv === '')
				uci.unset(UCI_CONF, id, r.rule.proxyOpt);
			else if (pv !== uci.get(UCI_CONF, id, r.rule.proxyOpt))
				uci.set(UCI_CONF, id, r.rule.proxyOpt, pv);
		});
		return Promise.resolve();
	}
});

/*
 * addShuntOptions(section, opts): embedded editor of the shunt options of every `_shunt` node,
 * each visible only while the host's node option selects that node (include/shunt_options.lua).
 * opts:
 *   sectionId     host section id (e.g. resolved @global[0] or the ACL section)
 *   nodeOption    name of the host's node option (e.g. 'node')
 *   tab, tabTitle tab to create (inserted at position 2, like upstream); omit to add untabbed
 *   nodes         getNodes() result (valid nodes)
 *   shuntNodes    nodes whose options are rendered (default: every `_shunt` node of `nodes`)
 *   geoview       bool, is_finded("geoview") (adds enable_geoview_ip)
 *   globalSid     section id of @global[0] (flush_set on enable_geoview_ip change)
 * Returns { tab, nodes: { <shunt id>: { options..., table } } }.
 */
function addShuntOptions(section, opts) {
	opts = opts || {};
	const nodes = opts.nodes || getNodesSync(false);
	const shuntNodes = opts.shuntNodes || nodes.filter((n) => n.protocol === '_shunt');
	const hostSid = opts.sectionId;
	const nodeOpt = opts.nodeOption || 'node';
	const depKey = '%s.%s.%s'.format(UCI_CONF, hostSid, nodeOpt);
	const gsid = opts.globalSid || globalSid('global');
	const result = { tab: opts.tab || null, nodes: {} };

	if (!shuntNodes.length)
		return result;

	if (opts.tab) {
		if (section.tabs && section.tabs[opts.tab] == null) {
			section.tab(opts.tab, opts.tabTitle || opts.tab);
			if (section.tab_names.length > 2) {
				section.tab_names.splice(section.tab_names.indexOf(opts.tab), 1);
				section.tab_names.splice(1, 0, opts.tab);
			}
		}
		else if (!section.tabs) {
			section.tab(opts.tab, opts.tabTitle || opts.tab);
		}
	}

	const add = (cls, name, title, desc) => {
		const o = opts.tab ? section.taboption(opts.tab, cls, name, title, desc) : section.option(cls, name, title, desc);
		return o;
	};

	const normalIds = {};
	nodes.forEach((n) => { if (n.node_type === 'normal') normalIds[n.id] = true; });

	const groups = [];
	(uci.sections(UCI_CONF, 'shunt_rules') || []).forEach((r) => {
		if (r.group && groups.indexOf(r.group) < 0)
			groups.push(r.group);
	});

	shuntNodes.forEach((sn) => {
		const nid = sn.id;
		const sec = uci.get(UCI_CONF, nid) || {};
		const prefix = '_shunt_' + nid + '_';
		const entry = { options: {} };
		const verify = () => {
			const o = section.children.filter((c) => c.option === nodeOpt)[0];
			return !o || o.formvalue(hostSid) === nid;
		};
		const bind = (o, realOpt) => {
			o.ucisection = nid;
			o.ucioption = realOpt;
			o.depends(depKey, nid);
			const superWrite = o.write, superRemove = o.remove;
			o.write = function(sid, v) { if (verify()) return superWrite.call(this, sid, v); };
			o.remove = function(sid) { if (verify()) return superRemove.call(this, sid); };
			entry.options[realOpt] = o;
			return o;
		};

		let o;
		if (sec.type === 'Xray') {
			o = bind(add(form.ListValue, prefix + 'domainStrategy', _('Domain Strategy')), 'domainStrategy');
			o.value('AsIs');
			o.value('IPIfNonMatch');
			o.value('IPOnDemand');
			o.default = 'IPOnDemand';
			o.description = '<br /><ul><li>' + _("'AsIs': Only use domain for routing. Default value.") +
				'</li><li>' + _("'IPIfNonMatch': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again.") +
				'</li><li>' + _("'IPOnDemand': As long as there is a IP-based rule, resolves the domain into IP immediately.") +
				'</li></ul>';

			o = bind(add(form.ListValue, prefix + 'domainMatcher', _('Domain matcher')), 'domainMatcher');
			o.value('hybrid');
			o.value('linear');
		}

		o = bind(add(form.Flag, prefix + 'fakedns', '<a style="color:#FF8C00">FakeDNS</a> ' + _('Main switch'),
			_('Use FakeDNS work in the domain that proxy.') + '<br>' +
			_('Suitable scenarios for let the node servers get the target domain names.') + '<br>' +
			_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.')), 'fakedns');

		o = bind(add(form.Flag, prefix + 'write_ipset_direct', _('Direct DNS result write to IPSet'),
			_('Perform the matching direct domain name rules into IP to IPSet/NFTSet, and then connect directly (not entering the core).') + ' ' +
			_('Maybe conflict with some special circumstances.')), 'write_ipset_direct');
		o.default = '1';
		o.rmempty = false;

		if (opts.geoview) {
			o = bind(add(form.Flag, prefix + 'enable_geoview_ip', _('Enable GeoIP Data Parsing')), 'enable_geoview_ip');
			o.default = '1';
			o.rmempty = false;
			o.description = '<ul><li>' + _('Analyzes and preloads GeoIP data to enhance the shunt performance.') + '</li>' +
				'<li>' + _('Note: Increases resource usage.') + ' ' + _('Maybe conflict with some special circumstances.') + '</li></ul>';
			const guardedWrite = o.write;
			o.write = function(sid, v) {
				const old = uci.get(UCI_CONF, nid, 'enable_geoview_ip') || '0';
				const r = guardedWrite.call(this, sid, v);
				if ((uci.get(UCI_CONF, nid, 'enable_geoview_ip') || '0') !== old && gsid)
					uci.set(UCI_CONF, gsid, 'flush_set', '1');
				return r;
			};
		}

		const og = bind(add(form.ListValue, prefix + 'shunt_group', _('Shunt Rule Group')), 'shunt_group');
		og.value('', _('default'));
		groups.forEach((g) => og.value(g));

		const rules = [];
		(uci.sections(UCI_CONF, 'shunt_rules') || []).forEach((r) => {
			rules.push({
				id: r['.name'],
				remarks: r.remarks || r['.name'],
				group: String(r.group || '').toLowerCase(),
				nodeOpt: r['.name'],
				nodeDefault: '',
				fakeOpt: r['.name'] + '_fakedns',
				proxyOpt: r['.name'] + '_proxy_tag'
			});
		});
		rules.push({
			id: '.default', remarks: _('Default'), group: '',
			nodeOpt: 'default_node', nodeDefault: '_direct',
			fakeOpt: 'default_fakedns', proxyOpt: 'default_proxy_tag'
		});

		const t = add(CBIShuntTable, prefix + '_table', ' ');
		t.depends(depKey, nid);
		t.nodeId = nid;
		t.nodes = nodes;
		t.rules = rules;
		t.normalIds = normalIds;
		t.groupOption = og;
		t.verify = verify;
		og.onchange = function(ev, sid, value) { t.filterRows(sid, value); };
		entry.table = t;
		entry.groupOption = og;
		result.nodes[nid] = entry;
	});

	return result;
}

/* ------------------------------------------------------------------ backend language
 * With luci.main.lang = auto the backend (logs, subscriptions, ...) translates with
 * passwall2.@global[0].auto_lang, which upstream's controller stores from the browser's
 * Accept-Language. Do the same once per browser session. */
(function syncAutoLang() {
	let langs = [];
	try {
		if (window.sessionStorage && sessionStorage.getItem('pw2-auto-lang'))
			return;
	}
	catch (e) {}
	try {
		langs = (navigator.languages && navigator.languages.length) ? Array.from(navigator.languages) : [ navigator.language || '' ];
	}
	catch (e) {}
	langs = langs.filter((l) => !!l);
	if (!langs.length)
		return;
	const accept = langs.map((l, i) => i ? l + ';q=' + Math.max(0.1, 1 - i / 10).toFixed(1) : l).join(',');
	L.resolveDefault(call('set_auto_lang', { accept_language: accept }), null).then(() => {
		try { sessionStorage.setItem('pw2-auto-lang', accept); } catch (e) {}
	});
})();

/* ------------------------------------------------------------------ export */

return baseclass.extend({
	APPNAME: APPNAME,
	BASE_PATH: BASE_PATH,
	TMP_PATH: TMP_PATH,

	call: call,
	url: url,
	loadCSS: loadCSS,
	wrap: wrap,

	getNodes: getNodes,
	getNodesSync: getNodesSync,
	getNodeList: getNodeList,
	getNodeListSync: getNodeListSync,
	nodeLabel: nodeLabel,
	nodeRemarks: nodeRemarks,
	protocolLabel: protocolLabel,
	isSpecialTarget: isSpecialTarget,
	editUrlFor: editUrlFor,

	badge: badge,
	setBadge: setBadge,
	card: card,
	button: button,
	icon: icon,
	pageHeader: pageHeader,
	poll: poll,
	unpoll: unpoll,
	notify: notify,
	textNode: textNode,
	showModal: showModal,
	confirm: confirmDialog,
	alert: alertDialog,
	showLog: showLog,
	logText: logText,
	redirectAfterApply: redirectAfterApply,

	addNodeOption: addNodeOption,
	addShuntOptions: addShuntOptions,
	buildNodeEntries: buildNodeEntries,
	NodePicker: NodePicker,
	NodeListValue: CBINodeListValue,
	NodeValue: CBINodeValue,
	NodeDynamicList: CBINodeDynamicList,
	HideValue: HideValue,
	ShuntTable: CBIShuntTable,

	getCacheVar: getCacheVar,
	parseCacheVar: parseCacheVar,
	findedCom: findedCom,
	isFinded: isFinded,
	comPath: comPath,
	getModules: getModules,
	tproxyOk: tproxyOk,
	globalSid: globalSid,

	datatype: checkDatatype,
	isIP: isIP,
	isIPv6: isIPv6,
	isBase64: isBase64,
	isJSON: isJSONText,
	isUUID: isUUID,
	isTimeHHMM: isTimeHHMM,
	legacyHour: legacyHour,
	legacyPorts: legacyPorts,
	aclMode: aclMode,
	escapeHTML: escapeHTML,
	trim: trim,
	randomChars: randomChars,
	latencyKind: latencyKind,
	b64ToBytes: b64ToBytes,
	bytesToB64: bytesToB64,
	downloadBlob: downloadBlob
});
