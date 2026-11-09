'use strict';
'require view';
'require uci';
'require ui';
'require dom';
'require passwall2.pw as pw';
'require passwall2.nodeform as nf';
'require passwall2.sharelink as sl';

/*
 * Node List (upstream: model/cbi/passwall2/client/node_list.lua, view/passwall2/node_list/node_list.htm,
 * htdocs/.../node_list_sort.js)
 *
 * - @global_other[0] options auto_detection_time / show_node_info / url_test_url saved immediately
 *   (save_node_list_opt), like upstream.
 * - group tabs, search/type/word filters, click-to-sort headers, drag & drop / "To Top" reordering.
 *   Order changes are persisted with "Save & Apply" (uci reorder of the nodes inside each group's slots).
 * - ICMP / TCP ping / URL test per node, automatic ping (localStorage cache 150 s / 60 s, 20 workers,
 *   5 s timeout, dedup by address:port) and "test all".
 * - add / copy / delete / delete selected / clear all / reassign group / use (set_node) /
 *   import share links (link_add_node, 1000 char chunks) / export share link + QR code.
 */

var CONF = 'passwall2';
var CHUNK = 1000;
var PING_WORKERS = 20, URLTEST_WORKERS = 3, PING_TIMEOUT = 5000;

function trim(s) { return (s == null ? '' : String(s)).replace(/^\s+|\s+$/g, ''); }

function typeLabel(n) {
	var type = n.type || '';
	if (type == 'sing-box' || type == 'Xray') {
		var p;
		switch (n.protocol) {
		case '_balancing': p = _('Balancing'); break;
		case '_urltest': p = 'URLTest'; break;
		case '_shunt': p = _('Shunt'); break;
		case '_iface': p = _('Interface'); break;
		default: p = nf.protoLabel(n.protocol || '');
		}
		if (type == 'sing-box') type = 'Sing-Box';
		type = type + ' ' + p;
	}
	if ((n.type == 'Hysteria2' || n.protocol == 'hysteria2') && n.hysteria2_realms)
		type += ' Realm';
	return trim(type);
}

function nodePort(n) { return n.port || n.hysteria_hop || n.hysteria2_hop || ''; }

/* get_address_full(): ping address, CJK addresses are treated as empty */
function pingAddress(n) {
	var a = n.address || '';
	return /[一-鿿]+/.test(a) ? '' : a;
}

/* func.js decodeIfBase64() */
function decodeIfBase64(str) {
	try {
		var s = str.replace(/-/g, '+').replace(/_/g, '/');
		s += '='.repeat((4 - s.length % 4) % 4);
		var decoded = decodeURIComponent(escape(atob(s)));
		var re = btoa(unescape(encodeURIComponent(decoded))).replace(/=+$/, '');
		return (re === s.replace(/=+$/, '')) ? decoded : str;
	} catch (e) {
		return str;
	}
}

function parseLatency(text) {
	var m = /^(\d+(?:[.,]\d+)?)\s*(ms|s)?$/i.exec(trim(text));
	if (!m) return null;
	var v = parseFloat(m[1].replace(',', '.'));
	return (m[2] && m[2].toLowerCase() == 's') ? v * 1000 : v;
}

function cacheGet(key) {
	try {
		var raw = window.localStorage.getItem(key);
		if (!raw) return null;
		var o = JSON.parse(raw);
		if (Date.now() - o.timestamp < o.savetime) return o;
		window.localStorage.removeItem(key);
	} catch (e) {}
	return null;
}

function cacheSet(key, value, savetime) {
	try {
		window.localStorage.setItem(key, JSON.stringify({ dom_id: key, timestamp: Date.now(), savetime: savetime, value: value }));
	} catch (e) {}
}

function cachePurge() {
	try {
		var ls = window.localStorage, keys = [];
		for (var i = 0; i < ls.length; i++) {
			var k = ls.key(i);
			if (k && (k.indexOf('icmp') === 0 || k.indexOf('tcping') === 0)) keys.push(k);
		}
		keys.forEach(function(k) {
			try {
				var o = JSON.parse(ls.getItem(k));
				if (!o || Date.now() - o.timestamp >= o.savetime) ls.removeItem(k);
			} catch (e) { ls.removeItem(k); }
		});
	} catch (e) {}
}

function withTimeout(p, ms) {
	return new Promise(function(resolve, reject) {
		var t = window.setTimeout(function() { reject(new Error('timeout')); }, ms);
		p.then(function(v) { window.clearTimeout(t); resolve(v); }, function(e) { window.clearTimeout(t); reject(e); });
	});
}

function processing() {
	ui.showModal(null, E('p', { 'class': 'spinning' }, [_('Processing, please wait…')]));
}

function collator() {
	try { return new Intl.Collator((L.env && L.env.lang) || undefined, { numeric: true, sensitivity: 'base' }); }
	catch (e) { return { compare: function(a, b) { return a < b ? -1 : (a > b ? 1 : 0); } }; }
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function() {
		return nf.loadEnv().then(function(env) {
			return Promise.all([env, L.resolveDefault(pw.call('get_now_use_node', {}), {})]);
		});
	},

	render: function(data) {
		var self = this;
		this.env = data[0];
		this.nowUse = (data[1] && data[1].global) || null;
		var other = uci.sections(CONF, 'global_other')[0] || {};
		this.opts = {
			auto: other.auto_detection_time || '0',
			info: other.show_node_info || '0',
			url: other.url_test_url || nf.PROBE_URLS[2][0]
		};
		this.gen = 0;
		this.dirty = {};
		this.sortState = {};
		this.filter = { q: '', type: '', word: '' };
		this.collectNodes();
		cachePurge();

		this.tabsEl = E('div', { 'class': 'pw-nl-tabs', 'role': 'tablist' });
		this.subInfoEl = E('div', { 'class': 'pw-nl-subinfo' });
		this.filterEl = E('div', { 'class': 'pw-nl-filter' });
		this.noteEl = E('div', { 'class': 'pw-nl-note' });
		this.tableEl = E('div', { 'class': 'pw-nl-tablewrap' });
		this.saveBtn = E('button', { 'class': 'btn cbi-button cbi-button-save important pw-btn', 'type': 'button', 'disabled': '',
			'click': ui.createHandlerFn(this, 'handleSaveOrder') }, [pw.icon('check'), ' ', E('span', {}, [_('Save & Apply')])]);

		var root = E('div', { 'class': 'pw-root pw-nl' }, [
			E('style', {}, [this.css()]),
			pw.pageHeader(_('Node List'), E('span', {}, [_('Nodes') + ': ', E('b', {}, [String(this.nodes.length)])]), [
				this.btn(_('Add'), 'add', 'handleAdd', 'add'),
				this.btn(_('Add the node via the link'), 'link', 'handleAddLink', 'apply'),
				this.saveBtn
			]),
			this.renderOptions(),
			pw.card(null,
				E('div', { 'class': 'pw-toolbar pw-nl-toolbar' }, [
					this.btn(_('Add'), 'add', 'handleAdd', 'add'),
					this.btn(_('Add the node via the link'), 'link', 'handleAddLink', 'apply'),
					this.btn(_('Clear all nodes'), 'delete', 'handleClearAll', 'remove'),
					this.btn(_('Delete select nodes'), 'delete', 'handleDeleteSelected', 'remove'),
					this.selectAllBtn = this.btn(_('Select all'), 'check', 'handleToggleSelectAll', 'neutral'),
					this.btn(_('Reassign Group'), 'list', 'handleReassign', 'neutral'),
					E('span', { 'class': 'pw-nl-sep' }),
					this.btn('Ping', 'ping', function() { return self.testAll('icmp'); }, 'neutral', _('Test all visible nodes')),
					this.btn('TCPing', 'ping', function() { return self.testAll('tcping'); }, 'neutral', _('Test all visible nodes')),
					this.btn(_('URL Test'), 'globe', function() { return self.testAll('urltest'); }, 'neutral', _('Test all visible nodes'))
				]),
				this.tabsEl,
				this.subInfoEl,
				this.filterEl,
				this.noteEl,
				this.tableEl
			)
		]);

		this.activeGroup = this.groupOrder[0] || null;
		try {
			var saved = window.sessionStorage.getItem('pw2-nl-group');
			if (saved && this.groups[saved]) this.activeGroup = saved;
		} catch (e) {}
		this.renderTabs();
		this.renderGroup();
		return root;
	},

	css: function() {
		return [
			'.pw-nl .pw-nl-toolbar{display:flex;flex-wrap:wrap;gap:.4em;align-items:center;margin-bottom:.8em}',
			'.pw-nl .pw-nl-sep{flex:0 0 1px;align-self:stretch;background:var(--pw-border,#ccc);margin:0 .2em}',
			'.pw-nl .pw-nl-opts{display:grid;grid-template-columns:repeat(auto-fit,minmax(15em,1fr));gap:.6em 1.2em;align-items:end}',
			'.pw-nl .pw-nl-opts label.pw-nl-optlabel{display:block;font-size:90%;opacity:.8;margin-bottom:.25em}',
			'.pw-nl .pw-nl-tabs{display:flex;flex-wrap:wrap;gap:.35em;margin:.2em 0 .6em}',
			'.pw-nl .pw-nl-tab{border:1px solid var(--pw-border,#ccc);background:transparent;color:inherit;border-radius:999px;padding:.3em .9em;cursor:pointer;display:inline-flex;gap:.4em;align-items:center}',
			'.pw-nl .pw-nl-tab.active{background:var(--pw-accent,#5e72e4);border-color:var(--pw-accent,#5e72e4);color:#fff}',
			'.pw-nl .pw-nl-tab .pw-nl-count{font-weight:700;color:#e33}',
			'.pw-nl .pw-nl-tab.active .pw-nl-count{color:#fff}',
			'.pw-nl .pw-nl-subinfo:not(:empty){margin:.2em 0 .6em;display:flex;gap:.5em;flex-wrap:wrap;align-items:center;font-size:92%}',
			'.pw-nl .pw-nl-filter{display:flex;flex-wrap:wrap;gap:.5em;align-items:center;margin-bottom:.6em}',
			'.pw-nl .pw-nl-filter.pw-filter-on{padding:.35em .5em;border-radius:8px;background:var(--pw-accent-soft,rgba(94,114,228,.12))}',
			'.pw-nl .pw-nl-filter input[type=search]{flex:1 1 12em;min-width:9em}',
			'.pw-nl .pw-nl-note:not(:empty){margin-bottom:.5em;font-size:92%;color:var(--pw-warn,#fb9a05)}',
			'.pw-nl table.pw-table{width:100%;border-collapse:separate;border-spacing:0}',
			'.pw-nl table.pw-table th{text-align:left;font-weight:600;padding:.5em .45em;border-bottom:1px solid var(--pw-border,#ddd);white-space:nowrap}',
			'.pw-nl table.pw-table td{padding:.45em;border-bottom:1px solid var(--pw-border,#eee);vertical-align:middle}',
			'.pw-nl table.pw-table tr.pw-nl-row:hover td{background:var(--pw-hover,rgba(94,114,228,.06))}',
			'.pw-nl tr.pw-row-hidden{display:none}',
			'.pw-nl tr._now_use_bg td{background:#5e72e445}',
			'@media (prefers-color-scheme: dark){.pw-nl tr._now_use_bg td{background:#4a90e240}}',
			'.pw-nl tr._now_use_bg .pw-nl-remark-text{color:#e33}',
			'.pw-nl tr.pw-dragging td{opacity:.55;background:var(--pw-accent-soft,rgba(94,114,228,.15))}',
			'.pw-nl .pw-nl-handle{cursor:grab;touch-action:none;opacity:.6;display:inline-flex;padding:.2em}',
			'.pw-nl .pw-nl-handle:active{cursor:grabbing}',
			'.pw-nl .pw-nl-remark{min-width:12em}',
			'.pw-nl .pw-nl-remark .pw-badge{margin-right:.4em}',
			'.pw-nl .pw-nl-addr{font-size:88%;opacity:.75;font-family:var(--pw-font-mono,monospace);word-break:break-all}',
			'.pw-nl .pw-nl-lat{white-space:nowrap;min-width:5em}',
			'.pw-nl .pw-nl-lat a{cursor:pointer;text-decoration:none}',
			'.pw-nl .pw-nl-lat .ok{color:#2dce89}.pw-nl .pw-nl-lat .warn{color:#fb9a05}.pw-nl .pw-nl-lat .err{color:#f5365c}',
			'.pw-nl .pw-nl-actions{display:flex;flex-wrap:wrap;gap:.25em;justify-content:flex-end}',
			'.pw-nl .pw-nl-actions .btn{padding:.2em .55em;line-height:1.4}',
			'.pw-nl th[data-pw-sort]{cursor:pointer;user-select:none}',
			'.pw-nl th .pw-nl-arrow{margin-left:.25em;opacity:.7}',
			'.pw-nl th .pw-nl-sub{font-weight:400;font-size:85%;margin-left:.5em}',
			'.pw-nl th .pw-nl-sub a{cursor:pointer;margin-right:.4em}',
			'.pw-nl th .pw-nl-sub a.pw-sort-active{font-weight:700;text-decoration:underline}',
			'.pw-nl .pw-nl-empty{padding:1.5em;text-align:center;opacity:.7}',
			'@media (max-width:760px){',
			'.pw-nl table.pw-table thead{display:none}',
			'.pw-nl table.pw-table,.pw-nl table.pw-table tbody{display:block}',
			'.pw-nl table.pw-table tr.pw-nl-row{display:grid;grid-template-columns:auto auto 1fr;grid-template-areas:"h c r" ". . ." "a a a";gap:.2em .5em;padding:.6em;margin-bottom:.6em;border:1px solid var(--pw-border,#ddd);border-radius:12px}',
			'.pw-nl table.pw-table tr.pw-nl-row.pw-row-hidden{display:none}',
			'.pw-nl table.pw-table td{border:0;padding:.15em}',
			'.pw-nl td.pw-nl-h{grid-area:h}.pw-nl td.pw-nl-c{grid-area:c}.pw-nl td.pw-nl-remark{grid-area:r;min-width:0}',
			'.pw-nl td.pw-nl-lat{display:inline-block}',
			'.pw-nl td.pw-nl-lat::before{content:attr(data-title) ": ";opacity:.6;font-size:85%}',
			'.pw-nl td.pw-nl-act{grid-area:a}',
			'.pw-nl .pw-nl-actions{justify-content:flex-start}',
			'}'
		].join('\n');
	},

	btn: function(label, iconName, handler, kind, title) {
		var fn = (typeof handler === 'function') ? handler : this[handler];
		return E('button', { 'class': 'btn cbi-button cbi-button-' + (kind || 'neutral') + ' pw-btn', 'type': 'button', 'title': title || null,
			'click': ui.createHandlerFn(this, fn) }, [pw.icon(iconName), ' ', E('span', {}, [label])]);
	},

	/* -------------------------------------------------------------------- data */

	collectNodes: function() {
		var all = uci.sections(CONF, 'nodes');
		/* get_node(): ungrouped nodes first, then the rest, each in UCI order */
		var nodes = all.filter(function(n) { return !n.group; }).concat(all.filter(function(n) { return !!n.group; }));
		this.nodes = nodes;
		this.byId = {};
		this.groups = {};
		this.groupOrder = [];
		var self = this;
		nodes.forEach(function(n) {
			self.byId[n['.name']] = n;
			var g = n.group || 'default';
			if (!self.groups[g]) { self.groups[g] = []; self.groupOrder.push(g); }
			self.groups[g].push(n['.name']);
		});
		this.origOrder = {};
		this.groupOrder.forEach(function(g) { self.origOrder[g] = self.groups[g].slice(); });
		this.subs = uci.sections(CONF, 'subscribe_list');
	},

	subscriptionOf: function(g) {
		var lower = String(g).toLowerCase();
		for (var i = 0; i < this.subs.length; i++)
			if (String(this.subs[i].remark || '').toLowerCase() == lower) return this.subs[i];
		return null;
	},

	visibleSelectedIds: function() {
		var ids = [];
		this.rows().forEach(function(tr) {
			if (!tr.classList.contains('pw-row-hidden') && tr.querySelector('input.nodes_select').checked)
				ids.push(tr.getAttribute('data-id'));
		});
		return ids;
	},

	rows: function() {
		return Array.prototype.slice.call(this.tableEl.querySelectorAll('tr.pw-nl-row'));
	},

	/* ----------------------------------------------------------------- options */

	renderOptions: function() {
		var self = this;
		var auto = E('select', { 'class': 'cbi-input-select' }, [
			E('option', { 'value': '0' }, [_('Close')]),
			E('option', { 'value': 'icmp' }, ['Ping']),
			E('option', { 'value': 'tcping' }, ['TCP Ping'])
		]);
		auto.value = this.opts.auto;
		auto.addEventListener('change', function() {
			self.saveOpt('auto_detection_time', auto.value).then(function() {
				self.opts.auto = auto.value;
				self.renderGroup();
			});
		});
		var info = E('input', { 'type': 'checkbox' });
		info.checked = this.opts.info == '1';
		info.addEventListener('change', function() {
			var v = info.checked ? '1' : '0';
			self.saveOpt('show_node_info', v).then(function() {
				self.opts.info = v;
				self.renderGroup();
			});
		});
		var choices = {};
		nf.PROBE_URLS.forEach(function(p) { choices[p[0]] = p[1]; });
		var urlBox = new ui.Combobox(this.opts.url, choices, { sort: nf.PROBE_URLS.map(function(p) { return p[0]; }), optional: false });
		var urlEl = urlBox.render();
		var lastUrl = this.opts.url;
		urlEl.addEventListener('cbi-dropdown-change', function() {
			var v = trim(urlBox.getValue());
			if (v && v != lastUrl) {
				self.saveOpt('url_test_url', v).then(function() { lastUrl = v; self.opts.url = v; });
			}
		});
		return pw.card(null, E('div', { 'class': 'pw-nl-opts' }, [
			E('div', {}, [E('label', { 'class': 'pw-nl-optlabel' }, [_('Automatic detection delay')]), auto]),
			E('div', {}, [E('label', { 'class': 'pw-nl-optlabel' }, [_('URL Test Address')]), urlEl]),
			E('div', {}, [E('label', { 'class': 'cbi-checkbox', 'style': 'display:inline-flex;gap:.5em;align-items:center' },
				[info, E('span', {}, [_('Show server address and port')])])])
		]));
	},

	saveOpt: function(option, value) {
		this.gen++;
		return pw.call('save_node_list_opt', { option: option, value: value }).catch(function(e) {
			ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
			throw e;
		});
	},

	/* -------------------------------------------------------------------- tabs */

	renderTabs: function() {
		var self = this;
		dom.content(this.tabsEl, this.groupOrder.map(function(g) {
			var sub = self.subscriptionOf(g);
			return E('button', {
				'type': 'button', 'role': 'tab',
				'class': 'pw-nl-tab' + (g == self.activeGroup ? ' active' : ''),
				'title': sub ? _('Subscribe') + ': ' + (sub.remark || '') : null,
				'click': function() {
					if (g == self.activeGroup) return;
					self.gen++;
					self.activeGroup = g;
					try { window.sessionStorage.setItem('pw2-nl-group', g); } catch (e) {}
					self.filter = { q: '', type: '', word: '' };
					self.renderTabs();
					self.renderGroup();
				}
			}, [
				sub ? pw.icon('refresh', 13) : '',
				E('span', {}, [g == 'default' ? _('default') : g]),
				E('span', {}, ['|']),
				E('span', { 'class': 'pw-nl-count' }, [String(self.groups[g].length)])
			]);
		}));
	},

	/* ------------------------------------------------------------------- table */

	renderGroup: function() {
		var self = this, g = this.activeGroup;
		this.gen++;
		dom.content(this.noteEl, []);
		dom.content(this.subInfoEl, []);
		if (!g || !this.groups[g]) {
			dom.content(this.filterEl, []);
			dom.content(this.tableEl, E('div', { 'class': 'pw-nl-empty' }, [_('No nodes!')]));
			return;
		}
		var sub = this.subscriptionOf(g);
		if (sub) {
			var count = this.nodes.filter(function(n) { return String(n.group || '').toLowerCase() == String(sub.remark || '').toLowerCase(); }).length;
			var parts = [pw.badge(_('Subscribe'), 'info'), E('span', {}, [_('Node num') + ': ' + count])];
			if (sub.rem_traffic || sub.expired_date)
				parts.push(E('span', {}, [(sub.rem_traffic || '') + ((sub.rem_traffic && sub.expired_date) ? '/' : '') + (sub.expired_date || '')]));
			parts.push(E('a', { 'href': pw.url('node_subscribe_config', sub['.name']) }, [_('Edit')]));
			dom.content(this.subInfoEl, parts);
		}

		var selAll = E('input', { 'type': 'checkbox', 'class': 'nodes_select_all', 'title': _('Select all') });
		selAll.addEventListener('change', function() { self.setSelectAll(selAll.checked); });
		this.selAllBox = selAll;
		var th = function(cls, key, title) {
			var t = E('th', { 'class': cls }, [title]);
			if (key) {
				t.setAttribute('data-pw-sort', key);
				t.setAttribute('title', _('Click to sort; click again to reverse. Press Save & Apply to keep the order.'));
				t.appendChild(E('span', { 'class': 'pw-nl-arrow' }));
				t.addEventListener('click', function(ev) {
					if (ev.target.closest('.pw-nl-sub')) return;
					self.sortBy(key);
				});
			}
			return t;
		};
		var remarkTh = th('pw-remark', 'name', _('Remarks'));
		remarkTh.appendChild(E('span', { 'class': 'pw-nl-sub' }, [
			E('a', { 'data-k': 'type', 'title': _('Sort by type or protocol, then by name'), 'click': function() { self.sortBy('type'); } }, [_('Type')]),
			E('a', { 'data-k': 'addr', 'title': _('Sort by server address and port'), 'click': function() { self.sortBy('addr'); } }, [_('Address')]),
			E('a', { 'data-k': 'orig', 'title': _('Restore the saved order'), 'click': function() { self.sortBy('orig'); } }, ['↺'])
		]));
		var thead = E('thead', {}, [E('tr', {}, [
			E('th', { 'style': 'width:1%' }),
			E('th', { 'style': 'width:1%' }, [selAll]),
			remarkTh,
			th('pw-ping', 'ping', 'Ping'),
			th('pw-tcping', 'tcping', 'TCPing'),
			th('pw-urltest', 'urltest', _('URL Test')),
			E('th', { 'style': 'text-align:right' }, [_('Actions')])
		])]);
		var tbody = E('tbody');
		this.groups[g].forEach(function(id, i) { tbody.appendChild(self.renderRow(self.byId[id], i)); });
		this.tbody = tbody;
		dom.content(this.tableEl, E('table', { 'class': 'pw-table table', 'id': 'cbi-passwall2-nodes-' + g + '-table' }, [thead, tbody]));
		this.updateSortIndicators();
		this.buildFilterBar();
		this.applyFilter();
		this.updateSelectState();
		this.markNowUse();
		this.autoPing();
	},

	renderRow: function(n, i) {
		var self = this, id = n['.name'];
		var addr = pingAddress(n), port = nodePort(n);
		var showInfo = this.opts.info == '1';
		var remark = E('div', { 'class': 'pw-nl-remark-inner' }, [
			pw.badge(typeLabel(n) || '?', (n.protocol || '').charAt(0) == '_' ? 'info' : 'muted'),
			E('span', { 'class': 'pw-nl-remark-text' }, [n.remarks || '']),
			E('span', { 'class': 'pw-nl-inuse' })
		]);
		if (showInfo && n.address && port) {
			var full = nf.isIPv6(n.address) ? '[' + n.address + ']' : n.address;
			remark.appendChild(E('div', { 'class': 'pw-nl-addr' }, [full + ':' + String(port).replace(/:/g, '-')]));
		}
		var auto = this.opts.auto;
		var latCell = function(kind, title) {
			var td = E('td', { 'class': 'pw-nl-lat pw-' + (kind == 'icmp' ? 'ping' : kind), 'data-title': title });
			var usable = (kind == 'icmp') ? !!addr : !!(addr && port);
			if (kind == 'urltest') usable = !!(n.address && port);
			if (!usable) {
				td.textContent = '---';
			} else if ((kind == 'icmp' && auto == 'icmp') || (kind == 'tcping' && auto == 'tcping')) {
				td.appendChild(E('a', { 'class': 'pw-nl-auto', 'click': function() { self.testOne(id, kind, td); } }, ['---']));
				td.setAttribute('data-auto', '1');
			} else {
				td.appendChild(E('a', { 'click': function() { self.testOne(id, kind, td); } }, [_('Test')]));
			}
			td.setAttribute('data-kind', kind);
			return td;
		};
		var actBtn = function(label, iconName, kind, fn, title) {
			return E('button', { 'class': 'btn cbi-button cbi-button-' + kind, 'type': 'button', 'title': title || label,
				'click': ui.createHandlerFn(self, fn) }, [pw.icon(iconName, 14), E('span', { 'class': 'pw-nl-btnlabel' }, [' ' + label])]);
		};
		var handle = E('span', { 'class': 'pw-nl-handle', 'title': _('Drag to reorder') }, [pw.icon('drag', 16)]);
		handle.addEventListener('pointerdown', function(ev) { self.dragStart(ev, tr); });
		var cb = E('input', { 'type': 'checkbox', 'class': 'nodes_select', 'cbid': id });
		cb.addEventListener('change', function() { self.updateSelectState(); });
		var special = (n.protocol || '').charAt(0) == '_';
		var tr = E('tr', { 'class': 'pw-nl-row cbi-rowstyle-' + (1 + i % 2), 'id': 'cbi-passwall2-' + id, 'data-id': id }, [
			E('td', { 'class': 'pw-nl-h' }, [handle]),
			E('td', { 'class': 'pw-nl-c' }, [cb]),
			E('td', { 'class': 'pw-nl-remark pw-remark' }, [remark]),
			latCell('icmp', 'Ping'),
			latCell('tcping', 'TCPing'),
			latCell('urltest', _('URL Test')),
			E('td', { 'class': 'pw-nl-act' }, [E('div', { 'class': 'pw-nl-actions' }, [
				actBtn(_('To Top'), 'chevron', 'neutral', function() { self.rowTop(tr); }),
				actBtn(_('Use'), 'play', 'apply', function() { return self.handleUse(id); }),
				special ? '' : actBtn(_('Share'), 'link', 'neutral', function() { return self.handleShare(id); }, _('Build Share URL') + ' / ' + _('Generate QRCode')),
				actBtn(_('Copy'), 'copy', 'neutral', function() { return self.handleCopy(id); }),
				E('a', { 'class': 'btn cbi-button cbi-button-edit', 'href': pw.url('node_config', id), 'title': _('Edit') },
					[pw.icon('edit', 14), E('span', { 'class': 'pw-nl-btnlabel' }, [' ' + _('Edit')])]),
				actBtn(_('Delete'), 'delete', 'remove', function() { return self.handleDelete(id); })
			])])
		]);
		return tr;
	},

	markNowUse: function() {
		var self = this;
		this.rows().forEach(function(tr) {
			var on = tr.getAttribute('data-id') === self.nowUse;
			tr.classList.toggle('_now_use_bg', on);
			tr.title = on ? _('Using...') : '';
			var slot = tr.querySelector('.pw-nl-inuse');
			dom.content(slot, on ? [' ', pw.badge(_('Using...'), 'ok')] : []);
		});
	},

	restyleRows: function() {
		this.rows().forEach(function(tr, i) {
			tr.classList.remove('cbi-rowstyle-1', 'cbi-rowstyle-2');
			tr.classList.add('cbi-rowstyle-' + (1 + i % 2));
		});
	},

	/* --------------------------------------------------------- order handling */

	setOrderFromDom: function(note) {
		var g = this.activeGroup;
		this.groups[g] = this.rows().map(function(tr) { return tr.getAttribute('data-id'); });
		var changed = this.groups[g].join(' ') !== this.origOrder[g].join(' ');
		if (changed) this.dirty[g] = true; else delete this.dirty[g];
		var anyDirty = Object.keys(this.dirty).length > 0;
		if (anyDirty) this.saveBtn.removeAttribute('disabled'); else this.saveBtn.setAttribute('disabled', '');
		this.restyleRows();
		if (note !== false)
			dom.content(this.noteEl, changed ? [_('The order changed on this page only. Press Save & Apply to store it on the router.')]
				: (note === 'restored' ? [_('Saved order restored.')] : []));
	},

	rowTop: function(tr) {
		this.tbody.insertBefore(tr, this.tbody.firstChild);
		this.setOrderFromDom();
	},

	dragStart: function(ev, tr) {
		if (ev.button != null && ev.button !== 0) return;
		ev.preventDefault();
		var self = this, tbody = this.tbody;
		var handle = ev.currentTarget;
		try { handle.setPointerCapture(ev.pointerId); } catch (e) {}
		tr.classList.add('pw-dragging');
		var move = function(e) {
			var el = document.elementFromPoint(e.clientX, e.clientY);
			var over = el && el.closest ? el.closest('tr.pw-nl-row') : null;
			if (!over || over === tr || over.parentNode !== tbody) return;
			var rect = over.getBoundingClientRect();
			var after = (e.clientY - rect.top) > rect.height / 2;
			tbody.insertBefore(tr, after ? over.nextSibling : over);
		};
		var up = function() {
			handle.removeEventListener('pointermove', move);
			handle.removeEventListener('pointerup', up);
			handle.removeEventListener('pointercancel', up);
			tr.classList.remove('pw-dragging');
			self.setOrderFromDom();
		};
		handle.addEventListener('pointermove', move);
		handle.addEventListener('pointerup', up);
		handle.addEventListener('pointercancel', up);
	},

	handleSaveOrder: function() {
		var self = this;
		if (!Object.keys(this.dirty).length) return;
		/* keep each group's slots in the global node order, fill them with the new group order;
		 * other section types keep their positions (upstream reorders to absolute indexes) */
		var queues = {};
		this.groupOrder.forEach(function(g) { queues[g] = self.groups[g].slice(); });
		var desired = uci.sections(CONF).map(function(sec) {
			if (sec['.type'] != 'nodes') return sec['.name'];
			var g = sec.group || 'default';
			return (queues[g] && queues[g].length) ? queues[g].shift() : sec['.name'];
		});
		for (var i = 1; i < desired.length; i++)
			uci.move(CONF, desired[i], desired[i - 1], true);
		return uci.save().then(function() {
			self.dirty = {};
			self.saveBtn.setAttribute('disabled', '');
			pw.redirectAfterApply(pw.url('node_list'));
			return ui.changes.apply(true);
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
		});
	},

	/* ----------------------------------------------------------------- sorting */

	sortKey: function(tr, key) {
		var id = tr.getAttribute('data-id'), n = this.byId[id] || {};
		var cellText = function(cls) { var c = tr.querySelector('td.' + cls); return c ? c.textContent : ''; };
		switch (key) {
		case 'name': return n.remarks || cellText('pw-remark');
		case 'type': return typeLabel(n).replace(/ Realm$/, '') + '\0' + (n.remarks || '');
		case 'addr':
			if (!n.address) return null;
			return n.address + '\0' + ('00000' + String(nodePort(n))).slice(-5);
		case 'ping': return parseLatency(cellText('pw-ping'));
		case 'tcping': return parseLatency(cellText('pw-tcping'));
		case 'urltest': return parseLatency(cellText('pw-urltest'));
		}
		return null;
	},

	pingRunning: function() {
		var mode = this.opts.auto;
		if (mode != 'icmp' && mode != 'tcping') return 0;
		var cls = mode == 'icmp' ? 'pw-ping' : 'pw-tcping';
		return this.rows().filter(function(tr) {
			var td = tr.querySelector('td.' + cls);
			return td && td.getAttribute('data-auto') == '1' && trim(td.textContent) == '---';
		}).length + (this.inflight || 0);
	},

	sortBy: function(key) {
		var self = this, g = this.activeGroup;
		if (this.waitTimer) { window.clearInterval(this.waitTimer); this.waitTimer = null; }
		if (key != 'orig' && key != 'name' && key != 'type' && key != 'addr' && this.pingRunning() > 0) {
			var started = Date.now(), idle = 0;
			var tick = function() {
				var left = self.pingRunning();
				dom.content(self.noteEl, [_('Automatic ping is still running (%d left). Sorting will run when it finishes.').replace('%d', left)]);
				if (!self.inflight) idle++; else idle = 0;
				if (left == 0 || idle >= 6) {
					window.clearInterval(self.waitTimer); self.waitTimer = null;
					self.sortBy(key);
				} else if (Date.now() - started > 120000) {
					window.clearInterval(self.waitTimer); self.waitTimer = null;
					dom.content(self.noteEl, [_('Automatic ping did not finish within 2 minutes. Sorting was cancelled. Reload the page and try again.')]);
				}
			};
			this.waitTimer = window.setInterval(tick, 500);
			tick();
			return;
		}
		var st = this.sortState[g] || {};
		var rows = this.rows();
		if (key == 'orig') {
			var pos = {};
			this.origOrder[g].forEach(function(id, i) { pos[id] = i; });
			rows.sort(function(a, b) { return pos[a.getAttribute('data-id')] - pos[b.getAttribute('data-id')]; });
			this.sortState[g] = { key: 'orig' };
		} else {
			var desc = (st.key == key) ? !st.desc : false;
			var coll = collator();
			var keyed = rows.map(function(tr, i) { return { tr: tr, i: i, k: self.sortKey(tr, key) }; });
			keyed.sort(function(a, b) {
				var ka = a.k, kb = b.k;
				var ea = (ka == null || ka === ''), eb = (kb == null || kb === '');
				if (ea && eb) return a.i - b.i;
				if (ea) return 1;
				if (eb) return -1;
				var c = (typeof ka == 'number' && typeof kb == 'number') ? ka - kb : coll.compare(String(ka), String(kb));
				if (c === 0) return a.i - b.i;
				return desc ? -c : c;
			});
			rows = keyed.map(function(x) { return x.tr; });
			this.sortState[g] = { key: key, desc: desc };
		}
		rows.forEach(function(tr) { self.tbody.appendChild(tr); });
		this.setOrderFromDom(key == 'orig' ? 'restored' : true);
		this.updateSortIndicators();
		this.applyFilter();
	},

	updateSortIndicators: function() {
		var st = this.sortState[this.activeGroup] || {};
		this.tableEl.querySelectorAll('th[data-pw-sort]').forEach(function(th) {
			var k = th.getAttribute('data-pw-sort'), a = th.querySelector('.pw-nl-arrow');
			if (a) a.textContent = (st.key == k) ? (st.desc ? '▼' : '▲') : '';
		});
		this.tableEl.querySelectorAll('.pw-nl-sub a').forEach(function(a) {
			a.classList.toggle('pw-sort-active', a.getAttribute('data-k') == st.key);
		});
		if (st.key == 'type' || st.key == 'addr') {
			var a2 = this.tableEl.querySelector('th[data-pw-sort=name] .pw-nl-arrow');
			if (a2) a2.textContent = st.desc ? '▼' : '▲';
		}
	},

	/* ----------------------------------------------------------------- filter */

	buildFilterBar: function() {
		var self = this, ids = this.groups[this.activeGroup] || [];
		if (ids.length < 2) { dom.content(this.filterEl, []); return; }
		var types = {}, words = {};
		ids.forEach(function(id) {
			var n = self.byId[id];
			var t = typeLabel(n);
			var tk = t.toLowerCase();
			types[tk] = types[tk] || { label: t, count: 0 };
			types[tk].count++;
			var seen = {};
			String(n.remarks || '').split(/[^\p{L}\p{N}]+/u).forEach(function(w) {
				if (w.length < 2 || /^\d+$/.test(w)) return;
				var k = w.toLowerCase();
				if (seen[k]) return;
				seen[k] = true;
				words[k] = words[k] || { label: w, count: 0 };
				words[k].count++;
			});
		});
		var children = [E('span', {}, [_('Filter:')])];
		var typeKeys = Object.keys(types);
		if (typeKeys.length >= 2) {
			var ts = E('select', { 'class': 'cbi-input-select', 'title': _('Type') }, [E('option', { 'value': '' }, [_('Type') + ': ' + _('All')])]);
			typeKeys.sort(function(a, b) { return types[a].label.localeCompare(types[b].label); }).forEach(function(k) {
				ts.appendChild(E('option', { 'value': k }, [(types[k].label || _('(empty)')) + ' (' + types[k].count + ')']));
			});
			ts.value = this.filter.type;
			ts.addEventListener('change', function() { self.filter.type = ts.value; self.applyFilter(); });
			children.push(ts);
		}
		var wordKeys = Object.keys(words).filter(function(k) { return words[k].count >= 2 && words[k].count < ids.length; })
			.sort(function(a, b) { return (words[b].count - words[a].count) || words[a].label.localeCompare(words[b].label); }).slice(0, 40);
		if (wordKeys.length) {
			var ws = E('select', { 'class': 'cbi-input-select', 'title': _('Word in remarks') }, [E('option', { 'value': '' }, [_('Word in remarks') + ': ' + _('All')])]);
			wordKeys.forEach(function(k) { ws.appendChild(E('option', { 'value': k }, [words[k].label + ' (' + words[k].count + ')'])); });
			ws.value = this.filter.word;
			ws.addEventListener('change', function() { self.filter.word = ws.value; self.applyFilter(); });
			children.push(ws);
		}
		var q = E('input', { 'type': 'search', 'class': 'cbi-input-text', 'placeholder': _('search...'), 'title': _('Show only rows that contain this text'), 'value': this.filter.q });
		var t = null;
		q.addEventListener('input', function() {
			window.clearTimeout(t);
			t = window.setTimeout(function() { self.filter.q = q.value; self.applyFilter(); }, 150);
		});
		children.push(q);
		this.shownEl = E('span', { 'class': 'pw-nl-shown' });
		children.push(this.shownEl);
		children.push(E('button', { 'class': 'btn cbi-button cbi-button-neutral', 'type': 'button', 'title': _('Show all rows'),
			'click': function() { self.filter = { q: '', type: '', word: '' }; self.buildFilterBar(); self.applyFilter(); } }, [_('Reset')]));
		children.push(E('span', { 'title': _('The filter only hides rows on this page and changes nothing on the router. Select all skips hidden rows.'), 'style': 'cursor:help;opacity:.7' }, [pw.icon('info', 14)]));
		dom.content(this.filterEl, children);
	},

	applyFilter: function() {
		var self = this, f = this.filter;
		var q = trim(f.q).toLowerCase();
		var shown = 0, total = 0;
		this.rows().forEach(function(tr) {
			var n = self.byId[tr.getAttribute('data-id')] || {};
			var t = typeLabel(n);
			var hay = (t + ' ' + (n.remarks || '') + ' ' + (n.address || '') + ':' + nodePort(n)).toLowerCase();
			var ok = true;
			if (f.type && t.toLowerCase() != f.type) ok = false;
			if (ok && f.word) {
				var words = String(n.remarks || '').split(/[^\p{L}\p{N}]+/u).map(function(w) { return w.toLowerCase(); });
				if (words.indexOf(f.word) < 0) ok = false;
			}
			if (ok && q && hay.indexOf(q) < 0) ok = false;
			tr.classList.toggle('pw-row-hidden', !ok);
			if (!ok) tr.querySelector('input.nodes_select').checked = false;
			total++;
			if (ok) shown++;
		});
		if (this.shownEl)
			this.shownEl.textContent = _('Shown %s of %t').replace('%s', shown).replace('%t', total);
		this.filterEl.classList.toggle('pw-filter-on', !!(f.q || f.type || f.word));
		this.updateSelectState();
	},

	/* -------------------------------------------------------------- selection */

	setSelectAll: function(state) {
		this.rows().forEach(function(tr) {
			var cb = tr.querySelector('input.nodes_select');
			cb.checked = state && !tr.classList.contains('pw-row-hidden');
		});
		this.updateSelectState();
	},

	updateSelectState: function() {
		var vis = this.rows().filter(function(tr) { return !tr.classList.contains('pw-row-hidden'); });
		var all = vis.length > 0 && vis.every(function(tr) { return tr.querySelector('input.nodes_select').checked; });
		if (this.selAllBox) this.selAllBox.checked = all;
		if (this.selectAllBtn) {
			this.selectAllBtn.lastChild.textContent = all ? _('DeSelect all') : _('Select all');
			this.selectAllBtn.setAttribute('data-all', all ? '1' : '0');
		}
	},

	handleToggleSelectAll: function() {
		this.setSelectAll(this.selectAllBtn.getAttribute('data-all') != '1');
	},

	/* ---------------------------------------------------------------- latency */

	showLatency: function(td, kind, ms) {
		var id = td.closest('tr') && td.closest('tr').getAttribute('data-id');
		var self = this;
		var span;
		if (ms === 'error') span = E('span', { 'class': 'err' }, [_('Error')]);
		else if (ms == null || ms === '' || ms < 0) span = E('span', { 'class': 'err' }, [_('Timeout')]);
		else {
			var v = Number(ms);
			var okB = kind == 'urltest' ? 1000 : 100, warnB = kind == 'urltest' ? 2000 : 200;
			span = E('span', { 'class': v < okB ? 'ok' : (v < warnB ? 'warn' : 'err') }, [String(ms) + ' ms']);
		}
		dom.content(td, E('a', { 'title': _('Test'), 'click': function() { if (id) self.testOne(id, kind, td); } }, [span]));
	},

	callTest: function(id, kind) {
		var n = this.byId[id] || {};
		if (kind == 'urltest')
			return withTimeout(pw.call('urltest_node', { index: '0', id: id }), 60000).then(function(r) { return r && r.use_time; });
		var addr = pingAddress(n), port = nodePort(n);
		return withTimeout(pw.call('ping_node', { index: '0', address: addr, port: String(port), type: kind }), PING_TIMEOUT)
			.then(function(r) { return r && r.ping; });
	},

	testOne: function(id, kind, td) {
		var self = this;
		if (td.dataset.busy == '1') return;
		td.dataset.busy = '1';
		dom.content(td, E('span', {}, [_('Check...')]));
		var gen = this.gen;
		return this.callTest(id, kind).then(function(v) {
			if (gen != self.gen && !td.isConnected) return;
			self.showLatency(td, kind, (v === '' || v == null) ? null : v);
			var n = self.byId[id] || {};
			if (kind != 'urltest')
				cacheSet(kind + ':' + pingAddress(n) + ':' + nodePort(n), (v === '' || v == null) ? -1 : Number(v), (v === '' || v == null) ? 60000 : 150000);
		}, function(e) {
			self.showLatency(td, kind, (e && e.message == 'timeout') ? null : 'error');
		}).finally(function() { td.dataset.busy = '0'; });
	},

	runQueue: function(items, workers, worker) {
		var self = this, gen = this.gen, idx = 0;
		var next = function() {
			if (gen != self.gen || idx >= items.length) return Promise.resolve();
			var it = items[idx++];
			self.inflight = (self.inflight || 0) + 1;
			return Promise.resolve(worker(it)).catch(function() {}).finally(function() {
				self.inflight--;
			}).then(next);
		};
		var ps = [];
		for (var i = 0; i < Math.min(workers, items.length); i++) ps.push(next());
		return Promise.all(ps);
	},

	/* pingAllNodes(): automatic ICMP / TCP ping with dedup and localStorage cache */
	autoPing: function() {
		var self = this, mode = this.opts.auto;
		if (mode != 'icmp' && mode != 'tcping') return;
		var cls = mode == 'icmp' ? 'pw-ping' : 'pw-tcping';
		var groups = {}, order = [];
		this.rows().forEach(function(tr) {
			var td = tr.querySelector('td.' + cls);
			if (!td || td.getAttribute('data-auto') != '1') return;
			var n = self.byId[tr.getAttribute('data-id')];
			var addr = pingAddress(n), port = nodePort(n);
			if (!addr || (mode == 'tcping' && !port)) return;
			var key = mode + ':' + addr + ':' + port;
			var cached = cacheGet(key);
			if (cached) {
				self.showLatency(td, mode, cached.value >= 0 ? cached.value : null);
				return;
			}
			if (!groups[key]) { groups[key] = { addr: addr, port: port, tds: [] }; order.push(key); }
			groups[key].tds.push(td);
		});
		var gen = this.gen;
		return this.runQueue(order, PING_WORKERS, function(key) {
			var g = groups[key];
			return withTimeout(pw.call('ping_node', { index: '0', address: g.addr, port: String(g.port), type: mode }), PING_TIMEOUT).then(function(r) {
				if (gen != self.gen) return;
				var v = r && r.ping;
				if (v != null && v !== '') {
					cacheSet(key, Number(v), 150000);
					g.tds.forEach(function(td) { self.showLatency(td, mode, v); });
				} else {
					cacheSet(key, -1, 60000);
					g.tds.forEach(function(td) { self.showLatency(td, mode, null); });
				}
			}, function() {
				if (gen != self.gen) return;
				g.tds.forEach(function(td) { self.showLatency(td, mode, null); });
			});
		});
	},

	/* Cancel every queued (not yet started) latency test: runQueue() stops at the next item.
	 * Only for actions that are about to talk to the router / leave the page, so their
	 * request is not stuck behind a long test queue. */
	stopTests: function() {
		this.gen++;
	},

	testAll: function(kind) {
		var self = this;
		var cls = kind == 'icmp' ? 'pw-ping' : (kind == 'tcping' ? 'pw-tcping' : 'pw-urltest');
		var run = this.testRun = (this.testRun || 0) + 1;
		var items = [];
		this.rows().forEach(function(tr) {
			if (tr.classList.contains('pw-row-hidden')) return;
			var td = tr.querySelector('td.' + cls);
			if (!td || td.dataset.busy == '1') return;
			/* a cell still waiting in an earlier, cancelled run is taken over (it has no link now) */
			var waiting = td.dataset.queued != null;
			if (!waiting && !td.querySelector('a')) return;
			if (!waiting)
				td._pwOrig = Array.prototype.slice.call(td.childNodes);
			td.dataset.queued = String(run);
			items.push({ id: tr.getAttribute('data-id'), td: td });
			dom.content(td, E('span', {}, ['…']));
		});
		this.gen++;
		var mine = function(it) { return it.td.dataset.queued == String(run); };
		var release = function(it) { delete it.td.dataset.queued; delete it.td._pwOrig; };
		return this.runQueue(items, kind == 'urltest' ? URLTEST_WORKERS : PING_WORKERS, function(it) {
			if (!mine(it)) return;
			release(it);
			return self.testOne(it.id, kind, it.td);
		}).then(function() {
			/* the queue was cancelled (stopTests / another run / re-render): put back what the
			 * untouched cells showed before, so they can be clicked or tested again */
			items.forEach(function(it) {
				if (!mine(it)) return;
				var orig = it.td._pwOrig;
				release(it);
				if (it.td.isConnected)
					dom.content(it.td, orig && orig.length ? orig : E('a', { 'click': function() { self.testOne(it.id, kind, it.td); } }, [_('Test')]));
			});
		});
	},

	/* ---------------------------------------------------------------- actions */

	reload: function() {
		window.location.href = pw.url('node_list');
	},

	/* add_node / copy_node return the new section id as `result` */
	idFromResult: function(res) {
		var id = res && res.result;
		return (typeof id === 'string' && /^[A-Za-z0-9_]+$/.test(id)) ? id : null;
	},

	handleAdd: function() {
		var self = this;
		this.gen++;
		var g = this.activeGroup || 'default';
		return pw.call('add_node', { redirect: '0', group: g }).then(function(res) {
			var id = self.idFromResult(res);
			if (id) window.location.href = pw.url('node_config', id);
			else self.reload();
		}).catch(function(e) { ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger'); });
	},

	handleCopy: function(id) {
		var self = this;
		this.gen++;
		return pw.call('copy_node', { section: id }).then(function(res) {
			var nid = self.idFromResult(res);
			if (nid && nid != id) window.location.href = pw.url('node_config', nid);
			else self.reload();
		}).catch(function(e) { ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger'); });
	},

	handleDelete: function(id) {
		var self = this;
		var n = this.byId[id] || {};
		return pw.confirm(_('Delete'), _('Are you sure to delete select nodes?') + ' (' + (n.remarks || id) + ')').then(function(ok) {
			if (!ok) return;
			self.stopTests();
			processing();
			return pw.call('delete_select_nodes', { ids: id }).then(function() { self.reload(); }, function(e) {
				ui.hideModal();
				ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
			});
		});
	},

	handleDeleteSelected: function() {
		var self = this;
		var ids = this.visibleSelectedIds();
		if (!ids.length) {
			ui.addNotification(null, E('p', {}, [_('You no select nodes !')]), 'warning');
			return;
		}
		return pw.confirm(_('Delete select nodes'), _('Are you sure to delete select nodes?')).then(function(ok) {
			if (!ok) return;
			self.stopTests();
			processing();
			return pw.call('delete_select_nodes', { ids: ids.join(',') }).then(function() { self.reload(); }, function(e) {
				ui.hideModal();
				ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
			});
		});
	},

	handleClearAll: function() {
		var self = this;
		return pw.confirm(_('Clear all nodes'), _('Are you sure to clear all nodes?')).then(function(ok) {
			if (!ok) return;
			self.stopTests();
			processing();
			return pw.call('clear_all_nodes', {}).then(function() { self.reload(); }, function(e) {
				ui.hideModal();
				ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
			});
		});
	},

	/* group picker of the add-link / reassign modals (init_group_dropdown) */
	groupPicker: function() {
		var choices = { 'default': _('default') };
		var order = ['default'];
		this.groupOrder.forEach(function(g) { if (!choices[g]) { choices[g] = g; order.push(g); } });
		var dd = new ui.Combobox('default', choices, { sort: order, optional: false, custom_placeholder: _('-- custom --') });
		var el = dd.render();
		var existing = order;
		return {
			el: el,
			get: function() {
				var v = trim(dd.getValue());
				if (v === '') return 'default';
				var lower = v.toLowerCase();
				for (var i = 0; i < existing.length; i++)
					if (existing[i].toLowerCase() == lower) return existing[i];
				return v;
			}
		};
	},

	handleReassign: function() {
		var self = this;
		var ids = this.visibleSelectedIds();
		if (!ids.length) {
			ui.addNotification(null, E('p', {}, [_('You no select nodes !')]), 'warning');
			return;
		}
		var gp = this.groupPicker();
		pw.showModal(_('Reassign Node Group'), [
			E('div', { 'class': 'pw-root pw-modal' }, [
				E('p', {}, [_('Nodes') + ': ' + ids.length]),
				E('label', {}, [_('Group Name')]), gp.el
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', 'click': ui.hideModal }, [_('Close')]), ' ',
				E('button', { 'class': 'btn cbi-button-action important', 'click': function() {
					var g = gp.get();
					self.stopTests();
					processing();
					pw.call('reassign_group', { group: g, ids: ids.join(',') }).then(function() { self.reload(); }, function(e) {
						ui.hideModal();
						ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
					});
				} }, [_('Save')])
			])
		]);
	},

	handleAddLink: function() {
		var self = this;
		var ta = E('textarea', { 'id': 'nodes_link', 'class': 'cbi-input-textarea', 'rows': 10,
			'style': 'width:100%;font-family:monospace;white-space:pre', 'wrap': 'off' });
		var gp = this.groupPicker();
		pw.showModal(_('Add the node via the link'), [
			E('div', { 'class': 'pw-root pw-modal' }, [
				ta,
				E('p', { 'style': 'color:red' }, [_('Enter share links, one per line. Subscription links are not supported!')]),
				E('label', {}, [_('Group Name')]), gp.el
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', 'click': ui.hideModal }, [_('Close')]), ' ',
				E('button', { 'class': 'btn cbi-button-action important', 'click': function() {
					var s = ta.value.replace(/\t/g, '').replace(/\r\n?/g, '\n').replace(/<[^>]*>/g, '');
					s = trim(s);
					if (s === '') { ta.focus(); return; }
					s = decodeIfBase64(s);
					if (s.indexOf('://') < 0) {
						ui.addNotification(null, E('p', {}, [_('Please enter the correct link.')]), 'warning');
						return;
					}
					var group = gp.get();
					ui.hideModal();
					self.addLinks(s, group);
				} }, [_('Add')])
			])
		]);
		window.setTimeout(function() { ta.focus(); }, 50);
	},

	/* ajax_add_node(): 1000 character chunks, posted sequentially */
	addLinks: function(link, group) {
		var self = this;
		this.stopTests();
		processing();
		var chunks = [];
		for (var i = 0; i < link.length; i += CHUNK) chunks.push(link.substring(i, i + CHUNK));
		var total = chunks.length;
		var p = Promise.resolve();
		chunks.forEach(function(c, idx) {
			p = p.then(function() {
				return pw.call('link_add_node', { chunk: c, chunk_index: String(idx), total_chunks: String(total), group: group });
			});
		});
		return p.then(function() { self.reload(); }, function(e) {
			ui.hideModal();
			ui.addNotification(null, E('p', {}, [(e && /network|fetch/i.test(String(e.message || e)) ? _('Network Error') : _('Error')) + ': ' + (e && e.message || e)]), 'danger');
		});
	},

	/* "Use" dialog (set_node_div) */
	handleUse: function(id) {
		var self = this;
		var n = this.byId[id] || {};
		var gnode = uci.get_first(CONF, 'global', 'node');
		var gsec = gnode ? uci.get(CONF, gnode) : null;
		var buttons = [];
		var set = function(type, config) {
			return pw.confirm(_('Use'), _('Are you sure set this node?')).then(function(ok) {
				if (!ok) return;
				self.stopTests();
				processing();
				return pw.call('set_node', { type: type, config: config, section: id }).then(function() {
					window.location.href = pw.url('log');
				}, function(e) {
					ui.hideModal();
					ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
				});
			});
		};
		if (gsec && gsec.protocol == '_shunt') {
			var grp = gsec.shunt_group;
			uci.sections(CONF, 'shunt_rules').forEach(function(e) {
				if (e['.name'] && e.remarks && (e.group || null) == (grp || null))
					buttons.push(E('button', { 'class': 'btn cbi-button cbi-button-apply', 'click': function() { set(gnode, e['.name']); } }, [e.remarks]));
			});
			buttons.push(E('button', { 'class': 'btn cbi-button cbi-button-apply', 'click': function() { set(gnode, 'default_node'); } }, [_('Default')]));
		} else {
			buttons.push(E('button', { 'class': 'btn cbi-button cbi-button-apply', 'click': function() { set('@global[0]', 'node'); } }, [_('Node')]));
		}
		pw.showModal(_('You choose node is:') + ' ' + (n.remarks || id), [
			E('div', { 'class': 'pw-root pw-modal', 'style': 'display:flex;flex-wrap:wrap;gap:.5em' }, buttons),
			E('div', { 'class': 'right' }, [E('button', { 'class': 'btn cbi-button', 'click': ui.hideModal }, [_('Close')])])
		]);
	},

	/* share link / QR of a stored node (same rules as the node editor's "Build Share URL") */
	handleShare: function(id) {
		var n = uci.get(CONF, id) || {};
		var type = n.type || '';
		var kind = nf.protocolKind(type, n.protocol);
		var url = null;
		try {
			var ctx = nf.makeCtx(this.env, id, kind);
			ctx.type = type;
			var specs = nf.getSpecs(type, ctx);
			var res = sl.buildUrl(nf.virtualForm(specs, n), type, n.remarks || '');
			url = res.url || null;
		} catch (e) { url = null; }
		if (!url) {
			ui.addNotification(null, E('p', {}, [_('Not a supported scheme:') + ' ' + type]), 'warning');
			return;
		}
		var holder = E('div', { 'style': 'display:flex;justify-content:center' });
		try { holder.innerHTML = sl.qrSVG(url, 240); } catch (e) { holder.textContent = String(e.message || e); }
		var status = E('span');
		pw.showModal(n.remarks || id, [
			E('div', { 'class': 'pw-root pw-modal', 'style': 'display:flex;flex-direction:column;gap:.75em;align-items:stretch' }, [
				holder,
				E('textarea', { 'class': 'cbi-input-textarea', 'readonly': '', 'rows': 4, 'style': 'width:100%;font-family:monospace;word-break:break-all' }, [url]),
				status
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', 'click': ui.hideModal }, [_('Close')]), ' ',
				E('button', { 'class': 'btn cbi-button-action important', 'click': function() {
					var done = function(ok) {
						dom.content(status, E('span', { 'class': ok ? 'pw-text-ok' : 'pw-text-err' },
							[ok ? _('Share URL to clipboard successfully.') : _('Share URL to clipboard unable.')]));
					};
					if (navigator.clipboard && window.isSecureContext)
						navigator.clipboard.writeText(url).then(function() { done(true); }, function() { done(false); });
					else {
						var ta = E('textarea', { 'style': 'position:fixed;opacity:0' }, [url]);
						document.body.appendChild(ta); ta.select();
						var ok = false;
						try { ok = document.execCommand('copy'); } catch (e) {}
						document.body.removeChild(ta);
						done(ok);
					}
				} }, [_('Copy')])
			])
		]);
	}
});
