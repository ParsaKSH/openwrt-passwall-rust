'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';
'require dom';
'require passwall2.pw as pw';

/*
 * Rule Manage page (upstream: model/cbi/passwall2/client/rule.lua,
 * view/passwall2/rule/rule_version.htm, view/passwall2/rule/shunt_rule_list.htm).
 * Spec 08 §9, 10 §2.14 / §2.16, 07 update_rules / rollback_rules / add_shunt_rule / delete_select_shunt_rules.
 */

const CFG = 'passwall2';

function purl() {
	return L.url.apply(L, ['admin/services/passwall2'].concat(Array.prototype.slice.call(arguments)));
}

function firstSid(type) {
	const list = uci.sections(CFG, type);
	return list.length ? list[0]['.name'] : uci.add(CFG, type);
}

function fileExists(path) {
	return L.resolveDefault(fs.stat(path), null).then((st) => !!st);
}

function timeChoices(o) {
	const seen = {};
	const add = (v) => { if (!seen[v]) { seen[v] = true; o.value(v); } };
	add('0:00');
	for (let t = 0; t <= 23; t++)
		add(t === 12 ? t + ':30' : (t === 23 ? t + ':59' : t + ':00'));
}

const GEO_SOURCES = [
	['https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/%s.dat', 'Loyalsoldier/%s'],
	['https://gh-proxy.org/https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/%s.dat', 'Loyalsoldier/%s (gh-proxy)'],
	['https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/%s.dat', 'Loyalsoldier/%s (CDN)'],
	['https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/%s.dat', 'MetaCubeX/%s'],
	['https://gh-proxy.org/https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/%s.dat', 'MetaCubeX/%s (gh-proxy)'],
	['https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/%s.dat', 'MetaCubeX/%s (CDN)'],
	['https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/%s.dat', 'Chocolate4U/%s (IR)'],
	['https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/%s.dat', 'runetfreedom/%s (RU)']
];

/* Translated labels: msgids are the literal upstream strings (e.g. "Loyalsoldier/geoip (CDN)") */
const GEO_LABELS = {
	geoip: [_('Loyalsoldier/geoip'), _('Loyalsoldier/geoip (gh-proxy)'), _('Loyalsoldier/geoip (CDN)'),
		_('MetaCubeX/geoip'), _('MetaCubeX/geoip (gh-proxy)'), _('MetaCubeX/geoip (CDN)'),
		_('Chocolate4U/geoip (IR)'), _('runetfreedom/geoip (RU)')],
	geosite: [_('Loyalsoldier/geosite'), _('Loyalsoldier/geosite (gh-proxy)'), _('Loyalsoldier/geosite (CDN)'),
		_('MetaCubeX/geosite'), _('MetaCubeX/geosite (gh-proxy)'), _('MetaCubeX/geosite (CDN)'),
		_('Chocolate4U/geosite (IR)'), _('runetfreedom/geosite (RU)')]
};

/* A Flag whose row is never shown (upstream hides them with CSS and binds custom checkboxes) */
const HiddenFlag = form.Flag.extend({
	__name__: 'PW.HiddenFlag',
	renderFrame: function (section_id, in_table, option_index, nodes) {
		const el = form.Flag.prototype.renderFrame.apply(this, [section_id, in_table, option_index, nodes]);
		return Promise.resolve(el).then((node) => {
			if (node && node.style) node.style.display = 'none';
			return node;
		});
	}
});

/* "Update Options" block: geoip / geosite checkboxes, Manually update, Rollback buttons */
const RuleUpdateValue = form.DummyValue.extend({
	__name__: 'PW.RuleUpdate',

	renderWidget: function (section_id) {
		const section = this.section;
		const flags = [['geoip', 'geoip_update'], ['geosite', 'geosite_update']];
		const checks = [];
		const boxes = flags.map((f) => {
			const cb = E('input', {
				'class': 'cbi-input-checkbox',
				'type': 'checkbox',
				'name': f[0],
				'value': '1'
			});
			cb.checked = (uci.get(CFG, section_id, f[1]) === '1');
			checks.push({ name: f[0], cb: cb });
			cb.addEventListener('change', () => {
				const w = section.getUIElement(section_id, f[1]);
				if (w) w.setValue(cb.checked ? '1' : '0');
			});
			return E('label', { 'style': 'margin-right:1.2em;display:inline-flex;align-items:center;gap:.35em' }, [cb, f[0]]);
		});

		const updateBtn = E('button', {
			'class': 'btn cbi-button cbi-button-apply',
			'type': 'button',
			'click': ui.createHandlerFn(this, () => {
				updateBtn.disabled = true;
				updateBtn.textContent = _('Updating...');
				/* upstream walks the inputs in reverse DOM order */
				const list = checks.slice().reverse().filter((c) => c.cb.checked).map((c) => c.name);
				return pw.call('update_rules', { update: list.join(',') }).then(() => {
					window.location.href = purl('log');
				}, () => {
					pw.notify(_('Error'), 'err');
					updateBtn.disabled = false;
					updateBtn.textContent = _('Manually update');
				});
			})
		}, [_('Manually update')]);

		const rollbackBtn = (type, label) => {
			const btn = E('button', {
				'class': 'btn cbi-button cbi-button-reset',
				'type': 'button',
				'style': 'margin-left:.5em',
				'click': ui.createHandlerFn(this, () => {
					btn.disabled = true;
					btn.textContent = _('Rollbacking...');
					return pw.call('rollback_rules', { type: type }).then((r) => {
						if (r && r.code == 1) {
							pw.notify(_('Success'), 'ok');
							btn.style.display = 'none';
						} else {
							throw new Error('rollback');
						}
					}).catch(() => {
						pw.notify(_('Error'), 'err');
						btn.disabled = false;
						btn.textContent = _('Rollback') + ' ' + label;
					});
				})
			}, [_('Rollback') + ' ' + label]);
			return btn;
		};

		return E('div', { 'id': '_rule_div' }, [
			E('div', {}, boxes),
			E('div', { 'style': 'margin-top:.8em' }, [
				updateBtn,
				this.has_old_geoip ? rollbackBtn('geoip', 'GeoIP') : '',
				this.has_old_geosite ? rollbackBtn('geosite', 'Geosite') : ''
			])
		]);
	}
});

/* ---------------------------------------------------------------- shunt rule list */

function escapeHTML(s) {
	return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/*
 * Apply a new in-group order to UCI (staged; persisted by Save / Save & Apply).
 * upstream quirk: rule.lua calls uci:reorder(name, idx-1) with absolute positions, which also moves the
 * group's rules in front of every other section of the file. We only reorder the group's rules relative
 * to each other, inside the slots they already occupy (the priority order the runtime sees is identical).
 */
function applyGroupOrder(newOrder) {
	if (!newOrder.length) return;
	const inGroup = {};
	newOrder.forEach((id) => { inGroup[id] = true; });
	const current = uci.sections(CFG, 'shunt_rules').map((s) => s['.name']).filter((id) => inGroup[id]);
	if (current.join(' ') === newOrder.join(' ')) return;
	const anchor = current[0];
	if (newOrder[0] !== anchor)
		uci.move(CFG, newOrder[0], anchor, false);
	for (let i = 1; i < newOrder.length; i++)
		uci.move(CFG, newOrder[i], newOrder[i - 1], true);
}

function renderShuntRuleList() {
	const rules = uci.sections(CFG, 'shunt_rules');
	const groups = {};
	const order = [];
	/* ungrouped rules first (same order as get_shunt_rules), grouping by `group` (empty = default) */
	const sorted = rules.filter((r) => !r.group).concat(rules.filter((r) => !!r.group));
	sorted.forEach((r) => {
		const g = (r.group && r.group !== '') ? r.group : 'default';
		if (!groups[g]) { groups[g] = []; order.push(g); }
		groups[g].push(r);
	});
	if (!order.length) { groups['default'] = []; order.push('default'); }

	let activeGroup = order[0];
	const tabBar = E('div', { 'class': 'pw-toolbar pw-tabs', 'style': 'flex-wrap:wrap' });
	const panes = E('div', {});
	const tabBtns = {}, paneEls = {};

	const showGroup = (g) => {
		activeGroup = g;
		order.forEach((k) => {
			tabBtns[k].classList.toggle('cbi-tab', k === g);
			tabBtns[k].classList.toggle('cbi-tab-disabled', k !== g);
			tabBtns[k].classList.toggle('active', k === g);
			paneEls[k].style.display = (k === g) ? '' : 'none';
		});
	};

	order.forEach((g) => {
		const list = groups[g];
		const label = (g === 'default') ? _('default') : g;
		tabBtns[g] = E('button', {
			'type': 'button',
			'class': 'btn cbi-button',
			'group_name': g,
			'click': () => showGroup(g)
		}, [escapeHTML(label) + ' | ', E('span', { 'style': 'color:red' }, [String(list.length)])]);
		tabBar.appendChild(tabBtns[g]);

		const tbody = E('tbody', {});
		const table = E('table', { 'class': 'table pw-table', 'id': 'cbi-passwall2-shunt_rules-' + g + '-table' }, [
			E('thead', {}, E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, ['ID']),
				E('th', { 'class': 'th' }, [_('Remarks')]),
				E('th', { 'class': 'th', 'style': 'width:1%;white-space:nowrap' }, [''])
			])),
			tbody
		]);

		const setOrder = () => {
			const ids = Array.prototype.map.call(tbody.querySelectorAll('tr[data-sid]'), (tr) => tr.getAttribute('data-sid'));
			if (!ids.length) {
				pw.notify(_('No shunt_rules!'), 'err');
				return;
			}
			applyGroupOrder(ids);
		};

		let dragRow = null;
		list.forEach((r) => {
			const id = r['.name'];
			const handle = E('span', {
				'class': 'pw-drag-handle',
				'title': _('Drag to reorder'),
				'style': 'cursor:move;user-select:none;padding:0 .4em;font-size:120%'
			}, ['⠿']);
			const tr = E('tr', { 'class': 'tr', 'data-sid': id }, [
				E('td', { 'class': 'td', 'data-title': 'ID' }, [E('b', {}, [id])]),
				E('td', { 'class': 'td', 'data-title': _('Remarks') }, [r.remarks != null ? String(r.remarks) : '']),
				E('td', { 'class': 'td cbi-section-actions', 'style': 'white-space:nowrap' }, [
					E('button', {
						'class': 'btn cbi-button', 'type': 'button',
						'click': () => {
							const first = tbody.querySelector('tr[data-sid]');
							if (first && first !== tr) {
								tbody.insertBefore(tr, first);
								setOrder();
							}
						}
					}, [_('To Top')]), ' ',
					E('button', {
						'class': 'btn cbi-button cbi-button-edit', 'type': 'button',
						'click': () => { window.location.href = purl('shunt_rules', id); }
					}, [_('Edit')]), ' ',
					E('button', {
						'class': 'btn cbi-button cbi-button-remove', 'type': 'button',
						'click': ui.createHandlerFn(this, () =>
							pw.confirm(_('Delete'), '%s: %s ?'.format(_('Delete'), r.remarks || id)).then((ok) => {
								if (!ok) return;
								return pw.call('delete_select_shunt_rules', { ids: id, redirect: '1' }).then(() => {
									window.location.reload();
								}, (e) => pw.notify(e && e.message ? e.message : _('Error'), 'err'));
							}))
					}, [_('Delete')]), ' ',
					handle
				])
			]);
			handle.addEventListener('mousedown', () => { tr.draggable = true; });
			handle.addEventListener('touchstart', () => { tr.draggable = true; }, { passive: true });
			tr.addEventListener('dragstart', (ev) => {
				dragRow = tr;
				tr.classList.add('dragging-row');
				ev.dataTransfer.effectAllowed = 'move';
				try { ev.dataTransfer.setData('text/plain', id); } catch (e) { }
			});
			tr.addEventListener('dragover', (ev) => {
				if (!dragRow || dragRow === tr || dragRow.parentNode !== tbody) return;
				ev.preventDefault();
				const rect = tr.getBoundingClientRect();
				const after = (ev.clientY - rect.top) > rect.height / 2;
				tbody.insertBefore(dragRow, after ? tr.nextSibling : tr);
			});
			tr.addEventListener('dragend', () => {
				tr.draggable = false;
				tr.classList.remove('dragging-row');
				if (dragRow) {
					dragRow = null;
					setOrder();
				}
			});
			tbody.appendChild(tr);
		});
		if (!list.length)
			tbody.appendChild(E('tr', { 'class': 'tr placeholder' }, [
				E('td', { 'class': 'td', 'colspan': 3 }, [E('em', {}, [_('This section contains no values yet')])])
			]));

		const addInput = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'id': 'add_name_' + g, 'placeholder': 'ID' });
		const addBtn = E('button', {
			'class': 'btn cbi-button cbi-button-add', 'type': 'button',
			'click': ui.createHandlerFn(this, () => {
				const name = addInput.value;
				if (!(name.length > 1)) return;
				return pw.call('add_shunt_rule', { add_name: name, group: activeGroup }).then((r) => {
					if (r && r.code == 1) {
						const uid = (r.data && r.data.uid) ? r.data.uid : name;
						window.location.href = purl('shunt_rules', uid);
					} else {
						pw.notify((r && r.data && r.data.message) ? _(r.data.message) : _('Save failed!'), 'err');
					}
				}, () => pw.notify(_('Save failed!'), 'err'));
			})
		}, [_('Add')]);
		addInput.addEventListener('keydown', (ev) => {
			if (ev.key === 'Enter') { ev.preventDefault(); addBtn.click(); }
		});

		paneEls[g] = E('div', { 'class': 'pw-shunt-group', 'group_name': g }, [
			table,
			E('div', { 'class': 'pw-toolbar', 'style': 'margin-top:.6em;gap:.5em;display:flex;align-items:center' }, [addInput, addBtn])
		]);
		panes.appendChild(paneEls[g]);
	});

	showGroup(activeGroup);

	return pw.card('Sing-Box/Xray ' + _('Shunt Rule'),
		E('div', { 'class': 'cbi-section-descr' }, [
			E('font', { 'color': 'red' }, [_('Please note attention to the priority, the higher the order, the higher the priority.')])
		]),
		tabBar,
		panes);
}

return view.extend({
	load: function () {
		return Promise.all([
			uci.load(CFG),
			fileExists('/tmp/bak_v2ray/geoip.dat'),
			fileExists('/tmp/bak_v2ray/geosite.dat'),
			L.resolveDefault(pw.loadCSS(), null)
		]);
	},

	render: function (data) {
		let m, s, o;

		m = new form.Map(CFG);

		/* [[ Rule Settings ]] */
		s = m.section(form.NamedSection, firstSid('global_rules'), 'global_rules', _('Rule status'));
		s.addremove = false;

		['geoip', 'geosite'].forEach((kind) => {
			o = s.option(form.Value, kind + '_url', kind === 'geoip' ? _('GeoIP Update URL') : _('Geosite Update URL'));
			GEO_SOURCES.forEach((src, i) => o.value(src[0].format(kind), GEO_LABELS[kind][i]));
			o.default = GEO_SOURCES[0][0].format(kind);
		});

		o = s.option(form.Value, 'v2ray_location_asset', _('Location of Geo rule files'),
			_('This variable specifies a directory where geoip.dat and geosite.dat files are.'));
		o.default = '/usr/share/v2ray/';
		o.placeholder = o.default;
		o.rmempty = false;

		o = s.option(form.ListValue, 'update_week_mode', _('Auto Update Mode'));
		o.value('', _('Disable'));
		o.value('8', _('Loop Mode'));
		o.value('7', _('Every day'));
		o.value('1', _('Every Monday'));
		o.value('2', _('Every Tuesday'));
		o.value('3', _('Every Wednesday'));
		o.value('4', _('Every Thursday'));
		o.value('5', _('Every Friday'));
		o.value('6', _('Every Saturday'));
		o.value('0', _('Every Sunday'));

		o = s.option(form.Value, 'update_time_mode', _('Update Time'));
		timeChoices(o);
		o.default = '0:00';
		o.validate = function (section_id, value) {
			return (value == null || value === '' || pw.isTimeHHMM(value)) ? true : _('valid time (hh:mm)');
		};
		['0', '1', '2', '3', '4', '5', '6', '7'].forEach((w) => o.depends('update_week_mode', w));

		o = s.option(form.ListValue, 'update_interval_mode', _('Update Interval(hour)'));
		for (let t = 1; t <= 24; t++)
			o.value(String(t), t + ' ' + _('hour'));
		o.default = '2';
		o.depends('update_week_mode', '8');
		o.rmempty = true;

		/* The update flags are always hidden; "Update Options" below edits them. */
		['geoip_update', 'geosite_update'].forEach((f) => {
			o = s.option(HiddenFlag, f);
			o.rmempty = false;
		});

		o = s.option(RuleUpdateValue, '_rule_update', _('Update Options'));
		o.has_old_geoip = data[1];
		o.has_old_geosite = data[2];

		pw.redirectAfterApply(purl('log'));

		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Rule Manage'), null, []),
			mapEl,
			renderShuntRuleList.call(this)
		]));
	}
});
