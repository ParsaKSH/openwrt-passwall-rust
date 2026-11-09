'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require passwall2.pw as pw';

/*
 * Socks instance editor, socks_config/<sid> (upstream: model/cbi/passwall2/client/socks_config.lua,
 * view/passwall2/socks_auto_switch/btn.htm). Spec 08 §13, 10 §2.12, 07 socks_autoswitch_add_node/remove_node.
 */

const CFG = 'passwall2';
const TMP_PATH = '/tmp/etc/passwall2';

function purl() {
	return L.url.apply(L, ['admin/services/passwall2'].concat(Array.prototype.slice.call(arguments)));
}

function pageSid() {
	const req = L.env.requestpath || [], disp = L.env.dispatchpath || [];
	if (req.length > disp.length)
		return req[disp.length];
	return null;
}

function urlEncode(s) {
	if (typeof s !== 'string') return '';
	return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

/* Lua MultiValue widget=checkbox: one option, values joined by a space */
const CheckboxMulti = form.Value.extend({
	__name__: 'PW.CheckboxMulti',

	cfgvalue: function (section_id, set_value) {
		if (arguments.length > 1)
			return form.Value.prototype.cfgvalue.apply(this, arguments);
		const v = form.Value.prototype.cfgvalue.apply(this, [section_id]);
		if (v == null) return [];
		return (Array.isArray(v) ? v : String(v).split(/\s+/)).filter((x) => x !== '');
	},

	renderWidget: function (section_id, option_index, cfgvalue) {
		const selected = {};
		(cfgvalue || []).forEach((v) => { selected[v] = true; });
		const id = this.cbid(section_id);
		const wrap = E('div', { 'id': id, 'class': 'pw-checkbox-group', 'style': 'display:flex;flex-wrap:wrap;gap:.3em 0' });
		(this.keylist || []).forEach((k, i) => {
			const cb = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox', 'value': k, 'id': id + '.' + k });
			cb.checked = !!selected[k];
			cb.addEventListener('change', () => wrap.dispatchEvent(new CustomEvent('widget-change', { bubbles: true })));
			wrap.appendChild(E('label', { 'for': id + '.' + k, 'style': 'display:inline-flex;align-items:center;gap:.35em;margin-right:1em' },
				[cb, this.vallist[i]]));
		});
		return wrap;
	},

	formvalue: function (section_id) {
		const wrap = this.map.findElement('id', this.cbid(section_id));
		if (!wrap) return [];
		return Array.prototype.filter.call(wrap.querySelectorAll('input[type="checkbox"]'), (cb) => cb.checked).map((cb) => cb.value);
	},

	write: function (section_id, value) {
		const list = (Array.isArray(value) ? value : [value]).filter((x) => x != null && x !== '');
		if (list.length)
			uci.set(CFG, section_id, this.option, list.join(' '));
		else
			uci.unset(CFG, section_id, this.option);
	}
});

function promptKeyword() {
	return new Promise((resolve) => {
		const input = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'style': 'width:100%' });
		const done = (v) => { ui.hideModal(); resolve(v); };
		input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') done(input.value); });
		ui.showModal(_('Socks Config'), [
			E('p', {}, [_('Please enter the node keyword, pay attention to distinguish between spaces, uppercase and lowercase.')]),
			input,
			E('div', { 'class': 'right', 'style': 'margin-top:1em' }, [
				E('button', { 'class': 'btn', 'click': () => done(null) }, [_('Cancel')]), ' ',
				E('button', { 'class': 'btn cbi-button-action', 'click': () => done(input.value) }, [_('OK')])
			])
		]);
		window.setTimeout(() => input.focus(), 50);
	});
}

const PROBE_URLS = [
	['https://cp.cloudflare.com/', 'Cloudflare'],
	['https://www.gstatic.com/generate_204', 'Gstatic'],
	['https://www.google.com/generate_204', 'Google'],
	['https://www.youtube.com/generate_204', 'YouTube'],
	['https://connect.rom.miui.com/generate_204', 'MIUI (CN)'],
	['https://connectivitycheck.platform.hicloud.com/generate_204', 'HiCloud (CN)'],
	['https://wifi.vivo.com.cn/generate_204', 'VIVO (CN)']
];

return view.extend({
	load: function () {
		return Promise.all([
			uci.load(CFG),
			pw.findedCom('sing-box'),
			pw.findedCom('xray'),
			L.resolveDefault(pw.getCacheVar(pageSid()), null),
			L.resolveDefault(pw.loadCSS(), null)
		]).then((r) => pw.getNodes().then((nodes) => { r.push(nodes); return r; }));
	},

	render: function (data) {
		const sid = pageSid();
		const back = purl();
		const has_singbox = !!data[1], has_xray = !!data[2], currentNode = data[3], nodes = data[5] || [];

		if (!sid || !uci.get(CFG, sid)) {
			window.location.href = back;
			return E('div');
		}

		let m, s, o;
		m = new form.Map(CFG);

		s = m.section(form.NamedSection, sid, 'socks', _('Socks Config'));
		s.addremove = false;
		s.dynamic = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		/* current node chosen by the auto-switch daemon */
		let autoSwitchTip = null;
		if (currentNode) {
			const n = uci.get(CFG, currentNode);
			if (n && Number(uci.get(CFG, sid, 'enable_autoswitch') || 0) === 1) {
				autoSwitchTip = _('Current node: %s').format('<a href="%s">%s</a>'.format(
					purl('node_config', n['.name']), pw.escapeHTML(pw.nodeRemarks(n)))) + '<br />';
			}
		}

		const socksNode = pw.addNodeOption(s, 'node', _('Node'), { nodes: nodes });
		if (autoSwitchTip)
			socksNode.description = autoSwitchTip;

		o = s.option(form.Flag, 'bind_local', _('Bind Local'), _('When selected, it can only be accessed localhost.'));
		o.default = '0';

		/* upstream quirk: the counting loop never breaks, default = number of socks sections + 1081 */
		const n = 1 + uci.sections(CFG, 'socks').length;
		o = s.option(form.Value, 'port', 'Socks ' + _('Listen Port'));
		o.default = String(n + 1080);
		o.datatype = 'port';
		o.rmempty = false;

		if (has_singbox || has_xray) {
			o = s.option(form.Value, 'http_port', 'HTTP ' + _('Listen Port') + ' ' + _('0 is not use'));
			o.default = '0';
			o.datatype = 'port';
		}

		o = s.option(form.Flag, 'log', _('Enable') + ' ' + _('Log'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.DummyValue, '_log', _('Log File'));
		o.renderWidget = function () {
			return E('div', { 'style': 'display:flex;gap:.6em;align-items:center;flex-wrap:wrap' }, [
				E('code', {}, [TMP_PATH + '/' + sid + '.log']),
				E('button', {
					'class': 'btn cbi-button cbi-button-apply', 'type': 'button',
					'click': ui.createHandlerFn(this, () => pw.showLog(_('Log File'), 'get_socks_log', { name: sid }))
				}, [_('View Log')])
			]);
		};
		o.depends('log', '1');

		const autoSwitch = s.option(form.Flag, 'enable_autoswitch', _('Auto Switch'));
		autoSwitch.default = '0';
		autoSwitch.rmempty = false;

		o = s.option(form.ListValue, 'backup_node_add_mode', _('Backup Node Addition Method'));
		o.depends('enable_autoswitch', '1');
		o.default = 'manual';
		o.value('manual', _('Manual'));
		o.value('batch', _('Batch'));

		const backupNodes = nodes.filter((v) => v.protocol !== '_shunt');
		backupNodes.forEach((v) => autoSwitch.depends({ node: v.id }));

		/* nodes_dynamiclist: ordered, grouped; items may be comma separated, unknown ids are dropped */
		o = pw.addNodeOption(s, 'autoswitch_backup_node', _('List of backup nodes'), { multiple: true, nodes: backupNodes });
		o.depends('backup_node_add_mode', 'manual');
		/* write: drop the currently selected main node, de-duplicate, store as list */
		o.write = function (section_id, value) {
			const main = this.section.formvalue(section_id, 'node');
			const seen = {}, t = [];
			L.toArray(value).forEach((x) => {
				if (x && x !== main && !seen[x]) { seen[x] = true; t.push(x); }
			});
			if (t.length)
				uci.set(CFG, section_id, 'autoswitch_backup_node', t);
			else
				uci.unset(CFG, section_id, 'autoswitch_backup_node');
		};

		o = s.option(CheckboxMulti, 'backup_node_group', _('Select Group'));
		o.depends('backup_node_add_mode', 'batch');
		o.value('default', _('default'));
		const groups = [];
		uci.sections(CFG, 'nodes').forEach((e) => {
			if (e.group && e.group !== '' && groups.indexOf(e.group) < 0)
				groups.push(e.group);
		});
		groups.forEach((g) => o.value(urlEncode(g), g));

		o = s.option(form.Value, 'backup_node_match_rule', _('Node Matching Rules'));
		o.depends('backup_node_add_mode', 'batch');
		o.description = _('Example: <code>^A && B && !C && D$</code><br>This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>Conditions are joined by <code>&&</code> (AND), and their order does not affect the result.<br>Multiple groups can be separated by <code>||</code> (OR), matching succeeds if any group matches.<br>Example: <code>A && B || C && D</code> means (A AND B) OR (C AND D).');

		o = s.option(form.Value, 'autoswitch_testing_time', _('How often to test'), _('Units:seconds'));
		o.datatype = 'min(10)';
		o.default = '30';
		o.depends('enable_autoswitch', '1');

		o = s.option(form.Value, 'autoswitch_connect_timeout', _('Timeout seconds'), _('Units:seconds'));
		o.datatype = 'min(1)';
		o.default = '3';
		o.depends('enable_autoswitch', '1');

		o = s.option(form.Value, 'autoswitch_retry_num', _('Timeout retry num'));
		o.datatype = 'min(1)';
		o.default = '1';
		o.depends('enable_autoswitch', '1');

		o = s.option(form.Flag, 'autoswitch_restore_switch', _('Restore Switch'),
			_('When detects main node is available, switch back to the main node.'));
		o.depends('enable_autoswitch', '1');

		o = s.option(form.Value, 'autoswitch_probe_url', _('Probe URL'), _('The URL used to detect the connection status.'));
		PROBE_URLS.forEach((p) => o.value(p[0], p[1]));
		o.default = PROBE_URLS[2][0];
		o.depends('enable_autoswitch', '1');

		/* keyword buttons (socks_auto_switch/btn.htm) */
		o = s.option(form.DummyValue, 'btn', '　');
		o.renderWidget = function () {
			const run = (method) => promptKeyword().then((key) => {
				if (!key) return;
				return pw.call(method, { id: sid, key: key }).then(() => {
					window.location.reload();
				}, (e) => pw.notify(e && e.message ? e.message : _('Error'), 'err'));
			});
			return E('div', { 'style': 'display:flex;gap:.5em;flex-wrap:wrap' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-add', 'type': 'button',
					'click': ui.createHandlerFn(this, () => run('socks_autoswitch_add_node'))
				}, [_('Add nodes to the standby node list by keywords')]),
				E('button', {
					'class': 'btn cbi-button cbi-button-remove', 'type': 'button',
					'click': ui.createHandlerFn(this, () => run('socks_autoswitch_remove_node'))
				}, [_('Delete nodes in the standby node list by keywords')])
			]);
		};
		o.depends('backup_node_add_mode', 'manual');

		pw.redirectAfterApply(back);

		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Socks Config'), sid, [
				E('a', { 'class': 'btn cbi-button', 'href': back }, [_('Back')])
			]),
			mapEl
		]));
	}
});
