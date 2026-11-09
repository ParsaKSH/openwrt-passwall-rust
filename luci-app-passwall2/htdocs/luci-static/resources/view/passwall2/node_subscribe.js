'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require passwall2.pw as pw';

/*
 * Node Subscribe page (upstream: model/cbi/passwall2/client/node_subscribe.lua
 * + view/passwall2/node_subscribe/js.htm). Spec 08 §4, 10 §2.13.
 */

const CFG = 'passwall2';

function purl() {
	return L.url.apply(L, ['admin/services/passwall2'].concat(Array.prototype.slice.call(arguments)));
}

/* api.trim: strip bytes <= 0x20 on both ends */
function trim(s) {
	return (s == null ? '' : String(s)).replace(/^[\x00-\x20]+/, '').replace(/[\x00-\x20]+$/, '');
}

/* Lua string.lower (ASCII only) */
function lower(s) {
	return (s == null ? '' : String(s)).replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/* api.UrlEncode: keep [A-Za-z0-9-_.~], %XX (upper hex) every other UTF-8 byte */
function urlEncode(s) {
	if (typeof s !== 'string') return '';
	return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function firstSid(type) {
	const list = uci.sections(CFG, type);
	return list.length ? list[0]['.name'] : uci.add(CFG, type);
}

/* api.compare_versions(v1, ">=", v2) */
function versionGE(v1, v2) {
	const part = (x) => {
		const n = Number(x);
		if (x !== '' && !isNaN(n)) return n;
		const m = String(x).match(/^[rR](\d+)$/);
		return m ? Number(m[1]) : 0;
	};
	const a = String(v1 || '').split(/[.-]/), b = String(v2 || '').split(/[.-]/);
	const max = Math.max(a.length, b.length);
	for (let i = 0; i < max; i++) {
		const s1 = part(a[i] != null ? a[i] : 0), s2 = part(b[i] != null ? b[i] : 0);
		if (s1 > s2) return true;
		if (s1 !== s2) return false;
	}
	return true;
}

function comVersion(com) {
	return L.resolveDefault(pw.call('com_version', { com: com }), {}).then((r) =>
		(r && r.code == 1 && r.data) ? String(r.data) : '');
}

/* Core-type candidate lists, spec 08 §0.4 */
function loadCoreTypes() {
	return Promise.all([
		pw.isFinded('sslocal'),
		pw.findedCom('sing-box'),
		pw.findedCom('xray'),
		comVersion('xray')
	]).then((r) => {
		const has_ss_rust = r[0], has_singbox = r[1], has_xray = r[2], xray_version = r[3];
		const t = { ss_type: [], trojan_type: [], vmess_type: [], vless_type: [], hysteria2_type: [] };
		if (has_ss_rust)
			t.ss_type.push('shadowsocks-rust');
		if (has_singbox)
			['trojan_type', 'ss_type', 'vmess_type', 'vless_type', 'hysteria2_type'].forEach((k) => t[k].push('sing-box'));
		if (has_xray) {
			['trojan_type', 'ss_type', 'vmess_type', 'vless_type'].forEach((k) => t[k].push('xray'));
			if (versionGE(xray_version, '26.1.13'))
				t.hysteria2_type.push('xray');
		}
		return t;
	});
}

/* Remark validation shared by list and editor (spec 08 §4.2) */
function validateRemark(section_id, value) {
	const v = trim(value);
	if (v === '')
		return _('Remark cannot be empty.');
	const dup = uci.sections(CFG, 'subscribe_list').some((e) =>
		e['.name'] !== section_id && e.remark != null && lower(e.remark) === lower(v));
	if (dup || lower(v) === 'default')
		return _('This remark already exists, please change a new remark.');
	return true;
}

/* Remark rename cascade (spec 08 §4.3) */
function writeRemark(section_id, value) {
	value = trim(value);
	const old = uci.get(CFG, section_id, 'remark') || '';
	if (old !== value) {
		uci.sections(CFG, 'nodes').forEach((e) => {
			if (e.group != null && lower(e.group) === lower(old))
				uci.set(CFG, e['.name'], 'group', value);
			if (e.protocol && (e.protocol === '_balancing' || e.protocol === '_urltest') && e.node_group) {
				const gs = String(e.node_group).split(/\s+/).filter((g) => g !== '')
					.map((g) => (urlEncode(old) === g) ? urlEncode(value) : g).join(' ');
				uci.set(CFG, e['.name'], 'node_group', trim(gs));
			}
		});
	}
	uci.set(CFG, section_id, 'remark', value);
}

return view.extend({
	load: function () {
		return Promise.all([
			uci.load(CFG),
			loadCoreTypes(),
			L.resolveDefault(pw.loadCSS(), null)
		]);
	},

	render: function (data) {
		const types = data[1];
		let m, s, o;

		m = new form.Map(CFG);

		/* on_before_save: drop md5 of every subscription to force a re-parse */
		const origParse = m.parse;
		m.parse = function () {
			return origParse.apply(this, arguments).then(() => {
				uci.sections(CFG, 'subscribe_list').forEach((e) => {
					if (uci.get(CFG, e['.name'], 'md5') != null)
						uci.unset(CFG, e['.name'], 'md5');
				});
			});
		};

		/* [[ Subscribe Settings ]] */
		s = m.section(form.NamedSection, firstSid('global_subscribe'), 'global_subscribe');
		s.addremove = false;
		s.anonymous = true;

		o = s.option(form.ListValue, 'filter_keyword_mode', _('Filter keyword Mode'));
		o.value('0', _('Close'));
		o.value('1', _('Discard List'));
		o.value('2', _('Keep List'));
		o.value('3', _('Discard List,But Keep List First'));
		o.value('4', _('Keep List,But Discard List First'));

		o = s.option(form.DynamicList, 'filter_discard_list', _('Discard List'));

		o = s.option(form.DynamicList, 'filter_keep_list', _('Keep List'));

		const typeDefs = [
			['ss_type', 'Shadowsocks'],
			['trojan_type', 'Trojan'],
			['vmess_type', 'VMess'],
			['vless_type', 'VLESS'],
			['hysteria2_type', 'Hysteria2']
		];
		let anyType = false;
		typeDefs.forEach((d) => {
			const list = types[d[0]];
			if (!list.length) return;
			anyType = true;
			o = s.option(form.ListValue, d[0], _('%s Node Use Type').format(d[1]));
			o.value('', _('Auto'));
			list.forEach((v) => o.value(v));
		});
		/* upstream quirk: the note lands on the last created option (filter_keep_list if no core) */
		if (anyType)
			o.description = '<font color="red">%s</font>'.format(
				_('The configured type also applies to the core specified when manually importing nodes.'));

		/* Subscribe Delete All */
		o = s.option(form.Button, '_stop', _('Delete All Subscribe Node'));
		o.inputtitle = _('Delete All Subscribe Node');
		o.inputstyle = 'remove';
		o.onclick = function () {
			return pw.confirm(_('Delete All Subscribe Node'), _('Are you sure you want to delete all subscribed nodes?')).then((ok) => {
				if (!ok) return;
				return pw.call('subscribe_del_all', {}).then(() => {
					window.location.reload();
				}, () => {
					pw.notify(_('Failed to delete.'), 'err');
				});
			});
		};

		o = s.option(form.Button, '_update', _('Manual subscription All'));
		o.inputtitle = _('Manual subscription All');
		o.inputstyle = 'apply';
		o.onclick = function () {
			const sids = listSection.cfgsections();
			const sections = [], urls = [];
			for (let i = 0; i < sids.length; i++) {
				const url = trim(listSection.formvalue(sids[i], 'url') || '');
				if (!url) {
					pw.notify(_('Subscribe URL cannot be empty.'), 'err');
					return;
				}
				sections.push(sids[i]);
				urls.push(url);
			}
			if (!sections.length)
				return;
			return pw.call('subscribe_manual_all', { sections: sections.join(','), urls: urls.join(',') }).then((r) => {
				if (!r || !r.success)
					pw.notify(r && r.msg ? _(r.msg) : _('Operation failed'), 'err');
				else
					window.location.href = purl('log');
			}, (e) => pw.notify(e && e.message ? e.message : _('Operation failed'), 'err'));
		};

		/* [[ Subscription list ]] */
		const listSection = s = m.section(form.TableSection, 'subscribe_list', '',
			'<font color="red">%s</font>'.format(_('When adding a new subscription, please save and apply before manually subscribing. If you only change the subscription URL, you can subscribe manually, and the system will save it automatically.')));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;
		s.extedit = purl('node_subscribe_config') + '/%s';
		s.handleAdd = function (ev) {
			const uid = uci.add(CFG, 'subscribe_list', 'sub_' + pw.randomChars(5));
			uci.set(CFG, uid, 'hysteria_up_mbps', '100');
			uci.set(CFG, uid, 'hysteria_down_mbps', '100');
			return this.map.save(null, true).then(() => {
				window.location.href = purl('node_subscribe_config', uid);
			});
		};

		o = s.option(form.Value, 'remark', _('Remarks'));
		o.width = 'auto';
		o.rmempty = false;
		o.validate = function (section_id, value) {
			return validateRemark(section_id, value);
		};
		o.write = function (section_id, value) {
			writeRemark(section_id, value);
		};

		o = s.option(form.DummyValue, '_node_count', _('Subscribe Info'));
		o.rawhtml = true;
		o.cfgvalue = function (section_id) {
			const remark = uci.get(CFG, section_id, 'remark') || '';
			let str = uci.get(CFG, section_id, 'rem_traffic') || '';
			const expired = uci.get(CFG, section_id, 'expired_date') || '';
			if (expired !== '')
				str = str + (str !== '' ? '/' : '') + expired;
			const num = uci.sections(CFG, 'nodes').filter((e) => e.group != null && lower(e.group) === lower(remark)).length;
			return E('div', { 'class': 'pw-sub-info' }, [
				pw.badge(_('Node num') + ': ' + num, num > 0 ? 'ok' : 'muted'),
				str !== '' ? E('div', { 'class': 'pw-sub-traffic', 'style': 'margin-top:.25em;font-size:90%' }, [str]) : ''
			]);
		};
		o.renderWidget = function (section_id, option_index, cfgvalue) {
			return cfgvalue;
		};

		o = s.option(form.Value, 'url', _('Subscribe URL'));
		o.width = 'auto';
		o.rmempty = false;

		o = s.option(form.Button, '_remove', _('Delete the subscribed node'));
		o.inputtitle = _('Delete the subscribed node');
		o.inputstyle = 'remove';
		o.onclick = function (ev, section_id) {
			const remark = uci.get(CFG, section_id, 'remark') || '';
			return pw.confirm(_('Delete the subscribed node'), _('Delete the subscribed node') + ': ' + remark + ' ?').then((ok) => {
				if (!ok) return;
				return pw.call('subscribe_del_node', { remark: remark }).then(() => {
					window.location.reload();
				}, () => {
					pw.notify(_('Failed to delete.'), 'err');
				});
			});
		};

		o = s.option(form.Button, '_update', _('Manual subscription'));
		o.inputtitle = _('Manual subscription');
		o.inputstyle = 'apply';
		o.onclick = function (ev, section_id) {
			const url = trim(this.section.formvalue(section_id, 'url') || '');
			if (!url) {
				pw.notify(_('Subscribe URL cannot be empty.'), 'err');
				return;
			}
			return pw.call('subscribe_manual', { section: section_id, url: url }).then((r) => {
				if (!r || !r.success)
					pw.notify(r && r.msg ? _(r.msg) : _('Operation failed'), 'err');
				else
					window.location.href = purl('log');
			}, (e) => pw.notify(e && e.message ? e.message : _('Operation failed'), 'err'));
		};

		pw.redirectAfterApply(purl('log'));

		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Node Subscribe'), null, []),
			mapEl
		]));
	}
});
