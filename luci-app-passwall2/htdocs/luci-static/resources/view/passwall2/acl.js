'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require passwall2.pw as pw';

/*
 * Access control list (upstream: model/cbi/passwall2/client/acl.lua). Spec 08 §11.
 */

const CFG = 'passwall2';

function purl() {
	return L.url.apply(L, ['admin/services/passwall2'].concat(Array.prototype.slice.call(arguments)));
}

function firstSid(type) {
	const list = uci.sections(CFG, type);
	return list.length ? list[0]['.name'] : uci.add(CFG, type);
}

return view.extend({
	load: function () {
		return Promise.all([
			uci.load(CFG),
			L.resolveDefault(pw.loadCSS(), null)
		]);
	},

	render: function () {
		let m, s, o;

		m = new form.Map(CFG);

		s = m.section(form.NamedSection, firstSid('global'), 'global', _('ACLs'),
			'<font color="red">%s</font>'.format(_('ACLs is a tools which used to designate specific IP proxy mode.')));
		s.addremove = false;

		o = s.option(form.Flag, 'acl_enable', _('Main switch'));
		o.rmempty = false;
		o.default = '0';

		/* [[ ACLs Settings ]] */
		s = m.section(form.TableSection, 'acl_rule');
		s.sortable = true;
		s.anonymous = true;
		s.addremove = true;
		s.extedit = purl('acl_config') + '/%s';
		s.handleAdd = function (ev) {
			const uid = uci.add(CFG, 'acl_rule', 'acl_' + pw.randomChars(5));
			return this.map.save(null, true).then(() => {
				window.location.href = purl('acl_config', uid);
			});
		};

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'remarks', _('Remarks'));
		o.rmempty = true;

		o = s.option(form.DummyValue, 'interface', _('Source Interface'));
		o.cfgvalue = function (section_id, set_value) {
			if (arguments.length > 1) return form.DummyValue.prototype.cfgvalue.apply(this, arguments);
			const v = uci.get(CFG, section_id, 'interface') || '';
			return v === '' ? _('All') : v;
		};

		o = s.option(form.DummyValue, 'sources', _('Source'));
		o.renderWidget = function (section_id) {
			const v = uci.get(CFG, section_id, 'sources');
			if (!Array.isArray(v))
				return E('div');
			const out = [];
			v.forEach((x, i) => {
				if (i) out.push(E('br'));
				out.push(String(x));
			});
			return E('div', {}, out);
		};

		o = s.option(form.DummyValue, 'mode', _('Mode'));
		o.renderWidget = function (section_id) {
			const v = uci.get(CFG, section_id, 'mode') || '0';
			if (v === '1')
				return pw.badge(_('Proxy'), 'ok');
			if (v === '2')
				return pw.badge(_('Proxy') + ' ' + _('Use global config'), 'info');
			return pw.badge(_('No Proxy'), 'muted');
		};

		pw.redirectAfterApply(purl('log'));

		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Access control'), null, []),
			mapEl
		]));
	}
});
