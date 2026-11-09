'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require passwall2.pw as pw';

/*
 * Shunt rule editor, shunt_rules/<sid> (upstream: model/cbi/passwall2/client/shunt_rules.lua). Spec 08 §14.
 */

const CFG = 'passwall2';

function purl() {
	return L.url.apply(L, ['admin/services/passwall2'].concat(Array.prototype.slice.call(arguments)));
}

function pageSid() {
	const req = L.env.requestpath || [], disp = L.env.dispatchpath || [];
	if (req.length > disp.length)
		return req[disp.length];
	return null;
}

function trim(s) {
	return (s == null ? '' : String(s)).replace(/^[\x00-\x20]+/, '').replace(/[\x00-\x20]+$/, '');
}

function lower(s) {
	return (s == null ? '' : String(s)).replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function firstSid(type) {
	const list = uci.sections(CFG, type);
	return list.length ? list[0]['.name'] : uci.add(CFG, type);
}

/* clean_text() of the Lua models (spec 08 §0.4) */
function cleanText(text) {
	return String(text == null ? '' : text)
		.replace(/\t/g, ' ')
		.replace(/ /g, ' ')
		.replace(/　/g, ' ')
		.replace(/^[ \t\n\r\f\v]+/, '')
		.replace(/[ \t\n\r\f\v]+$/, '\n')
		.replace(/\r\n/g, '\n')
		.replace(/[ \t]*\n[ \t]*/g, '\n');
}

function splitLines(text) {
	return String(text).split(/[\r\n]+/).filter((l) => l !== '');
}

/* domain_list validation, returns error message or null */
function checkDomainList(value) {
	const hosts = splitLines(cleanText(value));
	for (let i = 0; i < hosts.length; i++) {
		const host = hosts[i];
		let flag = true;
		let tmp = host;
		if (host.indexOf('#') < 0 && /\s/.test(host)) {
			/* contains whitespace: checked as hostname below (fails) */
		} else if (host.indexOf('regexp:') === 0) {
			flag = false;
		} else if (/^domain:./.test(host)) {
			tmp = host.split('domain:').join('');
		} else if (/^full:./.test(host)) {
			tmp = host.split('full:').join('');
		} else if (host.indexOf('geosite:') === 0) {
			flag = false;
		} else if (host.indexOf('rule-set:') === 0 || host.indexOf('rs:') === 0) {
			const w = host.substring(host.indexOf(':') + 1);
			if (w.indexOf('local:') === 0 || w.indexOf('remote:') === 0)
				flag = false;
		} else if (host.indexOf('#') === 0) {
			flag = false;
		}
		if (flag && !pw.datatype('hostname', tmp))
			return tmp + ' ' + _('Not valid domain name, please re-enter!');
	}
	return null;
}

/* ip_list validation, returns error message or null */
function checkIpList(value) {
	const lines = splitLines(cleanText(value));
	for (let i = 0; i < lines.length; i++) {
		const ipmask = lines[i];
		if (ipmask.indexOf('geoip:') === 0 && !/\s/.test(ipmask)) continue;
		if (ipmask.indexOf('rule-set:') === 0 || ipmask.indexOf('rs:') === 0) continue;
		if (ipmask.indexOf('#') === 0) continue;
		if (!(pw.datatype('ipmask4', ipmask) || pw.datatype('ipmask6', ipmask)))
			return ipmask + ' ' + _('Not valid IP format, please re-enter!');
	}
	return null;
}

/*
 * Lua MultiValue (widget=checkbox): stored as ONE option, values joined by a space.
 */
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
		const boxes = (this.keylist || []).map((k, i) => {
			const cb = E('input', { 'type': 'checkbox', 'class': 'cbi-input-checkbox', 'value': k, 'id': id + '.' + k });
			cb.checked = !!selected[k];
			cb.addEventListener('change', () => {
				const ev = new CustomEvent('widget-change', { bubbles: true });
				wrap.dispatchEvent(ev);
			});
			return E('label', { 'for': id + '.' + k, 'style': 'display:inline-flex;align-items:center;gap:.35em;margin-right:1em' },
				[cb, this.vallist[i]]);
		});
		const wrap = E('div', { 'id': id, 'class': 'pw-checkbox-group', 'style': 'display:flex;flex-wrap:wrap;gap:.3em 0' }, boxes);
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

/* DynamicList with cast="string": stored as one space separated option, de-duplicated */
const StringDynamicList = form.DynamicList.extend({
	__name__: 'PW.StringDynamicList',

	cfgvalue: function (section_id, set_value) {
		if (arguments.length > 1)
			return form.DynamicList.prototype.cfgvalue.apply(this, arguments);
		const v = form.DynamicList.prototype.cfgvalue.apply(this, [section_id]);
		if (v == null) return null;
		return (Array.isArray(v) ? v : String(v).split(' ')).filter((x) => x !== '');
	},

	write: function (section_id, value) {
		const seen = {}, out = [];
		L.toArray(value).forEach((x) => {
			if (x != null && x !== '' && !seen[x]) { seen[x] = true; out.push(x); }
		});
		if (out.length)
			uci.set(CFG, section_id, this.option, out.join(' '));
		else
			uci.unset(CFG, section_id, this.option);
	}
});

return view.extend({
	load: function () {
		return Promise.all([
			uci.load(CFG),
			L.resolveDefault(pw.loadCSS(), null)
		]);
	},

	render: function () {
		const sid = pageSid();
		const back = purl('rule');

		if (!sid || !uci.get(CFG, sid)) {
			window.location.href = back;
			return E('div');
		}

		const remarksLookup = {};
		const groups = [];
		uci.sections(CFG, 'shunt_rules').forEach((r) => {
			if (r['.name'] === sid) return;
			if (r.remarks != null)
				remarksLookup[r.remarks] = r['.name'];
			if (r.group && r.group !== '' && groups.indexOf(r.group) < 0)
				groups.push(r.group);
		});

		let m, s, o;
		m = new form.Map(CFG);

		/* on_before_save: any shunt rule change flushes the IP sets on next start */
		const origParse = m.parse;
		m.parse = function () {
			return origParse.apply(this, arguments).then(() => {
				uci.set(CFG, firstSid('global'), 'flush_set', '1');
			});
		};

		s = m.section(form.NamedSection, sid, 'shunt_rules', 'Sing-Box/Xray ' + _('Shunt Rule'));
		s.addremove = false;
		s.dynamic = false;

		o = s.option(form.Value, 'remarks', _('Remarks'));
		o.default = sid;
		o.rmempty = false;
		o.validate = function (section_id, value) {
			const v = trim(value);
			if (v === '')
				return _('Remark cannot be empty.');
			if (remarksLookup[v])
				return _('This remark already exists, please change a new remark.');
			return true;
		};
		o.write = function (section_id, value) {
			uci.set(CFG, section_id, 'remarks', trim(value));
		};

		o = s.option(form.Value, 'group', _('Shunt Rule Group'));
		o.default = '';
		o.value('', _('default'));
		groups.forEach((g) => o.value(g));
		o.write = function (section_id, value) {
			value = trim(value);
			const lv = lower(value);
			if (lv === '' || lv === 'default')
				return uci.unset(CFG, section_id, 'group');
			const keys = this.keylist || [];
			for (let i = 0; i < keys.length; i++)
				if (lower(keys[i]) === lv)
					return uci.set(CFG, section_id, 'group', keys[i]);
			uci.set(CFG, section_id, 'group', value);
		};

		o = s.option(CheckboxMulti, 'protocol', _('Protocol'));
		o.value('http');
		o.value('tls');
		o.value('quic');
		o.value('bittorrent');

		o = s.option(CheckboxMulti, 'inbound', _('Inbound Tag'));
		o.value('tproxy', _('Transparent proxy'));
		o.value('socks', 'Socks');

		o = s.option(form.ListValue, 'network', _('Network'));
		o.value('tcp,udp', 'TCP UDP');
		o.value('tcp', 'TCP');
		o.value('udp', 'UDP');

		o = s.option(StringDynamicList, 'source', _('Source'));
		o.description = '<ul><li>' + _('Example:') +
			'</li><li>' + _('IP') + ': 192.168.1.100' +
			'</li><li>' + _('IP CIDR') + ': 192.168.1.0/24' +
			'</li><li>' + _('GeoIP') + ': geoip:private' +
			'</li></ul>';
		o.validate = function (section_id, value) {
			if (value == null || value === '') return true;
			if (pw.datatype('ip4addr', value) || String(value).indexOf('geoip:') === 0)
				return true;
			return _('Not true format, please re-enter!') + ' ' + value;
		};

		o = s.option(form.Value, 'port', _('Port'));

		o = s.option(form.TextValue, 'domain_list', _('Domain'));
		o.rows = 10;
		o.wrap = 'off';
		o.monospace = true;
		o.validate = function (section_id, value) {
			const err = checkDomainList(value || '');
			return err ? err : true;
		};
		o.write = function (section_id, value) {
			uci.set(CFG, section_id, 'domain_list', cleanText(value));
		};
		o.description = '<br /><ul>' +
			'<li>' + _("Plaintext: If this string matches any part of the targeting domain, this rule takes effect. Example: rule 'sina.com' matches targeting domain 'sina.com', 'sina.com.cn' and 'www.sina.com', but not 'sina.cn'.") + '</li>' +
			'<li>' + _("Regular expression: Beginning with 'regexp:', the rest is a regular expression. When the regexp matches targeting domain, this rule takes effect. Example: rule 'regexp:\\.goo.*\\.com$' matches 'www.google.com' and 'fonts.googleapis.com', but not 'google.com'.") + '</li>' +
			'<li>' + _("Subdomain (recommended): Beginning with 'domain:' and the rest is a domain. When the targeting domain is exactly the value, or is a subdomain of the value, this rule takes effect. Example: rule 'domain:v2ray.com' matches 'www.v2ray.com', 'v2ray.com', but not 'xv2ray.com'.") + '</li>' +
			'<li>' + _("Full domain: Beginning with 'full:' and the rest is a domain. When the targeting domain is exactly the value, the rule takes effect. Example: rule 'full:v2ray.com' matches 'v2ray.com', but not 'www.v2ray.com'.") + '</li>' +
			'<li>' + _("Pre-defined domain list: Beginning with 'geosite:' and the rest is a name, such as geosite:google or geosite:cn.") + '</li>' +
			'<li>' + _("Sing-Box rule-set: Beginning with 'rule-set:remote:' or 'rule-set:local:'") +
			'<ul>' +
			'<li>' + _('Such as:') + "'rule-set:remote:https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs'" + '</li>' +
			'<li>' + _('Such as:') + "'rule-set:local:/usr/share/sing-box/geosite-cn.srs'" + '</li>' +
			'</ul>' +
			'</li>' +
			'<li>' + _('Annotation: Beginning with #') + '</li>' +
			'</ul>';

		o = s.option(form.TextValue, 'ip_list', 'IP');
		o.rows = 10;
		o.wrap = 'off';
		o.monospace = true;
		o.validate = function (section_id, value) {
			const err = checkIpList(value || '');
			return err ? err : true;
		};
		o.write = function (section_id, value) {
			uci.set(CFG, section_id, 'ip_list', cleanText(value));
		};
		o.description = '<br /><ul>' +
			'<li>' + _("IP: such as '127.0.0.1'.") + '</li>' +
			'<li>' + _("CIDR: such as '127.0.0.0/8'.") + '</li>' +
			'<li>' + _("GeoIP: such as 'geoip:cn'. It begins with geoip: (lower case) and followed by two letter of country code.") + '</li>' +
			'<li>' + _("Sing-Box rule-set: Beginning with 'rule-set:remote:' or 'rule-set:local:'") +
			'<ul>' +
			'<li>' + _('Such as:') + "'rule-set:remote:https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs'" + '</li>' +
			'<li>' + _('Such as:') + "'rule-set:local:/usr/share/sing-box/geoip-cn.srs'" + '</li>' +
			'</ul>' +
			'</li>' +
			'<li>' + _('Annotation: Beginning with #') + '</li>' +
			'</ul>';

		o = s.option(form.Flag, 'invert', 'invert', _('Invert match result.') + ' ' + _('Only support Sing-Box.'));

		pw.redirectAfterApply(back);

		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Shunt Rule'), uci.get(CFG, sid, 'remarks') || sid, [
				E('a', { 'class': 'btn cbi-button', 'href': back }, [_('Back')])
			]),
			mapEl
		]));
	}
});
