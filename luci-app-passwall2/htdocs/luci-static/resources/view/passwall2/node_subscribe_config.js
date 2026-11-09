'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require rpc';
'require passwall2.pw as pw';

/*
 * Subscription editor, node_subscribe_config/<sid>
 * (upstream: model/cbi/passwall2/client/node_subscribe_config.lua). Spec 08 §5.
 */

const CFG = 'passwall2';

function purl() {
	return L.url.apply(L, ['admin/services/passwall2'].concat(Array.prototype.slice.call(arguments)));
}

function trim(s) {
	return (s == null ? '' : String(s)).replace(/^[\x00-\x20]+/, '').replace(/[\x00-\x20]+$/, '');
}

function lower(s) {
	return (s == null ? '' : String(s)).replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function urlEncode(s) {
	if (typeof s !== 'string') return '';
	return encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

/* section id = first path segment after the dispatched page */
function pageSid() {
	const req = L.env.requestpath || [], disp = L.env.dispatchpath || [];
	if (req.length > disp.length)
		return req[disp.length];
	return null;
}

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

const callNetworkDevices = rpc.declare({
	object: 'luci-rpc',
	method: 'getNetworkDevices',
	expect: { '': {} }
});

/* api.get_network_devices() port (spec 05): kernel devices + offline UCI interfaces */
function loadNetworkDevices() {
	return Promise.all([
		L.resolveDefault(callNetworkDevices(), {}),
		L.resolveDefault(uci.load('network'), null)
	]).then((r) => {
		const devs = r[0] || {};
		const ifaceToDev = {}, devToIfaces = {}, ifaceProto = {};
		(uci.sections('network', 'interface') || []).forEach((sec) => {
			const name = sec['.name'];
			if (name === 'loopback') return;
			ifaceProto[name] = sec.proto;
			if (sec.device) {
				ifaceToDev[name] = sec.device;
				(devToIfaces[sec.device] = devToIfaces[sec.device] || []).push(name);
			}
		});
		const classifyDev = (name, d) => {
			if (d.devtype === 'bridge' || d.bridge) return _('Bridge');
			if (d.wireless || d.devtype === 'wlan') return _('Wireless Adapter');
			if (/^(tun|tap|wg|ppp)/.test(name)) return _('Tunnel Interface');
			return _('Ethernet Adapter');
		};
		const classifyUci = (dev, proto) => {
			if (dev && /^br-/.test(dev)) return _('Bridge');
			if (proto === 'wireguard' || proto === 'pppoe' || proto === 'pptp' || proto === 'l2tp') return _('Tunnel Interface');
			return _('Interface');
		};
		const seen = {}, out = [];
		Object.keys(devs).forEach((name) => {
			const d = devs[name] || {};
			if (name === 'lo' || /^(veth|ifb|gre|sit|ip6tnl|erspan)/.test(name) || d.master || d.devtype === 'dsa')
				return;
			const dtype = classifyDev(name, d);
			let label = dtype + ': "' + name + '"';
			if (devToIfaces[name])
				label += ' (' + devToIfaces[name].join(', ') + ')';
			out.push({ name: name, label: label, sort: dtype + ':' + name });
			seen[name] = true;
		});
		Object.keys(ifaceToDev).forEach((iface) => {
			const dev = ifaceToDev[iface];
			if (seen[dev]) return;
			out.push({ name: iface, label: classifyUci(dev, ifaceProto[iface]) + ': "' + iface + '"', sort: 'zzz:' + iface });
			seen[dev] = true;
		});
		out.sort((a, b) => (a.sort < b.sort) ? -1 : (a.sort > b.sort ? 1 : 0));
		return out;
	});
}

function timeChoices(o) {
	const seen = {};
	const add = (v) => { if (!seen[v]) { seen[v] = true; o.value(v); } };
	add('0:00');
	for (let t = 0; t <= 23; t++)
		add(t === 12 ? t + ':30' : (t === 23 ? t + ':59' : t + ':00'));
}

return view.extend({
	load: function () {
		const sid = pageSid();
		return Promise.all([
			uci.load(CFG),
			loadCoreTypes(),
			loadNetworkDevices(),
			L.resolveDefault(pw.loadCSS(), null)
		]).then((r) => {
			r.push(sid);
			return r;
		});
	},

	render: function (data) {
		const types = data[1], ifaces = data[2], sid = data[4];
		const back = purl('node_subscribe');

		if (!sid || !uci.get(CFG, sid)) {
			window.location.href = back;
			return E('div');
		}

		let m, s, o;
		m = new form.Map(CFG);

		/* on_before_save: delete <sid>.md5 */
		const origParse = m.parse;
		m.parse = function () {
			return origParse.apply(this, arguments).then(() => {
				if (uci.get(CFG, sid, 'md5') != null)
					uci.unset(CFG, sid, 'md5');
			});
		};

		s = m.section(form.NamedSection, sid, 'subscribe_list');
		s.addremove = false;
		s.dynamic = false;

		o = s.option(form.Value, 'remark', _('Subscribe Remark'));
		o.rmempty = false;
		o.validate = function (section_id, value) {
			const v = trim(value);
			if (v === '')
				return _('Remark cannot be empty.');
			const dup = uci.sections(CFG, 'subscribe_list').some((e) =>
				e['.name'] !== section_id && e.remark != null && lower(e.remark) === lower(v));
			if (dup || lower(v) === 'default')
				return _('This remark already exists, please change a new remark.');
			return true;
		};
		o.write = function (section_id, value) {
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
		};

		o = s.option(form.TextValue, 'url', _('Subscribe URL'));
		o.rows = 5;
		o.rmempty = false;
		o.validate = function (section_id, value) {
			if (value == null || value === '')
				return _('URL cannot be empty.');
			return true;
		};
		o.write = function (section_id, value) {
			uci.set(CFG, section_id, 'url', String(value).replace(/\s+/g, '').replace(/\0/g, ''));
		};

		o = s.option(form.ListValue, 'domain_resolver', _('Domain DNS Resolve'));
		o.description = _('If the node address is a domain name, this DNS will be used for resolution.') + '<br>' +
			_('Supports only Xray or Sing-box node types.') + '<br>' +
			'<font color="red">%s</font>'.format(_('Note: Auto tries to extract node DNS from Clash subscriptions. Disable skips extraction.'));
		o.default = '';
		o.value('disable', _('Disable'));
		o.value('', _('Auto'));
		o.value('tcp', 'TCP');
		o.value('udp', 'UDP');
		o.value('https', 'DoH');

		o = s.option(form.Value, 'domain_resolver_dns', 'DNS');
		o.datatype = 'or(ipaddr,ipaddrport)';
		o.value('114.114.114.114');
		o.value('223.5.5.5:53');
		o.default = '114.114.114.114';
		o.depends({ domain_resolver: 'tcp' });
		o.depends({ domain_resolver: 'udp' });

		o = s.option(form.Value, 'domain_resolver_dns_https', 'DNS');
		o.value('https://120.53.53.53/dns-query', 'DNSPod');
		o.value('https://223.5.5.5/dns-query', 'AliDNS');
		o.default = 'https://120.53.53.53/dns-query';
		o.depends({ domain_resolver: 'https' });

		o = s.option(form.ListValue, 'domain_strategy', _('Domain Strategy'),
			_('If is domain name, The requested domain name will be resolved to IP before connect.'));
		o.default = '';
		o.value('', _('Auto'));
		o.value('UseIPv4', _('IPv4 Only'));
		o.value('UseIPv6', _('IPv6 Only'));

		o = s.option(form.Flag, 'allowInsecure', _('allowInsecure'));
		o.default = '0';
		o.rmempty = false;
		o.description = _('Whether unsafe connections are allowed. When checked, Certificate validation will be skipped.') + '<br>' +
			_('Used when the node link does not include this parameter.');

		o = s.option(form.ListValue, 'filter_keyword_mode', _('Filter keyword Mode'));
		o.default = '5';
		o.value('0', _('Close'));
		o.value('1', _('Discard List'));
		o.value('2', _('Keep List'));
		o.value('3', _('Discard List,But Keep List First'));
		o.value('4', _('Keep List,But Discard List First'));
		o.value('5', _('Use global config'));

		o = s.option(form.DynamicList, 'filter_discard_list', _('Discard List'));
		o.depends('filter_keyword_mode', '1');
		o.depends('filter_keyword_mode', '3');
		o.depends('filter_keyword_mode', '4');

		o = s.option(form.DynamicList, 'filter_keep_list', _('Keep List'));
		o.depends('filter_keyword_mode', '2');
		o.depends('filter_keyword_mode', '3');
		o.depends('filter_keyword_mode', '4');

		[
			['ss_type', 'Shadowsocks'],
			['trojan_type', 'Trojan'],
			['vmess_type', 'VMess'],
			['vless_type', 'VLESS'],
			['hysteria2_type', 'Hysteria2']
		].forEach((d) => {
			const list = types[d[0]];
			if (!list.length) return;
			o = s.option(form.ListValue, d[0], _('%s Node Use Type').format(d[1]));
			o.default = 'global';
			o.value('global', _('Use global config'));
			list.forEach((v) => o.value(v));

			if (d[0] === 'hysteria2_type') {
				o = s.option(form.Value, 'hysteria_up_mbps', 'Hy/Hy2 ' + _('Max upload Mbps'));
				o.datatype = 'uinteger';

				o = s.option(form.Value, 'hysteria_down_mbps', 'Hy/Hy2 ' + _('Max download Mbps'));
				o.datatype = 'uinteger';
			}
		});

		o = s.option(form.Flag, 'boot_update', _('Update Once on Boot'),
			_('Updates the subscription the first time runs automatically after each system boot.'));
		o.default = '0';

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
		/* LuCI loads with cfgvalue(sid, value): keep the two-argument call so the value is stored */
		o.cfgvalue = function (section_id, set_value) {
			if (arguments.length > 1)
				return form.Value.prototype.cfgvalue.call(this, section_id, pw.legacyHour(set_value));
			return form.Value.prototype.cfgvalue.call(this, section_id);
		};
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

		o = s.option(form.ListValue, 'access_mode', _('Subscribe URL Access Method'));
		o.default = '';
		o.value('', _('Auto'));
		o.value('direct', _('Direct Connection'));
		o.value('proxy', _('Proxy'));

		o = s.option(form.Value, 'user_agent', _('User-Agent'));
		o.default = 'v2rayN/9.99';
		o.value('passwall2', 'PassWall2');
		o.value('v2rayN/9.99', 'v2rayN');
		o.value('clash.meta/v9.99.99', 'Clash.Meta');
		o.value('Shadowrocket/9999 CFNetwork/3896.100.1.2.1 Darwin/27.0.0 iPhone19,7', 'Shadowrocket');
		o.value('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0', 'Edge for Linux');
		o.value('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0', 'Edge for Windows');

		o = s.option(form.ListValue, 'chain_proxy', _('Chain Proxy'));
		o.value('', _('Close(Not use)'));
		o.value('1', _('Preproxy Node'));
		o.value('2', _('Landing Node'));
		o.value('3', _('Outbound Interface'));

		const descrStr = _('Chained proxy works only with Xray or Sing-box nodes.<br>You can only use manual or imported nodes as chained nodes.') +
			'<br>' + _('Only support a layer of proxy.');

		/* chain candidates: Xray/sing-box, not chained themselves, not subscription-imported */
		const chainFilter = (v) => v.node_type === 'normal' &&
			(v.type === 'Xray' || v.type === 'sing-box') && (!v.chain_proxy || v.chain_proxy === '') && v.add_mode !== '2';

		o = pw.addNodeOption(s, 'preproxy_node', _('Preproxy Node'), { types: ['normal'], filter: chainFilter });
		o.depends({ chain_proxy: '1' });
		o.description = descrStr;

		o = pw.addNodeOption(s, 'to_node', _('Landing Node'), { types: ['normal'], filter: chainFilter });
		o.depends({ chain_proxy: '2' });
		o.description = descrStr;

		o = s.option(form.Value, 'outbound_iface', _('Outbound Interface'));
		o.depends({ chain_proxy: '3' });
		o.value('', _('All'));
		ifaces.forEach((d) => o.value(d.name, d.label));

		o = s.option(form.Flag, 'hwid', _('Send HWID'));
		o.default = '0';
		o.description = _('Some subscription providers may require a hardware identifier (HWID) for authentication.') + '<br>' +
			_('Enabling this option will send a hashed HWID when updating subscriptions.') + '<br>' +
			_('This may reveal limited hardware information. Enable only if you trust your provider.');

		pw.redirectAfterApply(back);

		const remark = uci.get(CFG, sid, 'remark') || sid;
		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Node Subscribe'), remark, [
				E('a', { 'class': 'btn cbi-button', 'href': back }, [_('Back')])
			]),
			mapEl
		]));
	}
});
