'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';
'require rpc';
'require passwall2.pw as pw';

/*
 * ACL rule editor, acl_config/<sid> (upstream: model/cbi/passwall2/client/acl_config.lua,
 * client/include/shunt_options.lua, view/passwall2/include/node_change.htm, include/shunt_options.htm).
 * Spec 08 §12 / §15, 10 §3.4 / §3.5.
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

function firstSid(type) {
	const list = uci.sections(CFG, type);
	return list.length ? list[0]['.name'] : uci.add(CFG, type);
}

function fileExists(path) {
	return L.resolveDefault(fs.stat(path), null).then((st) => !!st);
}

function portNormalize(v) {
	return String(v == null ? '' : v).replace(/-/g, ':');
}

/* Lua datatypes.macaddr: six ':'-separated hex groups, each <= 0xff */
function isMacAddr(v) {
	if (!/^[a-fA-F0-9]+(:[a-fA-F0-9]+){5}$/.test(v)) return false;
	return v.split(':').every((p) => parseInt(p, 16) <= 255);
}

/* api.iprange: "^([^/]+)-([^/]+)$", both ip4addr */
function isIPRange(v) {
	const m = String(v).match(/^([^/]+)-([^/]+)$/);
	return !!m && pw.datatype('ip4addr', m[1]) && pw.datatype('ip4addr', m[2]);
}

function isSourceValid(v) {
	v = String(v);
	if (v.indexOf('ipset:') === 0 && v.split('ipset:').join('') !== '') return true;
	if (isMacAddr(v)) return true;
	if (pw.datatype('ip4addr', v)) return true;
	if (isIPRange(v)) return true;
	return false;
}

/* api.get_node_name: only balancing / shunt / iface nodes have a name */
function getNodeName(e) {
	if (e && e.type && e.remarks && e.protocol &&
		(e.protocol === '_balancing' || e.protocol === '_shunt' || e.protocol === '_iface')) {
		const typeName = (e.type === 'sing-box') ? 'Sing-Box' : e.type;
		return '%s：[%s] '.format(typeName + ' ' + _(e.protocol), e.remarks);
	}
	return '';
}

const callNetworkDevices = rpc.declare({ object: 'luci-rpc', method: 'getNetworkDevices', expect: { '': {} } });
const callHostHints = rpc.declare({ object: 'luci-rpc', method: 'getHostHints', expect: { '': {} } });

/* api.get_network_devices() port */
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

/* sys.net.mac_hints(): {mac, ip(hint)} sorted by hint length, then lexicographically */
function loadMacHints() {
	return L.resolveDefault(callHostHints(), {}).then((hosts) => {
		const out = [];
		Object.keys(hosts || {}).forEach((mac) => {
			if (!isMacAddr(mac)) return;
			const h = hosts[mac] || {};
			const hint = h.name || (h.ipaddrs && h.ipaddrs[0]) || (h.ip6addrs && h.ip6addrs[0]);
			if (hint) out.push({ mac: mac, ip: String(hint) });
		});
		out.sort((a, b) => (a.ip.length !== b.ip.length) ? (a.ip.length - b.ip.length) : (a.ip < b.ip ? -1 : (a.ip > b.ip ? 1 : 0)));
		return out;
	});
}

/*
 * Map with the dependency semantics of the Lua CBI: an inactive (hidden) or missing field counts as ""
 * (upstream relies on that, e.g. `_no_proxy = ""` or `node != ""` while node is hidden).
 */
const LegacyMap = form.Map.extend({
	isDependencySatisfied: function (depends, config_name, section_id) {
		let def = false;
		if (!Array.isArray(depends) || !depends.length)
			return true;
		for (let i = 0; i < depends.length; i++) {
			let istat = true;
			const reverse = !!depends[i]['!reverse'];
			for (const dep in depends[i]) {
				if (dep === '!reverse' || dep === '!contains')
					continue;
				if (dep === '!default') {
					def = true;
					istat = false;
					continue;
				}
				const res = this.lookupOption(dep, section_id, config_name);
				let val = (res && res[0].isActive(res[1])) ? res[0].formvalue(res[1]) : '';
				if (val == null) val = '';
				istat = istat && (String(val) === String(depends[i][dep]));
			}
			if (istat !== reverse)
				return true;
		}
		return def;
	}
});

return view.extend({
	load: function () {
		const sid = pageSid();
		return Promise.all([
			uci.load(CFG),
			loadNetworkDevices(),
			loadMacHints(),
			pw.isFinded('geoview'),
			sid ? fileExists(TMP_PATH + '/acl/' + sid + '.log') : Promise.resolve(false),
			L.resolveDefault(pw.loadCSS(), null)
		]).then((r) => pw.getNodes().then((nodes) => {
			return { sid: sid, ifaces: r[1], macs: r[2], hasGeoview: r[3], hasLog: r[4], nodes: nodes };
		}));
	},

	render: function (data) {
		const sid = data.sid;
		const back = purl('acl');

		if (!sid || !uci.get(CFG, sid)) {
			window.location.href = back;
			return E('div');
		}

		const nodes = data.nodes;
		const currentNodeId = uci.get(CFG, sid, 'node');
		const currentNode = (currentNodeId && uci.get(CFG, currentNodeId)) || {};

		let m, s, o;
		m = new LegacyMap(CFG);

		/* [[ ACLs Settings ]] */
		s = m.section(form.NamedSection, sid, 'acl_rule', _('ACLs'));
		s.addremove = false;

		s.tab('Main', _('Main'));
		s.tab('Proxy', _('Proxy'));
		s.tab('DNS', _('DNS'));
		s.tab('Log', _('Log'));

		o = s.taboption('Main', form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('Main', form.Value, 'remarks', _('Remarks'));
		o.default = sid;
		o.rmempty = false;

		o = s.taboption('Main', form.Value, 'interface', _('Source Interface'));
		o.value('', _('All'));
		data.ifaces.forEach((d) => o.value(d.name, d.label));
		o.validate = function (section_id, value) {
			if (value == null || value === '' || /^[a-zA-Z0-9][a-zA-Z0-9._-]*$/.test(value))
				return true;
			return _('Invalid interface name');
		};

		o = s.taboption('Main', form.DynamicList, 'sources', _('Source'));
		o.description = '<ul><li>' + _('Example:') +
			'</li><li>' + _('MAC') + ': 00:00:00:FF:FF:FF' +
			'</li><li>' + _('IP') + ': 192.168.1.100' +
			'</li><li>' + _('IP CIDR') + ': 192.168.1.0/24' +
			'</li><li>' + _('IP range') + ': 192.168.1.100-192.168.1.200' +
			'</li><li>' + _('IPSet') + ': ipset:lanlist' +
			'</li></ul>';
		data.macs.forEach((h) => o.value(h.mac, '%s (%s)'.format(h.mac, h.ip)));
		o.validate = function (section_id, value) {
			if (value == null || value === '') return true;
			return isSourceValid(value) ? true : (_('Not true format, please re-enter!') + ' ' + value);
		};
		o.write = function (section_id, value) {
			const seen = {}, out = [];
			L.toArray(value).forEach((x) => { if (x && !seen[x]) { seen[x] = true; out.push(x); } });
			if (out.length) uci.set(CFG, section_id, 'sources', out);
			else uci.unset(CFG, section_id, 'sources');
		};

		const globalNode = uci.get_first(CFG, 'global', 'node');
		o = s.taboption('Main', form.ListValue, 'mode', _('Mode'));
		o.value('0', _('No Proxy'));
		o.value('1', _('Proxy'));
		o.value('2', _('Proxy') + ' ' + _('Use global config') + '(' + getNodeName(globalNode ? uci.get(CFG, globalNode) : null) + ')');

		const portOption = (name, title, choices, def, deps) => {
			o = s.taboption('Proxy', form.Value, name, title);
			choices.forEach((c) => o.value(c[0], c[1]));
			if (def != null) o.default = def;
			o.write = function (section_id, value) {
				uci.set(CFG, section_id, name, portNormalize(value));
			};
			deps.forEach((d) => o.depends(d));
			return o;
		};

		portOption('tcp_no_redir_ports', _('TCP No Redir Ports'),
			[['', _('No patterns are used')], ['1:65535', _('All')]], null, [{ mode: '1' }, { mode: '2' }]);
		portOption('udp_no_redir_ports', _('UDP No Redir Ports'),
			[['', _('No patterns are used')], ['1:65535', _('All')]], null, [{ mode: '1' }, { mode: '2' }]);

		o = s.taboption('Main', pw.HideValue, '_show_tcp_redir');
		o.depends({ tcp_no_redir_ports: '1:65535', '!reverse': true });

		o = s.taboption('Main', pw.HideValue, '_show_udp_redir');
		o.depends({ udp_no_redir_ports: '1:65535', '!reverse': true });

		portOption('tcp_redir_ports', _('TCP Redir Ports'),
			[['1:65535', _('All')],
			['22,25,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418', _('Common Use')],
			['80,443', '80,443']], '1:65535',
			[{ _node: '1', _show_tcp_redir: '1' }, { mode: '2', _show_tcp_redir: '1' }]);
		portOption('udp_redir_ports', _('UDP Redir Ports'),
			[['1:65535', _('All')]], '1:65535',
			[{ _node: '1', _show_udp_redir: '1' }, { mode: '2', _show_udp_redir: '1' }]);

		o = s.taboption('Proxy', form.DummyValue, 'tips', '　');
		o.rawhtml = true;
		o.cfgvalue = function () {
			return '<font color="red">%s</font>'.format(
				_('The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000.'));
		};
		o.depends('mode', '1');
		o.depends('mode', '2');

		o = s.taboption('Main', pw.HideValue, '_no_proxy');
		o.depends('mode', '0');
		o.depends({ tcp_no_redir_ports: '1:65535', udp_no_redir_ports: '1:65535' });

		o = s.taboption('Main', pw.HideValue, '_show_node_option');
		o.depends({ mode: '1', _no_proxy: '' });

		const nodeOpt = pw.addNodeOption(s, 'node', "<a style='color: red'>" + _('Node') + '</a>', { tab: 'Main', nodes: nodes });
		nodeOpt.depends('_show_node_option', '1');

		o = s.taboption('Main', pw.HideValue, '_node');
		o.depends({ node: '', '!reverse': true });

		const isSingbox = s.taboption('Main', pw.HideValue, '_is_singbox');
		isSingbox.depends('_hide', '1');

		o = s.taboption('Main', pw.HideValue, '_is_xray');
		o.depends('_hide', '1');

		/* [[ Log ]] */
		o = s.taboption('Log', form.Flag, 'log', _('Enable Node Log'));
		o.depends('_node', '1');

		o = s.taboption('Log', form.ListValue, 'loglevel', _('Log Level'));
		o.default = 'warn';
		o.value('debug', 'Debug');
		o.value('info', 'Info');
		o.value('warn', 'Warning');
		o.value('error', 'Error');
		o.depends('log', '1');

		o = s.taboption('Log', form.DummyValue, '_acl_log', _('Log File'));
		o.renderWidget = function () {
			const items = [E('code', {}, [TMP_PATH + '/acl/' + sid + '.log'])];
			if (data.hasLog)
				items.push(E('button', {
					'class': 'btn cbi-button cbi-button-apply', 'type': 'button',
					'click': ui.createHandlerFn(this, () => pw.showLog(_('Log File'), 'get_redir_log', { id: sid }))
				}, [_('View Log')]));
			return E('div', { 'style': 'display:flex;gap:.6em;align-items:center;flex-wrap:wrap' }, items);
		};
		o.depends('log', '1');

		/* [[ DNS ]] */
		o = s.taboption('DNS', pw.HideValue, '_show_dns_option');
		o.depends({ mode: '1', _node: '1' });

		o = s.taboption('DNS', form.ListValue, 'direct_dns_query_strategy', _('Direct Query Strategy'));
		o.default = 'UseIP';
		o.value('UseIP');
		o.value('UseIPv4');
		o.value('UseIPv6');
		o.depends('_show_dns_option', '1');

		o = s.taboption('DNS', form.ListValue, 'remote_dns_protocol', _('Remote DNS Protocol'));
		o.value('tcp', 'TCP');
		o.value('doh', 'DoH');
		o.value('udp', 'UDP');
		if (currentNode.type === 'sing-box') {
			o.value('tls', 'TLS(DoT)');
			o.value('quic', 'QUIC(DoQ)');
			o.value('http3', 'HTTP3(DoH3)');
		}
		o.depends('_show_dns_option', '1');

		o = s.taboption('DNS', form.Value, 'remote_dns', _('Remote DNS'));
		o.datatype = 'or(ipaddr,ipaddrport(1))';
		o.default = '1.1.1.1';
		o.value('1.1.1.1', '1.1.1.1 (CloudFlare)');
		o.value('1.1.1.2', '1.1.1.2 (CloudFlare-Security)');
		o.value('8.8.4.4', '8.8.4.4 (Google)');
		o.value('8.8.8.8', '8.8.8.8 (Google)');
		o.value('9.9.9.9', '9.9.9.9 (Quad9-Recommended)');
		o.value('149.112.112.112', '149.112.112.112 (Quad9-Recommended)');
		o.value('208.67.220.220', '208.67.220.220 (OpenDNS)');
		o.value('208.67.222.222', '208.67.222.222 (OpenDNS)');
		['tcp', 'udp', 'quic', 'tls'].forEach((p) => o.depends('remote_dns_protocol', p));

		o = s.taboption('DNS', form.Value, 'remote_dns_doh', _('Remote DNS DoH'));
		o.value('https://1.1.1.1/dns-query', 'CloudFlare');
		o.value('https://1.1.1.2/dns-query', 'CloudFlare-Security');
		o.value('https://8.8.4.4/dns-query', 'Google 8844');
		o.value('https://8.8.8.8/dns-query', 'Google 8888');
		o.value('https://9.9.9.9/dns-query', 'Quad9-Recommended 9.9.9.9');
		o.value('https://149.112.112.112/dns-query', 'Quad9-Recommended 149.112.112.112');
		o.value('https://208.67.222.222/dns-query', 'OpenDNS');
		o.value('https://dns.adguard.com/dns-query,94.140.14.14', 'AdGuard');
		o.value('https://doh.libredns.gr/dns-query,116.202.176.26', 'LibreDNS');
		o.value('https://doh.libredns.gr/ads,116.202.176.26', 'LibreDNS (No Ads)');
		o.default = 'https://1.1.1.1/dns-query';
		/* doh_validate (ACL variant: extra elements must be IPv4) */
		o.validate = function (section_id, value) {
			if (value != null && value !== '') {
				const val = String(value).split(',');
				val.shift();
				if (val.every((v) => v === '' || pw.datatype('ipmask4', v)))
					return true;
			}
			return _('DoH request address') + ' ' + _('Format must be:') + ' URL,IP';
		};
		o.depends('remote_dns_protocol', 'doh');
		o.depends('remote_dns_protocol', 'http3');

		o = s.taboption('DNS', form.Value, 'remote_dns_client_ip', _('Remote DNS EDNS Client Subnet'));
		o.description = _('Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).') + '<br />' +
			_('This feature requires the DNS server to support the Edns Client Subnet (RFC7871).');
		o.datatype = 'ipaddr';
		o.depends('_show_dns_option', '1');

		o = s.taboption('DNS', form.ListValue, 'remote_dns_detour', _('Remote DNS Outbound'));
		o.default = 'remote';
		o.value('remote', _('Remote'));
		o.value('direct', _('Direct'));
		o.depends('_show_dns_option', '1');

		const remoteFakedns = s.taboption('DNS', form.Flag, 'remote_fakedns', 'FakeDNS', _('Use FakeDNS work in the domain that proxy.'));
		remoteFakedns.default = '0';
		remoteFakedns.rmempty = false;
		remoteFakedns.depends('_hide', '1');

		o = s.taboption('DNS', form.ListValue, 'remote_dns_query_strategy', _('Remote Query Strategy'));
		o.default = 'UseIPv4';
		o.value('UseIP');
		o.value('UseIPv4');
		o.value('UseIPv6');
		o.depends('_show_dns_option', '1');

		o = s.taboption('DNS', form.Value, 'remote_rewrite_ttl', _('Remote DNS') + ' TTL');
		o.datatype = 'min(1)';
		o.default = '30';
		o.depends({ _show_dns_option: '1', _is_singbox: '1' });

		o = s.taboption('DNS', form.ListValue, 'dns_hosts_mode', _('Domain Override'));
		o.value('default', _('Use global config'));
		o.value('disable', _('No patterns are used'));
		o.value('custom', _('-- custom --'));
		o.depends('_show_dns_option', '1');

		o = s.taboption('DNS', form.TextValue, 'dns_hosts', _('Domain Override'));
		o.rows = 5;
		o.wrap = 'off';
		o.monospace = true;
		o.depends('dns_hosts_mode', 'custom');
		/* only delete when the submitted node is an Xray / sing-box node */
		o.remove = function (section_id) {
			if (!nodeOpt.isActive(section_id)) return;
			const nv = this.section.formvalue(section_id, 'node');
			const t = nv ? uci.get(CFG, nv) : null;
			if (t && (t.type === 'Xray' || t.type === 'sing-box'))
				uci.unset(CFG, section_id, 'dns_hosts');
		};

		/* node dependent visibility */
		nodes.forEach((v) => {
			if (v.type === 'sing-box')
				isSingbox.depends({ node: v.id });
			if (v.node_type === 'normal' || v.protocol === '_balancing' || v.protocol === '_urltest')
				remoteFakedns.depends({ node: v.id, _show_dns_option: '1' });
		});

		/*
		 * [[ Shunt ]] (include/shunt_options.lua): the options live on the shunt node itself. Upstream renders
		 * them only for the saved node and re-submits the page when another shunt node is picked
		 * (include/node_change.htm); here every shunt node's editor is rendered and shown while selected.
		 */
		pw.addShuntOptions(s, {
			sectionId: sid,
			nodeOption: 'node',
			tab: 'Shunt',
			tabTitle: _('Shunt Rule'),
			nodes: nodes,
			geoview: data.hasGeoview,
			globalSid: firstSid('global')
		});

		pw.redirectAfterApply(back);

		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Access control'), uci.get(CFG, sid, 'remarks') || sid, [
				E('a', { 'class': 'btn cbi-button', 'href': back }, [_('Back')])
			]),
			mapEl
		]));
	}
});
