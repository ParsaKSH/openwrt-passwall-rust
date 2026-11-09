'use strict';
'require view';
'require dom';
'require form';
'require fs';
'require uci';
'require ui';
'require network';
'require tools.widgets as widgets';
'require passwall2.pw as pw';

/*
 * Server instance editor (upstream: model/cbi/passwall2/server/server_config.lua +
 * server/type/{1_sing-box,2_xray,3_ss-rust,4_ssr}.lua + view/passwall2/server/config_*.htm).
 * URL: server_config/<sid>, config passwall2_server, section type `server`.
 *
 * As upstream, only the fields of the currently selected type are built (all types share
 * one flat UCI namespace: protocol, port, tls, ... ). Changing `type` stores
 * {enable, remarks, type, protocol:''} and reloads the page so the new type's form renders.
 *
 * Dependencies follow the legacy CBI semantics (spec 09 §1.2): a list of entries is OR,
 * keys inside one entry are AND; `true` = checkbox checked, `false` = unchecked OR field
 * hidden/absent, strings compare against the visible field's value ("" when hidden).
 */

var CONF = 'passwall2_server';

function url(path) {
	return L.url('admin/services/passwall2/' + path);
}

/* upstream m.redirect: after a successful Save & Apply land on `target` */
function redirectAfterApply(target) {
	if (typeof(pw.redirectAfterApply) == 'function')
		return pw.redirectAfterApply(target);
	document.addEventListener('uci-applied', function() {
		window.setTimeout(function() { window.location.href = target; }, 500);
	}, { once: true });
}

function header(title, desc) {
	try {
		if (typeof(pw.pageHeader) == 'function') {
			var n = pw.pageHeader(title, desc);
			if (n instanceof Node)
				return n;
		}
	}
	catch (e) {}
	return E('div', { 'class': 'pw-page-header' }, [
		E('h2', {}, title),
		desc ? E('div', { 'class': 'cbi-map-descr' }, desc) : ''
	]);
}

function getSid() {
	var p = L.env.requestpath || [];
	var i = p.indexOf('server_config');
	if (i >= 0 && p[i + 1])
		return p[i + 1];
	var m = /\/server_config\/([^\/?#]+)/.exec(window.location.pathname);
	return m ? decodeURIComponent(m[1]) : null;
}

/* ------------------------------------------------------------------ helpers */

/* api.trim: strip bytes <= 32 from both ends */
function trim(s) {
	return String(s == null ? '' : s).replace(/^[\x00-\x20]+|[\x00-\x20]+$/g, '');
}

function utf8Encode(str) {
	return unescape(encodeURIComponent(str));
}

function utf8Decode(bin) {
	return decodeURIComponent(escape(bin));
}

/* api.base64Encode (standard alphabet, padded) */
function b64encode(str) {
	try { return btoa(utf8Encode(String(str))); }
	catch (e) { return ''; }
}

/* api.base64Decode (accepts url-safe, missing padding); returns the input on failure */
function b64decode(str) {
	var s = String(str).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
	while (s.length % 4)
		s += '=';
	try { return utf8Decode(atob(s)); }
	catch (e) {
		try { return atob(s); }
		catch (e2) { return String(str); }
	}
}

/* cbi.js is_json: parses AND is a non-null object (arrays count) */
function isJSON(str) {
	try {
		var r = JSON.parse(str);
		return typeof(r) === 'object' && r !== null;
	}
	catch (e) {
		return false;
	}
}

/* func.js isBase64 */
function isBase64(str) {
	return /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$/.test(str);
}

/* PEM normalisation of every "\n"-escaped field (spec 09 §1.4) */
function pemEscape(value) {
	var v = trim(value).replace(/\r\n/g, '\n').replace(/\r/g, '\n')
		.replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\n+/g, '\n');
	return v.replace(/\n/g, '\\n');
}

function pemUnescape(value) {
	return String(value == null ? '' : value).replace(/\\n/g, '\n');
}

/* "CR/LF stripped + trim" fields */
function oneLine(value) {
	return trim(String(value == null ? '' : value).replace(/[\r\n]/g, ''));
}

function dedupe(list) {
	var seen = {}, out = [];
	L.toArray(list).forEach(function(v) {
		if (!seen.hasOwnProperty(v)) {
			seen[v] = true;
			out.push(v);
		}
	});
	return out;
}

/* api.compare_versions: split on . and -, numeric parts, "rN" -> N, others 0 */
function compareVersions(a, op, b) {
	function parts(v) {
		return String(v == null ? '' : v).split(/[.-]/).map(function(p) {
			var m;
			if (/^\d+$/.test(p))
				return +p;
			if ((m = /^r(\d+)$/.exec(p)) != null)
				return +m[1];
			return 0;
		});
	}
	if (a == null || a === '' || b == null || b === '')
		return false;
	var x = parts(a), y = parts(b), n = Math.max(x.length, y.length), c = 0;
	for (var i = 0; i < n; i++) {
		var xi = x[i] || 0, yi = y[i] || 0;
		if (xi != yi) {
			c = (xi < yi) ? -1 : 1;
			break;
		}
	}
	switch (op) {
	case '>=': return c >= 0;
	case '>': return c > 0;
	case '<=': return c <= 0;
	case '<': return c < 0;
	case '==': return c == 0;
	}
	return false;
}

/* api.parse_realm_uri: realm[+http]://token@server/realm_id?query */
function parseRealmUri(uri) {
	uri = trim(uri);
	if (uri === '')
		return null;
	var scheme = /^realm\+http:\/\//.test(uri) ? 'realm+http' : (/^realm:\/\//.test(uri) ? 'realm' : null);
	if (!scheme)
		return null;
	uri = uri.replace(/^realm\+http:\/\//, '').replace(/^realm:\/\//, '');
	var m = /^([^@]+)@([^\/]+)\/([^?]*)\??(.*)$/.exec(uri);
	if (!m)
		return null;
	var token = m[1], server_url = m[2], realm_id = m[3].replace(/\/+$/, ''), query = m[4];
	var address = null, port = null, am;
	if ((am = /^\[([^\]]+)\]:(\d+)$/.exec(server_url)) != null) {
		address = am[1]; port = am[2];
	}
	else if ((am = /^([^:]+):(\d+)$/.exec(server_url)) != null) {
		address = am[1]; port = am[2];
	}
	if (address == null)
		address = ((am = /^\[([^\]]+)\]$/.exec(server_url)) != null) ? am[1] : server_url;
	port = (port != null) ? +port : (scheme == 'realm+http' ? 80 : 443);
	var stun = null, re = /[Ss][Tt][Uu][Nn]=([^&]+)/g, sm;
	while ((sm = re.exec(query || '')) != null) {
		stun = stun || [];
		stun.push(sm[1]);
	}
	return {
		scheme: scheme, token: token, server_url: server_url, address: address,
		port: port, realm_id: realm_id, stun_servers: stun
	};
}

/* datatypes.ipaddr / ip6addr / hostname (luci.cbi.datatypes) */
function isIPv4(s) {
	var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
	return !!m && +m[1] <= 255 && +m[2] <= 255 && +m[3] <= 255 && +m[4] <= 255;
}

function isIPv6(s) {
	if (!/^[0-9a-fA-F:.]+$/.test(s) || s.indexOf(':') < 0)
		return false;
	try {
		new URL('http://[' + s + ']/');
		return true;
	}
	catch (e) {
		return false;
	}
}

function innerIP(val) {
	var v = trim(val).toLowerCase();
	var m = /\[(.*?)\]/.exec(v);
	return m ? m[1] : v;
}

function isIP(val) {
	var s = innerIP(val);
	return isIPv4(s) || isIPv6(s);
}

function isHostname(val) {
	return !!val && val.length < 254 &&
		(/^[a-zA-Z_]+$/.test(val) || (/^[a-zA-Z0-9_][a-zA-Z0-9_\-.]*[a-zA-Z0-9]$/.test(val) && /[^0-9.]/.test(val)));
}

/* api.get_valid_nodes() restricted to what the server pages need (normal nodes). */
var NODE_PROTO_NAMES = {
	vmess: 'VMess', vless: 'VLESS', shadowsocks: 'SS', shadowsocksr: 'SSR', wireguard: 'WG',
	hysteria: 'HY', hysteria2: 'HY2', anytls: 'AnyTLS', ssh: 'SSH'
};

function getValidNormalNodes() {
	var show = uci.get('passwall2', '@global_other[0]', 'show_node_info') || '0';
	var def = [], other = [];
	uci.sections('passwall2', 'nodes').forEach(function(e) {
		if (!e.type || !e.remarks)
			return;
		var proto = e.protocol;
		if (proto == '_balancing' || proto == '_shunt' || proto == '_iface' || proto == '_urltest')
			return;
		var typeName = (e.type == 'sing-box') ? 'Sing-Box' : e.type;
		var port = e.port || e.hysteria_hop || e.hysteria2_hop;
		var isRealm = (proto == 'hysteria2' && e.hysteria2_realms) ? true : false;
		if (!((port && e.address) || isRealm))
			return;
		var address = e.address;
		if (!(isIP(address) || isHostname(address) || isRealm))
			return;
		if ((e.type == 'sing-box' || e.type == 'Xray') && proto) {
			var p = NODE_PROTO_NAMES.hasOwnProperty(proto) ? NODE_PROTO_NAMES[proto]
				: proto.replace(/^[a-z]/, function(c) { return c.toUpperCase(); });
			typeName = typeName + ' ' + p;
		}
		if (address && isIPv6(innerIP(address)) && !/\[.*\]/.test(address))
			address = '[' + address + ']';
		if (isRealm)
			typeName = typeName + ' Realm';
		var remark = trim('%s：[%s]'.format(typeName, e.remarks));
		if (show == '1' && !isRealm)
			remark = trim('%s：[%s] %s:%s'.format(typeName, e.remarks, address, String(port || '').replace(/:/g, '-')));
		var n = { id: e['.name'], remark: remark, type: e.type, group: e.group || '' };
		if (!e.group)
			def.push(n);
		else
			other.push(n);
	});
	return def.concat(other);
}

/* api.get_network_devices() -> [{name, label}] */
function getNetworkDevices() {
	return Promise.all([
		L.resolveDefault(network.getDevices(), []),
		L.resolveDefault(uci.load('network'), null)
	]).then(function(res) {
		var devs = res[0] || [];
		var ifaceToDev = {}, devToIfaces = {}, ifaceProto = {}, ifaces = [];
		uci.sections('network', 'interface').forEach(function(s) {
			var n = s['.name'];
			if (n == 'loopback')
				return;
			ifaces.push(n);
			ifaceProto[n] = s.proto || '';
			if (s.device) {
				ifaceToDev[n] = s.device;
				(devToIfaces[s.device] = devToIfaces[s.device] || []).push(n);
			}
		});
		var seen = {}, list = [];
		devs.forEach(function(d) {
			var name = d.getName();
			if (!name || name == 'lo' || /^(veth|ifb|gre|sit|ip6tnl|erspan)/.test(name))
				return;
			var dtype = d.getType();
			if (dtype == 'alias' || (typeof(d.isBridgePort) == 'function' && d.isBridgePort()))
				return;
			var type;
			if (dtype == 'bridge')
				type = _('Bridge');
			else if (dtype == 'wifi')
				type = _('Wireless Adapter');
			else if (dtype == 'tunnel' || /^(tun|tap|wg|ppp)/.test(name))
				type = _('Tunnel Interface');
			else
				type = _('Ethernet Adapter');
			seen[name] = true;
			var label = '%s: "%s"'.format(type, name);
			if (devToIfaces[name])
				label += ' (' + devToIfaces[name].join(', ') + ')';
			list.push({ name: name, label: label, sort: type + ':' + name });
		});
		ifaces.forEach(function(n) {
			var dev = ifaceToDev[n];
			if (dev && seen[dev])
				return;
			var type;
			if (dev && /^br-/.test(dev))
				type = _('Bridge');
			else if ([ 'wireguard', 'pppoe', 'pptp', 'l2tp' ].indexOf(ifaceProto[n]) >= 0)
				type = _('Tunnel Interface');
			else
				type = _('Interface');
			list.push({ name: n, label: '%s: "%s"'.format(type, n), sort: 'zzz:' + n });
		});
		list.sort(function(a, b) { return a.sort < b.sort ? -1 : (a.sort > b.sort ? 1 : 0); });
		return list;
	});
}

/* api.finded_com / api.is_finded via directory listings (luci-base grants file list) */
function listDir(dir, cache) {
	if (!cache.hasOwnProperty(dir))
		cache[dir] = L.resolveDefault(fs.list(dir), null);
	return cache[dir];
}

function fileInDir(path, cache) {
	var i = path.lastIndexOf('/');
	if (i < 0)
		return Promise.resolve(null);
	var dir = path.substring(0, i) || '/', base = path.substring(i + 1);
	return listDir(dir, cache).then(function(entries) {
		if (entries == null)
			return null;	/* unknown */
		for (var j = 0; j < entries.length; j++)
			if (entries[j].name == base && entries[j].type != 'directory')
				return true;
		return false;
	});
}

function isFinded(bin, cache) {
	var dirs = [ '/bin', '/usr/bin', '/usr/sbin', '/sbin' ];
	return Promise.all(dirs.map(function(d) { return fileInDir(d + '/' + bin, cache); })).then(function(r) {
		return r.indexOf(true) >= 0;
	});
}

function rpcVersion(com) {
	return Promise.resolve().then(function() {
		return pw.call('com_version', { com: com });
	}).then(function(r) {
		return (r && r.code == 1 && r.data) ? String(r.data) : '';
	}).catch(function() { return ''; });
}

/* ------------------------------------------------------- dependency engine */

function depValue(section, section_id, key) {
	var opt = null;
	for (var i = 0; i < section.children.length; i++)
		if (section.children[i].option == key)
			opt = section.children[i];
	if (!opt || !opt.isActive(section_id))
		return '';
	var v = opt.formvalue(section_id);
	if (opt.enabled !== undefined && opt.disabled !== undefined)	/* Flag: unchecked checkbox posts nothing */
		return (v == opt.enabled) ? '1' : '';
	if (Array.isArray(v))
		v = v.join(' ');
	return (v == null) ? '' : String(v);
}

function pwCheckDepends(section_id) {
	var list = this.pwDeps;
	if (!list || !list.length)
		return true;
	for (var i = 0; i < list.length; i++) {
		var ok = true;
		for (var k in list[i]) {
			if (!list[i].hasOwnProperty(k))
				continue;
			/* loose compare on purpose: "1" == true, "" == false (legacy cbi.js) */
			if (!(depValue(this.section, section_id, k) == list[i][k])) {
				ok = false;
				break;
			}
		}
		if (ok)
			return true;
	}
	return false;
}

function deps(o /*, entry, entry, ... */) {
	o.pwDeps = (o.pwDeps || []).concat(Array.prototype.slice.call(arguments, 1));
	o.checkDepends = pwCheckDepends;
	return o;
}

/* Sibling posted value as upstream `s.fields[x]:formvalue(t)`: nil when hidden/unchecked. */
function postedValue(section, section_id, key) {
	var v = depValue(section, section_id, key);
	return v === '' ? null : v;
}

/* --------------------------------------------------------- option helpers */

function flag(s, name, title, def, desc) {
	var o = s.option(form.Flag, name, title, desc);
	if (def != null)
		o.default = String(def);
	return o;
}

function value(s, name, title, desc) {
	return s.option(form.Value, name, title, desc);
}

function list(s, name, title, desc) {
	return s.option(form.ListValue, name, title, desc);
}

function dynlist(s, name, title, desc) {
	var o = s.option(form.DynamicList, name, title, desc);
	o.write = function(section_id, v) {
		var d = dedupe(v);
		return this.map.data.set(CONF, section_id, this.option, d.length ? d : null);
	};
	return o;
}

function choices(o, vals) {
	vals.forEach(function(v) {
		if (Array.isArray(v))
			o.value(v[0], v[1]);
		else
			o.value(v);
	});
	return o;
}

function jsonText(s, name, title, uciopt, message) {
	var o = s.option(form.TextValue, name, title);
	o.rows = 10;
	o.wrap = 'off';
	o.monospace = true;
	o.cfgvalue = function(section_id) {
		var raw = uci.get(CONF, section_id, uciopt);
		return raw ? b64decode(raw) : null;
	};
	o.validate = function(section_id, v) {
		if (v == null || v === '')
			return true;
		return isJSON(v) ? true : message;
	};
	o.write = function(section_id, v) {
		return this.map.data.set(CONF, section_id, uciopt, b64encode(v) || '');
	};
	return o;
}

function pemText(s, name, title, desc) {
	var o = s.option(form.TextValue, name, title, desc);
	o.default = '';
	o.rows = 5;
	o.wrap = 'off';
	o.monospace = true;
	o.cfgvalue = function(section_id) {
		return pemUnescape(uci.get(CONF, section_id, name) || '');
	};
	o.write = function(section_id, v) {
		var e = pemEscape(v);
		return this.map.data.set(CONF, section_id, name, e !== '' ? e : null);
	};
	return o;
}

function lineText(s, name, title, desc) {
	var o = s.option(form.TextValue, name, title, desc);
	o.default = '';
	o.rows = 5;
	o.wrap = 'soft';
	o.monospace = true;
	o.write = function(section_id, v) {
		var e = oneLine(v);
		return this.map.data.set(CONF, section_id, name, e !== '' ? e : null);
	};
	return o;
}

function base64Validate(section_id, v) {
	if (v == null || v === '')
		return true;
	return isBase64(v) ? true : _('Must be Base64 text!');
}

function realmUrlOption(s) {
	var o = value(s, 'hysteria2_realm_url', _('Realm URL'), _('Example:') + 'realm://public@realm.hy2.io/your-realm-name');
	o.validate = function(section_id, v) {
		if (v == null || v === '')
			return true;
		return parseRealmUri(trim(v)) ? true : _('Invalid Realm URL.');
	};
	o.write = function(section_id, v) {
		return this.map.data.set(CONF, section_id, this.option, trim(v));
	};
	return deps(o, { hysteria2_realms: '1' });
}

/* Common tls validate of server Xray / sing-box (spec 09 §3.3). */
function tlsValidate(section_id, v) {
	var sec = this.section;
	if (v == null || v === '')
		return true;
	var reality = postedValue(sec, section_id, 'reality');
	var usePem = postedValue(sec, section_id, 'tls_use_pem');
	if (reality == '1')
		return true;
	if (v == '1' && usePem != '1') {
		var ca = postedValue(sec, section_id, 'tls_certificateFile') || '';
		var key = postedValue(sec, section_id, 'tls_keyFile') || '';
		if (ca == '' || key == '')
			return _('Certificate and Private key path can not be empty!');
	}
	else if (v == '1' && usePem == '1') {
		var ca2 = postedValue(sec, section_id, 'tls_certificate') || '';
		var key2 = postedValue(sec, section_id, 'tls_key') || '';
		if (ca2 == '' || key2 == '')
			return _('Certificate and Private key PEM can not be empty!');
	}
	return true;
}

function certPathOption(s, sid, name, title, desc, ext) {
	var o = value(s, name, title, desc);
	o.default = uci.get(CONF, sid, name) || ('/etc/config/ssl/' + sid + ext);
	o.pwCheckFile = true;
	return o;
}

function customConfigOptions(s) {
	flag(s, 'custom', _('Use Custom Config'));
	var o = jsonText(s, 'custom_config', _('Custom Config') + ' (JSON)', 'config_str',
		_('Custom Config') + ' ' + _('Must be JSON text!'));
	/* upstream: remove() targets the non-existent `custom_config` option -> config_str is kept */
	o.remove = function() {};
	deps(o, { custom: true });
}

function firewallOptions(s) {
	var o = flag(s, 'firewall_allow', _('Firewall Allow'), '0');
	deps(o, { custom: false });

	o = s.option(widgets.ZoneSelect, 'firewall_allow_src', _('Source zone'));
	o.rmempty = false;	/* rmempty = not is_js_luci */
	o.nocreate = true;
	o.allowany = true;
	o.default = 'wan';
	deps(o, { custom: false, firewall_allow: true });
}

function genWireguardKeyOption(s) {
	var o = s.option(form.Button, '_gen_wireguard_key', _('Generate key'));
	o.inputtitle = _('Generate key');
	o.inputstyle = 'apply';
	o.onclick = function(ev, section_id) {
		var map = this.map;
		return Promise.resolve().then(function() {
			return pw.call('gen_wireguard_key', {});
		}).then(function(res) {
			if (res && res.code == 1 && res.data) {
				[ [ 'wireguard_private_key', res.data.private_key ], [ 'wireguard_public_key', res.data.public_key ] ].forEach(function(p) {
					var l = map.lookupOption(p[0], section_id);
					var el = l ? l[0].getUIElement(section_id) : null;
					if (el) {
						el.setValue(p[1] || '');
						l[0].triggerValidation(section_id);
					}
				});
			}
			else {
				alert(_('Error'));
			}
		}).catch(function() {
			alert(_('Error'));
		});
	};
	o.write = function() {};
	o.remove = function() {};
	return deps(o, { protocol: 'wireguard' });
}

function outboundOptions(s, ctx, typeName) {
	var lead = [ [ '', _('Close') ], [ '_socks', _('Custom Socks') ], [ '_http', _('Custom HTTP') ], [ '_iface', _('Custom Interface') ] ];
	var o;
	if (typeof(pw.addNodeOption) == 'function') {
		/* grouped node picker (upstream nodes_listvalue template) */
		o = pw.addNodeOption(s, 'outbound_node', _('outbound node'), {
			values: lead,
			types: [ 'normal' ],
			filter: function(n) { return n.type == typeName; }
		});
	}
	else {
		o = list(s, 'outbound_node', _('outbound node'));
		lead.forEach(function(v) { o.value(v[0], v[1]); });
		ctx.nodes.forEach(function(n) {
			if (n.type == typeName)
				o.value(n.id, n.group ? n.remark + ' [' + n.group + ']' : n.remark);
		});
	}
	o.default = '';
	deps(o, { custom: false });

	var sockHttp = [ { outbound_node: '_socks' }, { outbound_node: '_http' } ];

	o = value(s, 'outbound_node_address', _('Address (Support Domain Name)'));
	deps.apply(null, [ o ].concat(sockHttp));

	o = value(s, 'outbound_node_port', _('Port'));
	o.datatype = 'port';
	deps.apply(null, [ o ].concat(sockHttp));

	o = value(s, 'outbound_node_username', _('Username'));
	deps.apply(null, [ o ].concat(sockHttp));

	o = value(s, 'outbound_node_password', _('Password'));
	o.password = true;
	deps.apply(null, [ o ].concat(sockHttp));

	o = value(s, 'outbound_node_iface', _('Interface'));
	ctx.netdevs.forEach(function(d) { o.value(d.name, d.label); });
	deps(o, { outbound_node: '_iface' });
}

function usersMulti(s, ctx) {
	var o = s.option(form.MultiValue, 'users', _('User'));
	o.cast = 'table';
	ctx.users.forEach(function(u) { o.value(u['.name'], u.username || u['.name']); });
	o.write = function(section_id, v) {
		var d = dedupe(v);
		return this.map.data.set(CONF, section_id, 'users', d.length ? d : null);
	};
	return o;
}

function userSelect(s, ctx) {
	var o = list(s, 'user', _('User'));
	ctx.users.forEach(function(u) { o.value(u['.name'], u.username || u['.name']); });
	return deps(o, { custom: false });
}

var ALPN_LIST = [ 'h3', 'h2', 'h3,h2', 'http/1.1', 'h2,http/1.1', 'h3,h2,http/1.1' ];

/* ------------------------------------------------------------ type: SSR */

var SSR_METHODS = [ 'none', 'table', 'rc2-cfb', 'rc4', 'rc4-md5', 'rc4-md5-6', 'aes-128-cfb',
	'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
	'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
	'cast5-cfb', 'des-cfb', 'idea-cfb', 'seed-cfb', 'salsa20', 'chacha20', 'chacha20-ietf' ];
var SSR_PROTOCOLS = [ 'origin', 'verify_simple', 'verify_deflate', 'verify_sha1', 'auth_simple',
	'auth_sha1', 'auth_sha1_v2', 'auth_sha1_v4', 'auth_aes128_md5', 'auth_aes128_sha1',
	'auth_chain_a', 'auth_chain_b', 'auth_chain_c', 'auth_chain_d', 'auth_chain_e', 'auth_chain_f' ];
var SSR_OBFS = [ 'plain', 'http_simple', 'http_post', 'random_head', 'tls_simple',
	'tls1.0_session_auth', 'tls1.2_ticket_auth' ];

function buildSSR(s, ctx) {
	var o;
	customConfigOptions(s);

	o = value(s, 'port', _('Listen Port'));
	o.datatype = 'port';
	deps(o, { custom: false });

	userSelect(s, ctx);

	o = choices(list(s, 'method', _('Encrypt Method')), SSR_METHODS);
	deps(o, { custom: false });

	o = choices(list(s, 'protocol', _('Protocol')), SSR_PROTOCOLS);
	deps(o, { custom: false });

	deps(value(s, 'protocol_param', _('Protocol_param')), { custom: false });

	o = choices(list(s, 'obfs', _('Obfs')), SSR_OBFS);
	deps(o, { custom: false });

	deps(value(s, 'obfs_param', _('Obfs_param')), { custom: false });

	o = value(s, 'timeout', _('Connection Timeout'));
	o.datatype = 'uinteger';
	o.default = '300';
	deps(o, { custom: false });

	deps(flag(s, 'tcp_fast_open', 'TCP ' + _('Fast Open'), '0'), { custom: false });

	o = flag(s, 'udp_forward', _('UDP Forward'), '1');
	o.rmempty = false;

	firewallOptions(s);

	o = flag(s, 'log', _('Log'), '1');
	o.rmempty = false;
}

/* --------------------------------------------------------- type: SS-Rust */

var SSRUST_SERVER_METHODS = [ 'plain', 'none', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha8-poly1305', '2022-blake3-chacha20-poly1305' ];

function buildSSRust(s, ctx) {
	var o;
	customConfigOptions(s);

	o = value(s, 'port', _('Listen Port'));
	o.datatype = 'port';
	deps(o, { custom: false });

	userSelect(s, ctx);

	o = choices(list(s, 'method', _('Encrypt Method')), SSRUST_SERVER_METHODS);
	deps(o, { custom: false });

	o = value(s, 'timeout', _('Connection Timeout'));
	o.datatype = 'uinteger';
	o.default = '300';
	deps(o, { custom: false });

	deps(flag(s, 'tcp_fast_open', 'TCP ' + _('Fast Open'), '0'), { custom: false });

	firewallOptions(s);

	o = flag(s, 'log', _('Log'), '1');
	o.rmempty = false;
}

/* ------------------------------------------------------------ type: Xray */

var XRAY_SS_METHODS = [ 'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'xchacha20-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305' ];
var MKCP_HEADERS = [ 'none', 'srtp', 'utp', 'wechat-video', 'dtls', 'wireguard', 'dns' ];
var HY2_STUN_DEFAULT = [ 'stun.sip.us:3478', 'stun.nextcloud.com:3478', 'global.stun.twilio.com:3478' ];

function hysteria2Options(s, sbDesc) {
	var o;
	o = flag(s, 'hysteria2_realms', _('Realms'), '0');
	deps(o, { protocol: 'hysteria2' });

	realmUrlOption(s);

	o = dynlist(s, 'hysteria2_realm_stun', _('Realm STUN'));
	o.default = HY2_STUN_DEFAULT.slice();
	deps(o, { hysteria2_realms: '1' });

	o = flag(s, 'hysteria2_realm_upnp', _('Enable') + ' UPnP/NAT-PMP', '0',
		_('Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success.'));
	deps(o, { hysteria2_realms: '1' });

	o = list(s, 'hysteria2_obfs_type', _('Obfs Type'));
	o.value('', _('Disable'));
	o.value('salamander');
	o.value('gecko');
	deps(o, { protocol: 'hysteria2' });

	o = value(s, 'hysteria2_obfs_password', _('Obfs Password'));
	deps(o, { hysteria2_obfs_type: 'salamander' }, { hysteria2_obfs_type: 'gecko' });

	o = value(s, 'hysteria2_obfs_MinPacketSize', _('Gecko Packet Size (min)'));
	o.datatype = 'uinteger';
	o.placeholder = '512';
	o.default = '512';
	deps(o, { hysteria2_obfs_type: 'gecko' });

	o = value(s, 'hysteria2_obfs_MaxPacketSize', _('Gecko Packet Size (max)'));
	o.datatype = 'uinteger';
	o.placeholder = '1200';
	o.default = '1200';
	deps(o, { hysteria2_obfs_type: 'gecko' });

	o = flag(s, 'hysteria2_ignore_client_bandwidth', _('Client BBR Flow Control'), '0',
		sbDesc ? _('Commands the client to use the BBR flow control algorithm') : null);
	deps(o, { protocol: 'hysteria2' });

	o = value(s, 'hysteria2_up_mbps', _('Max upload Mbps'));
	deps(o, { protocol: 'hysteria2', hysteria2_ignore_client_bandwidth: false });

	o = value(s, 'hysteria2_down_mbps', _('Max download Mbps'));
	deps(o, { protocol: 'hysteria2', hysteria2_ignore_client_bandwidth: false });
}

function masqueOptions(s) {
	var o;
	deps(value(s, 'masque_path', _('MASQUE Path')), { protocol: 'masque' });

	o = dynlist(s, 'masque_address', _('MASQUE Address'));
	o.rmempty = false;
	deps(o, { protocol: 'masque' });

	o = value(s, 'masque_mtu', 'MTU');
	o.datatype = 'uinteger';
	o.default = '1280';
	deps(o, { protocol: 'masque' });
}

function buildXray(s, ctx) {
	var sid = ctx.sid, o;

	customConfigOptions(s);

	o = choices(list(s, 'protocol', _('Protocol')), [
		[ 'vmess', 'Vmess' ], [ 'vless', 'VLESS' ], [ 'http', 'HTTP' ], [ 'socks', 'Socks' ],
		[ 'shadowsocks', 'Shadowsocks' ], [ 'trojan', 'Trojan' ], [ 'hysteria2', 'Hysteria2' ],
		[ 'wireguard', 'WireGuard' ], [ 'masque', 'MASQUE' ], [ 'tunnel', 'Tunnel' ]
	]);
	deps(o, { custom: false });

	o = value(s, 'port', _('Listen Port'));
	o.datatype = 'port';
	deps(o, { custom: false });

	o = usersMulti(s, ctx);
	deps.apply(null, [ o ].concat([ 'http', 'socks', 'shadowsocks', 'vmess', 'vless', 'trojan', 'hysteria2', 'wireguard', 'masque' ]
		.map(function(p) { return { protocol: p }; })));

	o = choices(list(s, 'd_protocol', _('Destination protocol')), [ [ 'tcp', 'TCP' ], [ 'udp', 'UDP' ], [ 'tcp,udp', 'TCP,UDP' ] ]);
	deps(o, { protocol: 'tunnel' });

	deps(value(s, 'd_address', _('Destination address')), { protocol: 'tunnel' });

	o = value(s, 'd_port', _('Destination port'));
	o.datatype = 'port';
	deps(o, { protocol: 'tunnel' });

	o = value(s, 'decryption', _('Encrypt Method') + ' (decryption)');
	o.default = 'none';
	o.placeholder = 'none';
	o.write = function(section_id, v) {
		v = trim(v);
		return this.map.data.set(CONF, section_id, 'decryption', v === '' ? 'none' : v);
	};
	deps(o, { protocol: 'vless' });

	o = choices(list(s, 'ss_method', _('Encrypt Method')), XRAY_SS_METHODS);
	deps(o, { protocol: 'shadowsocks' });

	deps(value(s, 'ss_password', _('Password')), { protocol: 'shadowsocks' });

	o = choices(list(s, 'ss_network', _('Transport')), [ [ 'tcp', 'TCP' ], [ 'udp', 'UDP' ], [ 'tcp,udp', 'TCP,UDP' ] ]);
	o.default = 'tcp,udp';
	deps(o, { protocol: 'shadowsocks' });

	o = flag(s, 'udp_forward', _('UDP Forward'), '1');
	o.rmempty = false;
	deps(o, { protocol: 'socks' });

	o = list(s, 'flow', _('flow'));
	o.default = '';
	o.value('', _('Disable'));
	o.value('xtls-rprx-vision');
	deps(o, { protocol: 'vless' });

	/* hysteria2 */
	hysteria2Options(s, false);

	/* MASQUE */
	masqueOptions(s);

	/* TLS */
	o = flag(s, 'tls', 'TLS', '0');
	o.validate = tlsValidate;
	o.pwIsTls = true;
	deps.apply(null, [ o ].concat([ 'vmess', 'vless', 'http', 'socks', 'shadowsocks', 'trojan' ]
		.map(function(p) { return { protocol: p }; })));

	/* REALITY */
	o = flag(s, 'reality', _('REALITY'), '0');
	deps.apply(null, [ o ].concat([ 'raw', 'ws', 'grpc', 'httpupgrade', 'xhttp' ]
		.map(function(t) { return { tls: true, transport: t }; })));

	deps(value(s, 'reality_private_key', _('Private Key')), { reality: true });
	deps(dynlist(s, 'reality_shortId', _('Short Id')), { reality: true });

	o = value(s, 'reality_dest', _('Dest'));
	o.default = 'google.com:443';
	deps(o, { reality: true });

	deps(dynlist(s, 'reality_serverNames', _('serverNames')), { reality: true });

	o = list(s, 'alpn', _('alpn'));
	o.default = 'default';
	o.value('default', _('Default'));
	choices(o, ALPN_LIST);
	deps(o, { tls: true, reality: false });

	o = flag(s, 'use_mldsa65Seed', _('ML-DSA-65'), '0');
	deps(o, { reality: true });

	o = lineText(s, 'reality_mldsa65Seed', 'ML-DSA-65 ' + _('Private Key'));
	deps(o, { use_mldsa65Seed: true });

	o = flag(s, 'tls_use_pem', _('Use PEM'), null, _('Use certificate and private key PEM content.'));
	deps(o, { tls: true, reality: false }, { protocol: 'hysteria2' }, { protocol: 'masque' });

	var certDeps = [ { tls: true, reality: false, tls_use_pem: false },
		{ protocol: 'hysteria2', tls_use_pem: false }, { protocol: 'masque', tls_use_pem: false } ];

	o = certPathOption(s, sid, 'tls_certificateFile', _('Path to the certificate file'), _('as:') + '/etc/ssl/fullchain.crt', '.crt');
	deps.apply(null, [ o ].concat(certDeps));

	o = certPathOption(s, sid, 'tls_keyFile', _('Path to the private key file'), _('as:') + '/etc/ssl/private.key', '.key');
	deps.apply(null, [ o ].concat(certDeps));

	o = pemText(s, 'tls_certificate', _('TLS Certificate (PEM)'), _('Full certificate (chain), PEM format.'));
	deps(o, { tls_use_pem: true });

	o = pemText(s, 'tls_key', _('TLS Private Key (PEM)'), _('Private key in PEM format.'));
	deps(o, { tls_use_pem: true });

	o = flag(s, 'ech', _('ECH'), '0');
	deps(o, { tls: true, reality: false }, { protocol: 'masque' });

	o = lineText(s, 'ech_key', _('ECH Key'));
	deps(o, { ech: true });

	o = choices(list(s, 'transport', _('Transport')), [
		[ 'raw', 'RAW' ], [ 'mkcp', 'mKCP' ], [ 'ws', 'WebSocket' ], [ 'grpc', 'gRPC' ],
		[ 'httpupgrade', 'HttpUpgrade' ], [ 'xhttp', 'XHTTP' ]
	]);
	deps.apply(null, [ o ].concat([ 'vmess', 'vless', 'socks', 'shadowsocks', 'trojan' ]
		.map(function(p) { return { protocol: p }; })));

	/* WebSocket */
	deps(value(s, 'ws_host', _('WebSocket Host')), { transport: 'ws' });
	deps(value(s, 'ws_path', _('WebSocket Path')), { transport: 'ws' });

	/* HttpUpgrade */
	deps(value(s, 'httpupgrade_host', _('HttpUpgrade Host')), { transport: 'httpupgrade' });
	o = value(s, 'httpupgrade_path', _('HttpUpgrade Path'));
	o.placeholder = '/';
	deps(o, { transport: 'httpupgrade' });

	/* XHTTP */
	deps(value(s, 'xhttp_host', _('XHTTP Host')), { transport: 'xhttp' });
	o = value(s, 'xhttp_path', _('XHTTP Path'));
	o.placeholder = '/';
	deps(o, { transport: 'xhttp' });

	o = value(s, 'xhttp_maxuploadsize', _('maxUploadSize'));
	o.default = '1000000';
	deps(o, { transport: 'xhttp' });

	o = value(s, 'xhttp_maxconcurrentuploads', _('maxConcurrentUploads'));
	o.default = '10';
	deps(o, { transport: 'xhttp' });

	/* upstream dead fields: transport "splithttp" is not a choice -> never visible */
	o = value(s, 'splithttp_maxuploadsize', _('maxUploadSize'));
	o.default = '1000000';
	deps(o, { transport: 'splithttp' });

	o = value(s, 'splithttp_maxconcurrentuploads', _('maxConcurrentUploads'));
	o.default = '10';
	deps(o, { transport: 'splithttp' });

	/* TCP */
	o = choices(list(s, 'tcp_guise', _('Camouflage Type')), [ [ 'none', 'none' ], [ 'http', 'http' ] ]);
	deps(o, { transport: 'raw' });

	deps(dynlist(s, 'tcp_guise_http_host', _('HTTP Host')), { tcp_guise: 'http' });
	deps(dynlist(s, 'tcp_guise_http_path', _('HTTP Path')), { tcp_guise: 'http' });

	/* mKCP */
	o = choices(list(s, 'mkcp_guise', _('Camouflage Type'), _('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)<br />dns: Disguising traffic as DNS requests.')), MKCP_HEADERS);
	deps(o, { transport: 'mkcp' });

	o = value(s, 'mkcp_domain', _('Camouflage Domain'), _('Use it together with the DNS disguised type. You can fill in any domain.'));
	deps(o, { mkcp_guise: 'dns' });

	o = value(s, 'mkcp_mtu', _('KCP MTU'));
	o.datatype = 'uinteger';
	o.default = '1350';
	deps(o, { transport: 'mkcp' });

	deps(value(s, 'mkcp_seed', _('KCP Seed')), { transport: 'mkcp' });

	/* gRPC */
	deps(value(s, 'grpc_serviceName', 'ServiceName'), { transport: 'grpc' });

	/* FinalMask */
	o = flag(s, 'use_finalmask', 'FinalMask', '0');
	deps(o, { custom: false, protocol: 'vmess' }, { custom: false, protocol: 'vless' },
		{ custom: false, protocol: 'trojan' }, { custom: false, protocol: 'shadowsocks' },
		{ custom: false, protocol: 'hysteria2', hysteria2_realms: false });

	o = jsonText(s, 'finalmask', 'FinalMask JSON', 'finalmask', _('Must be JSON text!'));
	deps(o, { use_finalmask: true });

	/* acceptProxyProtocol */
	o = flag(s, 'acceptProxyProtocol', _('acceptProxyProtocol'), '0',
		_('Whether to receive PROXY protocol, when this node want to be fallback or forwarded by proxy, it must be enable, otherwise it cannot be used.'));
	deps(o, { transport: 'raw' }, { transport: 'ws' });

	/* Fast Open */
	o = flag(s, 'tcp_fast_open', 'TCP ' + _('Fast Open'), '0');
	deps(o, { protocol: 'vmess', custom: false }, { protocol: 'vless', custom: false },
		{ protocol: 'shadowsocks', custom: false }, { protocol: 'trojan', custom: false });

	/* Fallback */
	o = flag(s, 'fallback', _('Fallback'));
	deps(o, { protocol: 'vless', transport: 'raw' }, { protocol: 'trojan', transport: 'raw' });

	o = dynlist(s, 'fallback_list', 'Fallback', _('format: dest,path,xver'));
	deps(o, { fallback: true });

	/* WireGuard */
	o = value(s, 'wireguard_mtu', 'MTU');
	o.default = '1420';
	deps(o, { protocol: 'wireguard' });

	o = value(s, 'wireguard_private_key', _('Private Key'));
	o.validate = base64Validate;
	deps(o, { protocol: 'wireguard' });

	o = value(s, 'wireguard_public_key', _('Public Key'));
	o.validate = base64Validate;
	deps(o, { protocol: 'wireguard' });

	genWireguardKeyOption(s);

	firewallOptions(s);

	o = flag(s, 'accept_lan', _('Accept LAN Access'), '0', _('When selected, it can accessed lan , this will not be safe!'));
	deps(o, { custom: false });

	outboundOptions(s, ctx, 'Xray');

	o = flag(s, 'log', _('Log'), '1');
	o.rmempty = false;

	o = choices(list(s, 'loglevel', _('Log Level')), [ 'debug', 'info', 'warning', 'error' ]);
	o.default = 'warning';
	deps(o, { log: true });
}

/* -------------------------------------------------------- type: sing-box */

var SB_SS_METHODS = [ 'none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305' ];

function buildSingbox(s, ctx) {
	var sid = ctx.sid, o;
	var tags = ctx.singboxTags || '';
	var hasQuic = tags.indexOf('with_quic') >= 0;
	var hasUtls = tags.indexOf('with_utls') >= 0;
	var hasWG = tags.indexOf('with_wireguard') >= 0;
	var localVersion = (/[^v]+/.exec(ctx.singboxVersion || '') || [ '' ])[0];
	var ge114 = compareVersions(localVersion, '>=', '1.14.0');
	var ge115 = compareVersions(localVersion, '>=', '1.15.0');

	customConfigOptions(s);

	var proto = choices(list(s, 'protocol', _('Protocol')), [
		[ 'direct', 'Direct' ], [ 'mixed', 'Mixed' ], [ 'socks', 'Socks' ], [ 'http', 'HTTP' ],
		[ 'shadowsocks', 'Shadowsocks' ], [ 'vmess', 'Vmess' ], [ 'vless', 'VLESS' ], [ 'trojan', 'Trojan' ],
		[ 'naive', 'Naive' ], [ 'anytls', 'AnyTLS' ]
	]);
	deps(proto, { custom: false });

	o = value(s, 'port', _('Listen Port'));
	o.datatype = 'port';
	deps(o, { custom: false });

	var users = usersMulti(s, ctx);
	deps.apply(null, [ users ].concat([ 'mixed', 'socks', 'http', 'shadowsocks', 'vmess', 'vless', 'trojan', 'naive', 'anytls' ]
		.map(function(p) { return { protocol: p }; })));

	if (hasQuic) {
		/* hysteria */
		proto.value('hysteria', 'Hysteria');
		deps(users, { protocol: 'hysteria' });

		deps(value(s, 'hysteria_obfs', _('Obfs Password')), { protocol: 'hysteria' });

		o = value(s, 'hysteria_up_mbps', _('Max upload Mbps'));
		o.default = '100';
		deps(o, { protocol: 'hysteria' });

		o = value(s, 'hysteria_down_mbps', _('Max download Mbps'));
		o.default = '100';
		deps(o, { protocol: 'hysteria' });

		deps(value(s, 'hysteria_recv_window_conn', _('QUIC stream receive window')), { protocol: 'hysteria' });
		deps(value(s, 'hysteria_recv_window_client', _('QUIC connection receive window')), { protocol: 'hysteria' });

		o = value(s, 'hysteria_max_conn_client', _('QUIC concurrent bidirectional streams'));
		o.default = '1024';
		deps(o, { protocol: 'hysteria' });

		deps(flag(s, 'hysteria_disable_mtu_discovery', _('Disable MTU detection')), { protocol: 'hysteria' });

		/* tuic */
		proto.value('tuic', 'TUIC');
		deps(users, { protocol: 'tuic' });

		o = list(s, 'tuic_congestion_control', _('Congestion control algorithm'));
		o.default = 'cubic';
		o.value('bbr', _('BBR'));
		o.value('cubic', _('CUBIC'));
		o.value('new_reno', _('New Reno'));
		deps(o, { protocol: 'tuic' });

		deps(flag(s, 'tuic_zero_rtt_handshake', _('Enable 0-RTT QUIC handshake'), '0'), { protocol: 'tuic' });

		o = value(s, 'tuic_heartbeat', _('Heartbeat interval(second)'));
		o.datatype = 'uinteger';
		o.default = '3';
		deps(o, { protocol: 'tuic' });

		o = list(s, 'tuic_alpn', _('QUIC TLS ALPN'));
		o.default = 'default';
		o.value('default', _('Default'));
		choices(o, ALPN_LIST.concat([ 'spdy/3.1', 'h3,spdy/3.1' ]));
		deps(o, { protocol: 'tuic' });

		/* hysteria2 */
		proto.value('hysteria2', 'Hysteria2');
		deps(users, { protocol: 'hysteria2' });
		hysteria2Options(s, true);
	}

	o = choices(list(s, 'd_protocol', _('Destination protocol')), [ [ 'tcp', 'TCP' ], [ 'udp', 'UDP' ], [ 'tcp,udp', 'TCP,UDP' ] ]);
	deps(o, { protocol: 'direct' });

	deps(value(s, 'd_address', _('Destination address')), { protocol: 'direct' });

	o = value(s, 'd_port', _('Destination port'));
	o.datatype = 'port';
	deps(o, { protocol: 'direct' });

	o = value(s, 'decryption', _('Encrypt Method'));
	o.default = 'none';
	deps(o, { protocol: 'vless' });

	o = choices(list(s, 'ss_method', _('Encrypt Method')), SB_SS_METHODS);
	deps(o, { protocol: 'shadowsocks' });

	deps(value(s, 'ss_password', _('Password')), { protocol: 'shadowsocks' });

	o = list(s, 'flow', _('flow'));
	o.default = '';
	o.value('', _('Disable'));
	o.value('xtls-rprx-vision');
	deps(o, { protocol: 'vless', tls: true });

	/* MASQUE */
	if (ge115 && hasQuic) {
		proto.value('masque', 'MASQUE');
		deps(users, { protocol: 'masque' });
		masqueOptions(s);
	}

	o = flag(s, 'tls', _('TLS'), '0');
	o.validate = tlsValidate;
	o.pwIsTls = true;
	deps.apply(null, [ o ].concat([ 'http', 'vmess', 'vless', 'trojan', 'anytls' ]
		.map(function(p) { return { protocol: p }; })));

	if (hasUtls) {
		/* REALITY */
		o = flag(s, 'reality', _('REALITY'), '0');
		deps.apply(null, [ o ].concat([ 'http', 'vmess', 'vless', 'trojan', 'anytls' ]
			.map(function(p) { return { protocol: p, tls: true }; })));

		deps(value(s, 'reality_private_key', _('Private Key')), { reality: true });
		deps(value(s, 'reality_shortId', _('Short Id')), { reality: true });

		o = value(s, 'reality_handshake_server', _('Handshake Server'));
		o.default = 'google.com';
		deps(o, { reality: true });

		o = value(s, 'reality_handshake_server_port', _('Handshake Server Port'));
		o.datatype = 'port';
		o.default = '443';
		deps(o, { reality: true });
	}

	o = list(s, 'alpn', _('ALPN'));
	o.default = 'default';
	o.value('default', _('Default'));
	choices(o, ALPN_LIST);
	deps(o, { tls: true, reality: false }, { protocol: 'hysteria' });

	var pemProtos = [ 'naive', 'hysteria', 'tuic', 'hysteria2', 'masque' ];

	o = flag(s, 'tls_use_pem', _('Use PEM'), null, _('Use certificate and private key PEM content.'));
	deps.apply(null, [ o, { tls: true, reality: false } ].concat(pemProtos.map(function(p) { return { protocol: p }; })));

	var certDeps = [ { tls: true, reality: false, tls_use_pem: false } ]
		.concat(pemProtos.map(function(p) { return { protocol: p, tls_use_pem: false }; }));

	o = certPathOption(s, sid, 'tls_certificateFile', _('Path to the certificate file'), _('as:') + '/etc/ssl/fullchain.crt', '.crt');
	deps.apply(null, [ o ].concat(certDeps));

	o = certPathOption(s, sid, 'tls_keyFile', _('Path to the private key file'), _('as:') + '/etc/ssl/private.key', '.key');
	deps.apply(null, [ o ].concat(certDeps));

	o = pemText(s, 'tls_certificate', _('TLS Certificate (PEM)'), _('Full certificate (chain), PEM format.'));
	deps(o, { tls_use_pem: true });

	o = pemText(s, 'tls_key', _('TLS Private Key (PEM)'), _('Private key in PEM format.'));
	deps(o, { tls_use_pem: true });

	o = flag(s, 'ech', _('ECH'), '0');
	deps(o, { tls: true, flow: '', reality: false }, { protocol: 'naive' }, { protocol: 'hysteria' },
		{ protocol: 'tuic' }, { protocol: 'hysteria2', hysteria2_realms: false }, { protocol: 'masque' });

	/* sing-box ech_key: "\n"-escaped PEM (differs from Xray) */
	o = pemText(s, 'ech_key', _('ECH Key'));
	deps(o, { ech: true });

	o = choices(list(s, 'transport', _('Transport')), [
		[ 'tcp', 'TCP' ], [ 'http', 'HTTP' ], [ 'ws', 'WebSocket' ], [ 'httpupgrade', 'HTTPUpgrade' ],
		[ 'quic', 'QUIC' ], [ 'grpc', 'gRPC' ]
	]);
	deps(o, { protocol: 'shadowsocks' }, { protocol: 'vmess' }, { protocol: 'vless' }, { protocol: 'trojan' });

	/* HTTP */
	deps(dynlist(s, 'http_host', _('HTTP Host')), { transport: 'http' });
	deps(value(s, 'http_path', _('HTTP Path')), { transport: 'http' });

	/* WebSocket */
	deps(value(s, 'ws_host', _('WebSocket Host')), { transport: 'ws' });
	deps(value(s, 'ws_path', _('WebSocket Path')), { transport: 'ws' });

	/* HTTPUpgrade */
	deps(value(s, 'httpupgrade_host', _('HTTPUpgrade Host')), { transport: 'httpupgrade' });
	deps(value(s, 'httpupgrade_path', _('HTTPUpgrade Path')), { transport: 'httpupgrade' });

	/* gRPC */
	deps(value(s, 'grpc_serviceName', 'ServiceName'), { transport: 'grpc' });

	/* Mux */
	o = flag(s, 'mux', _('Mux'));
	o.rmempty = false;
	deps(o, { protocol: 'vmess' }, { protocol: 'vless', flow: '' }, { protocol: 'shadowsocks' }, { protocol: 'trojan' });

	/* TCP Brutal */
	o = flag(s, 'tcpbrutal', _('TCP Brutal'), '0');
	deps(o, { mux: true });

	o = value(s, 'tcpbrutal_up_mbps', _('Max upload Mbps'));
	o.default = '10';
	deps(o, { tcpbrutal: true });

	o = value(s, 'tcpbrutal_down_mbps', _('Max download Mbps'));
	o.default = '50';
	deps(o, { tcpbrutal: true });

	if (hasWG) {
		proto.value('wireguard', 'WireGuard');
		deps(users, { protocol: 'wireguard' });

		deps(flag(s, 'wireguard_system_interface', _('System interface'), '0'), { protocol: 'wireguard' });

		o = value(s, 'wireguard_mtu', 'MTU');
		o.default = '1408';
		deps(o, { protocol: 'wireguard' });

		deps(dynlist(s, 'wireguard_local_address', _('Local Address')), { protocol: 'wireguard' });

		o = value(s, 'wireguard_private_key', _('Private Key'));
		o.validate = base64Validate;
		deps(o, { protocol: 'wireguard' });

		o = value(s, 'wireguard_public_key', _('Public Key'));
		o.validate = base64Validate;
		deps(o, { protocol: 'wireguard' });

		genWireguardKeyOption(s);
	}

	if (ge114) {
		proto.value('snell', 'Snell');
		deps(users, { protocol: 'snell' });

		o = choices(list(s, 'snell_version', _('Version')), [ '5', '6' ]);
		deps(o, { protocol: 'snell' });

		o = value(s, 'snell_psk', _('Pre shared key'));
		o.rmempty = false;
		deps(o, { protocol: 'snell' });

		o = choices(list(s, 'snell_obfs_mode', _('Obfs')), [ 'none', 'http' ]);
		deps(o, { protocol: 'snell', snell_version: '5' });

		o = choices(list(s, 'snell_mode', _('Mode')), [ 'default', 'unshaped', 'unsafe-raw' ]);
		deps(o, { protocol: 'snell', snell_version: '6' });
	}

	firewallOptions(s);

	o = flag(s, 'accept_lan', _('Accept LAN Access'), '0', _('When selected, it can accessed lan , this will not be safe!'));
	deps(o, { custom: false });

	outboundOptions(s, ctx, 'sing-box');

	o = flag(s, 'log', _('Log'), '1');
	o.rmempty = false;

	o = choices(list(s, 'loglevel', _('Log Level')), [ 'debug', 'info', 'warn', 'error' ]);
	o.default = 'info';
	deps(o, { log: true });
}

/* Server types in upstream file order (1_sing-box, 2_xray, 3_ss-rust, 4_ssr). */
var TYPES = [
	{ name: 'sing-box', label: 'Sing-Box', has: 'singbox', build: buildSingbox, setsDefault: true },
	{ name: 'Xray', label: 'Xray', has: 'xray', build: buildXray, setsDefault: true },
	{ name: 'SS-Rust', label: _('Shadowsocks Rust'), has: 'ssrust', build: buildSSRust },
	{ name: 'SSR', label: _('ShadowsocksR'), has: 'ssr', build: buildSSR }
];

return view.extend({
	load: function() {
		if (typeof(pw.loadCSS) == 'function') {
			try { pw.loadCSS(); } catch (e) {}
		}
		var cache = {};
		return Promise.all([
			uci.load(CONF),
			L.resolveDefault(uci.load('passwall2'), null)
		]).then(function() {
			var appPath = function(k, def) {
				return uci.get('passwall2', '@global_app[0]', k.replace(/-/g, '_') + '_file') || def;
			};
			var sbPath = appPath('sing-box', '/usr/bin/sing-box');
			var xrPath = appPath('xray', '/usr/bin/xray');

			return Promise.all([
				fileInDir(sbPath, cache),
				fileInDir(xrPath, cache),
				isFinded('ssserver', cache),
				isFinded('ssr-server', cache),
				rpcVersion('sing-box'),
				rpcVersion('xray'),
				getNetworkDevices().catch(function() { return []; })
			]).then(function(r) {
				var sbVersion = r[4];
				var has = {
					/* listing unavailable -> fall back on "a version is reported" */
					singbox: (r[0] == null) ? (sbVersion !== '') : r[0],
					xray: (r[1] == null) ? (r[5] !== '') : r[1],
					ssrust: r[2],
					ssr: r[3]
				};
				var info = { path: sbPath, has: has, sbVersion: sbVersion, netdevs: r[6] || [] };
				if (!has.singbox)
					return info;
				/* `sing-box version` -> Tags (needs file exec ACL; otherwise assume the stock build tags) */
				return L.resolveDefault(fs.exec_direct(sbPath, [ 'version' ]), null).then(function(out) {
					var tags = null, ver = null, m;
					if (out) {
						if ((m = /^Tags:\s*(.*)$/m.exec(out)) != null)
							tags = m[1];
						if ((m = /^sing-box version (\S+)/m.exec(out)) != null)
							ver = m[1];
					}
					info.sbTags = (tags != null) ? tags : 'with_quic,with_utls,with_wireguard';
					if (!info.sbVersion && ver)
						info.sbVersion = ver;
					return info;
				});
			});
		});
	},

	render: function(info) {
		var sid = getSid();
		if (!sid || !/^[A-Za-z0-9_]+$/.test(sid) || !uci.get(CONF, sid)) {
			window.location.href = url('server');
			return E('div', {}, _('Collecting data...'));
		}

		var ctx = {
			sid: sid,
			users: uci.sections(CONF, 'user'),
			nodes: getValidNormalNodes(),
			netdevs: info.netdevs || [],
			singboxTags: info.sbTags || '',
			singboxVersion: info.sbVersion || ''
		};

		var available = TYPES.filter(function(t) { return info.has[t.has]; });
		var storedType = uci.get(CONF, sid, 'type');
		/* server: a brand-new server takes the first installed type in file order */
		var currentType = storedType || (available.length ? available[0].name : null);

		var m, s, o;

		m = new form.Map(CONF);
		this.map = m;

		s = m.section(form.NamedSection, sid, 'server', _('Server Config'));
		s.addremove = false;
		s.dynamic = false;

		o = s.option(form.Flag, 'enable', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'remarks', _('Remarks'));
		o.default = _('Remarks');
		o.rmempty = false;

		var typeOpt = s.option(form.ListValue, 'type', _('Type'));
		available.forEach(function(t) {
			typeOpt.value(t.name, t.label);
			if (t.setsDefault && typeOpt.default == null)
				typeOpt.default = t.name;
		});
		/* keep a stored type whose binary is missing selectable instead of silently replacing it */
		if (storedType && !available.some(function(t) { return t.name == storedType; }))
			typeOpt.value(storedType, storedType);
		/* unset type -> the form shows (and on save stores) the type whose fields are built */
		if (!storedType && currentType)
			typeOpt.default = currentType;
		typeOpt.onchange = function(ev, section_id, val) {
			if (val == currentType)
				return;
			var sec = this.section;
			var en = depValue(sec, section_id, 'enable') == '1' ? '1' : '0';
			var remarks = depValue(sec, section_id, 'remarks');
			/*
			 * upstream config_footer: server_update_config(id, {enable, remarks, type, protocol:''})
			 * then reload. Staged through the LuCI session so a server that was just added
			 * (not yet committed) keeps working; Save & Apply commits it.
			 */
			uci.set(CONF, section_id, 'enable', en);
			uci.set(CONF, section_id, 'remarks', remarks);
			uci.set(CONF, section_id, 'type', val);
			uci.unset(CONF, section_id, 'protocol');
			return uci.save().then(function() {
				window.location.href = url('server_config/' + section_id);
			}).catch(function() {
				alert(_('Error'));
			});
		};

		var builder = null;
		TYPES.forEach(function(t) {
			if (t.name == currentType && info.has[t.has])
				builder = t;
		});
		if (builder)
			builder.build(s, ctx);

		return m.render().then(function(mapEl) {
			return E('div', { 'class': 'pw-root' }, [
				header(_('Server Config')),
				E('div', { 'class': 'pw-toolbar' }, [
					E('a', { 'class': 'btn cbi-button cbi-button-neutral', 'href': url('server') }, '« ' + _('Server-Side'))
				]),
				mapEl
			]);
		});
	},

	/*
	 * Checks that need the router: certificate/key files must exist (upstream validate:
	 * "Can't find this file!"), and re-run the TLS cross-field validation.
	 */
	preSaveCheck: function() {
		var m = this.map;
		if (!m)
			return Promise.resolve(true);
		var sid = getSid();
		var s = m.children[0];
		var checks = [];

		s.children.forEach(function(o) {
			if (o.pwIsTls && o.isActive(sid))
				o.triggerValidation(sid);
			if (!o.pwCheckFile || !o.isActive(sid))
				return;
			var v = o.formvalue(sid);
			if (v == null || v === '')
				return;
			checks.push(fs.stat(v).then(function() { return null; }, function(err) {
				/* only a definite "not found" blocks; permission problems cannot be decided here */
				return (err && err.name == 'NotFoundError') ? (o.title + ': ' + v) : null;
			}));
		});

		return Promise.all(checks).then(function(res) {
			var bad = res.filter(function(x) { return x != null; });
			if (!bad.length)
				return true;
			ui.addNotification(null, [
				E('p', {}, _("Can't find this file!")),
				E('ul', {}, bad.map(function(b) { return E('li', {}, b); }))
			], 'danger');
			return false;
		});
	},

	handleSave: function(ev) {
		var self = this;
		return this.preSaveCheck().then(function(ok) {
			if (ok)
				return view.prototype.handleSave.call(self, ev);
		});
	},

	/* upstream m.redirect = server: back to the list after Save & Apply */
	handleSaveApply: function(ev, mode) {
		var self = this;
		var target = url('server');
		return this.preSaveCheck().then(function(ok) {
			if (!ok)
				return;
			return view.prototype.handleSave.call(self, ev).then(function() {
				redirectAfterApply(target);
				return ui.changes.apply(mode == '0');
			});
		});
	}
});
