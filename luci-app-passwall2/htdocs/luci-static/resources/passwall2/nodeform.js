'use strict';
'require baseclass';
'require form';
'require ui';
'require uci';
'require fs';
'require dom';
'require passwall2.pw as pw';

/*
 * Client node form definitions (port of upstream client/type/{1_sing-box,2_xray,3_ss-rust,4_ssr}.lua
 * and client/include/shunt_options.lua for _shunt nodes).
 *
 * Specs are declarative ({cls, name, title, desc, values, deps, default, ...}) so that the same
 * definitions drive (a) the LuCI form on node_config and (b) a "virtual form" used to evaluate
 * which options are visible for a stored node (share-link export from the node list).
 *
 * Option names are the UCI option names (no per-type prefix): only the selected type's fields are
 * rendered at a time, exactly like upstream (which reloads the page when the type changes), so
 * write/remove only ever touches the active type's options.
 *
 * Dependency semantics (upstream deplist2json + legacy cbi.js):
 *   entries are OR-ed, keys inside an entry are AND-ed; `true` = checkbox checked,
 *   `false` = unchecked OR field absent/hidden, strings compare to the visible field value
 *   ("" also matches an absent/hidden field).
 */

var CONF = 'passwall2';

var SSR_METHODS = ['none', 'table', 'rc2-cfb', 'rc4', 'rc4-md5', 'rc4-md5-6', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
	'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'bf-cfb', 'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
	'cast5-cfb', 'des-cfb', 'idea-cfb', 'seed-cfb', 'salsa20', 'chacha20', 'chacha20-ietf'];
var SSR_PROTOCOLS = ['origin', 'verify_simple', 'verify_deflate', 'verify_sha1', 'auth_simple', 'auth_sha1', 'auth_sha1_v2',
	'auth_sha1_v4', 'auth_aes128_md5', 'auth_aes128_sha1', 'auth_chain_a', 'auth_chain_b', 'auth_chain_c', 'auth_chain_d',
	'auth_chain_e', 'auth_chain_f'];
var SSR_OBFS = ['plain', 'http_simple', 'http_post', 'random_head', 'tls_simple', 'tls1.0_session_auth', 'tls1.2_ticket_auth'];
var SSRUST_METHODS = ['none', 'plain', 'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-128-gcm',
	'2022-blake3-aes-256-gcm', '2022-blake3-chacha8-poly1305', '2022-blake3-chacha20-poly1305'];
var XRAY_SS_METHODS = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305', 'xchacha20-poly1305',
	'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'];
var XRAY_VMESS_SECURITY = ['auto', 'aes-128-gcm', 'chacha20-poly1305'];
var MKCP_HEADERS = ['none', 'srtp', 'utp', 'wechat-video', 'dtls', 'wireguard', 'dns'];
var SB_SS_NEW = ['none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
	'2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'];
var SB_SS_OLD = ['aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'rc4-md5',
	'chacha20-ietf', 'xchacha20'];
var SB_VMESS_SECURITY = ['none', 'auto', 'aes-128-gcm', 'chacha20-poly1305', 'zero'];
var PROBE_URLS = [
	['https://cp.cloudflare.com/', 'Cloudflare'],
	['https://www.gstatic.com/generate_204', 'Gstatic'],
	['https://www.google.com/generate_204', 'Google'],
	['https://www.youtube.com/generate_204', 'YouTube'],
	['https://connect.rom.miui.com/generate_204', 'MIUI (CN)'],
	['https://connectivitycheck.platform.hicloud.com/generate_204', 'HiCloud (CN)'],
	['https://wifi.vivo.com.cn/generate_204', 'VIVO (CN)']
];
var USER_AGENTS = [
	['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36', 'chrome'],
	['Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0', 'firefox'],
	['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15', 'safari'],
	['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.70', 'edge'],
	['Go-http-client/1.1', 'golang'],
	['curl/7.68.0', 'curl']
];
var CIPHER_SUITES = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
	'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
	'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
	'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
	'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'];
var ALPN_LIST = ['h3', 'h2', 'h3,h2', 'http/1.1', 'h2,http/1.1', 'h3,h2,http/1.1'];
var FP_XRAY = ['chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized', 'unsafe'];
var FP_SB = ['chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'];
var REALM_STUN = ['stun.sip.us:3478', 'stun.nextcloud.com:3478', 'global.stun.twilio.com:3478'];
var SPECIAL_PROTOCOLS = ['_balancing', '_shunt', '_iface', '_urltest'];

/* ------------------------------------------------------------------ helpers */

function trim(s) { return (s == null ? '' : String(s)).replace(/^\s+|\s+$/g, ''); }

function urlEncode(s) {
	/* api.UrlEncode: escape everything except [A-Za-z0-9-_.~] */
	if (typeof s !== 'string') return '';
	var bin = unescape(encodeURIComponent(s)), out = '';
	for (var i = 0; i < bin.length; i++) {
		var c = bin.charAt(i);
		if (/[A-Za-z0-9\-_.~]/.test(c)) out += c;
		else out += '%' + ('0' + bin.charCodeAt(i).toString(16).toUpperCase()).slice(-2);
	}
	return out;
}

function b64EncodeUtf8(s) { return btoa(unescape(encodeURIComponent(s))); }
function b64DecodeUtf8(s) {
	try {
		var t = String(s).replace(/-/g, '+').replace(/_/g, '/');
		t += '='.repeat((4 - t.length % 4) % 4);
		var bin = atob(t);
		try { return decodeURIComponent(escape(bin)); } catch (e) { return bin; }
	} catch (e) { return null; }
}

function toArray(v) {
	if (v == null || v === '') return [];
	return Array.isArray(v) ? v.slice() : String(v).split(/\s+/).filter(function(x) { return x !== ''; });
}

function dedup(list) {
	var seen = {}, out = [];
	(list || []).forEach(function(x) {
		if (x != null && String(x).length > 0 && !seen[x]) { seen[x] = true; out.push(x); }
	});
	return out;
}

function isIPv4(s) {
	var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s || '');
	return !!m && m.slice(1).every(function(x) { return +x <= 255; });
}

function isIPv6(s) {
	s = s || '';
	if (s.indexOf(':') < 0 || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
	var dbl = s.split('::');
	if (dbl.length > 2) return false;
	var parts = function(x) { return x === '' ? [] : x.split(':'); };
	var head = parts(dbl[0]), tail = dbl.length > 1 ? parts(dbl[1]) : [];
	var all = head.concat(tail), groups = all.length;
	for (var i = 0; i < all.length; i++) {
		if (i == all.length - 1 && all[i].indexOf('.') >= 0) {
			if (!isIPv4(all[i])) return false;
			groups++;
		} else if (!/^[0-9a-fA-F]{1,4}$/.test(all[i])) return false;
	}
	return dbl.length > 1 ? groups < 8 : groups == 8;
}

function isIP(s) { return isIPv4(s) || isIPv6(s); }

function isHostname(v) {
	/* luci.cbi.datatypes.hostname (non strict) */
	return !!v && v.length < 254 && (/^[a-zA-Z_]+$/.test(v) ||
		(/^[a-zA-Z0-9_][a-zA-Z0-9_\-.]*[a-zA-Z0-9]$/.test(v) && /[^0-9.]/.test(v)));
}

function compareVersions(a, op, b) {
	var parse = function(v) {
		return String(v || '').split(/[.\-]/).map(function(p) {
			if (/^\d+$/.test(p)) return +p;
			var m = /^r(\d+)$/.exec(p);
			return m ? +m[1] : 0;
		});
	};
	var x = parse(a), y = parse(b), n = Math.max(x.length, y.length), c = 0;
	for (var i = 0; i < n; i++) {
		var p = x[i] || 0, q = y[i] || 0;
		if (p != q) { c = p < q ? -1 : 1; break; }
	}
	switch (op) {
	case '>=': return c >= 0;
	case '>': return c > 0;
	case '<=': return c <= 0;
	case '<': return c < 0;
	default: return c == 0;
	}
}

function parseRealmUri(uri) {
	/* api.parse_realm_uri */
	uri = trim(uri);
	if (uri === '') return null;
	var scheme = /^realm\+http:\/\//.test(uri) ? 'realm+http' : (/^realm:\/\//.test(uri) ? 'realm' : null);
	if (!scheme) return null;
	uri = uri.replace(/^realm\+http:\/\//, '').replace(/^realm:\/\//, '');
	var m = /^([^@]+)@([^/]+)\/([^?]*)\??(.*)$/.exec(uri);
	if (!m) return null;
	var server_url = m[2], address, port;
	var m6 = /^\[([^\]]+)\]:(\d+)$/.exec(server_url), m4 = /^([^:]+):(\d+)$/.exec(server_url);
	if (m6) { address = m6[1]; port = m6[2]; }
	else if (m4) { address = m4[1]; port = m4[2]; }
	else { var mb = /^\[([^\]]+)\]$/.exec(server_url); address = mb ? mb[1] : server_url; }
	var stun = [], re = /[Ss][Tt][Uu][Nn]=([^&]+)/g, sm;
	while ((sm = re.exec(m[4] || '')) !== null) stun.push(sm[1]);
	return {
		scheme: scheme, token: m[1], server_url: server_url, address: address,
		port: +port || (scheme == 'realm+http' ? 80 : 443), realm_id: m[3].replace(/\/+$/, ''),
		stun_servers: stun.length ? stun : null
	};
}

function validateHeaders(value, banSpecial) {
	value = trim(value).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
	var seen = {};
	var lines = value.split('\n');
	for (var i = 0; i < lines.length; i++) {
		var line = lines[i];
		if (line === '' || trim(line) === '') continue;
		var m = /^\s*([^:]+):/.exec(line);
		var key = m ? trim(m[1]).toLowerCase() : null;
		if (!key || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(key) || seen[key] ||
		    (banSpecial && (key == 'host' || key == 'capsule-protocol')))
			return _('Not true format, please re-enter!') + ' (' + line + ')';
		seen[key] = true;
	}
	return true;
}

function normJsonText(value) {
	return trim(value).replace(/\r\n/g, '\n').replace(/^[ \t]*\n/, '').replace(/\n[ \t]*$/, '').replace(/\n[ \t]*\n/g, '\n');
}

function isJsonObject(str) {
	try { var o = JSON.parse(str); return o !== null && typeof o === 'object'; } catch (e) { return false; }
}

/* value encoders (UCI <-> form) used by the `enc` spec attribute */
var ENC = {
	pem: {
		decode: function(v) { return (v || '').replace(/\\n/g, '\n'); },
		encode: function(v) {
			v = trim(v).replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\n+/g, '\n');
			return v.replace(/\n/g, '\\n');
		}
	},
	escnl: {
		/* masque warp keys / headers: trim, CRLF/CR -> LF, LF -> literal \n */
		decode: function(v) { return (v || '').replace(/\\n/g, '\n'); },
		encode: function(v) { return trim(v).replace(/\r\n?/g, '\n').replace(/\n/g, '\\n'); }
	},
	oneline: {
		decode: function(v) { return v; },
		encode: function(v) { return trim(String(v).replace(/[\r\n]/g, '')); }
	},
	sshkey: {
		decode: function(v) { return v; },
		encode: function(v) { return trim(v).replace(/\r\n/g, '\n').replace(/[ \t]*\n[ \t]*/g, '\n').replace(/\n+/g, '\n'); }
	},
	b64json: {
		decode: function(v) { return v == null ? null : b64DecodeUtf8(v); },
		encode: function(v) { return b64EncodeUtf8(normJsonText(v)); }
	},
	trim: {
		decode: function(v) { return v; },
		encode: function(v) { return trim(v); }
	},
	nonedefault: {
		decode: function(v) { return v; },
		encode: function(v) { v = trim(v); return v === '' ? 'none' : v; }
	}
};

/* ------------------------------------------------------------------- specs */

function Spec(cls, name, title, desc) {
	this.cls = cls;
	this.name = name;
	this.title = title;
	this.desc = desc;
	this.values = [];
	this.deps = [];
}
Spec.prototype.value = function(k, l, group) {
	this.values.push([String(k), l == null ? String(k) : l, group == null ? '' : group]);
	return this;
};
Spec.prototype.depends = function(d) { this.deps.push(d); return this; };
Spec.prototype.set = function(props) { for (var k in props) this[k] = props[k]; return this; };

function SpecList() { this.list = []; this.map = {}; }
SpecList.prototype.add = function(cls, name, title, desc) {
	var sp = new Spec(cls, name, title, desc);
	this.list.push(sp);
	this.map[name] = sp;
	return sp;
};
SpecList.prototype.get = function(name) { return this.map[name]; };

function nodeGroupLabel(g) { return (g && g !== '') ? g : _('default'); }

/* ------------------------------------------------------------- environment */

function listDir(path) {
	return L.resolveDefault(fs.list(path), []).then(function(l) { return Array.isArray(l) ? l : []; });
}

function getNetworkDevices(env) {
	/* api.get_network_devices() */
	var ifaceToDev = {}, devToIfaces = {}, ifaceProto = {};
	uci.sections('network', 'interface').forEach(function(sec) {
		var name = sec['.name'];
		if (name == 'loopback') return;
		ifaceProto[name] = sec.proto;
		if (sec.device) {
			ifaceToDev[name] = sec.device;
			(devToIfaces[sec.device] = devToIfaces[sec.device] || []).push(name);
		}
	});
	return listDir('/sys/class/net').then(function(entries) {
		var devs = entries.map(function(e) { return e.name; }).filter(function(dev) {
			return dev != 'lo' && !/^(veth|ifb|gre|sit|ip6tnl|erspan)/.test(dev);
		});
		return Promise.all(devs.map(function(dev) {
			return listDir('/sys/class/net/' + dev).then(function(sub) {
				var names = {};
				sub.forEach(function(s) { names[s.name] = s.type; });
				return { dev: dev, names: names };
			});
		}));
	}).then(function(infos) {
		var seen = {}, out = [];
		infos.forEach(function(info) {
			var n = info.names, dev = info.dev;
			if (n.master || n.dsa) return;
			var dtype;
			if (n.bridge === 'directory') dtype = _('Bridge');
			else if (n.wireless === 'directory') dtype = _('Wireless Adapter');
			else if (/^(tun|tap|wg|ppp)/.test(dev)) dtype = _('Tunnel Interface');
			else dtype = _('Ethernet Adapter');
			var label = dtype + ': "' + dev + '"';
			if (devToIfaces[dev]) label += ' (' + devToIfaces[dev].join(', ') + ')';
			out.push({ name: dev, label: label, sort: dtype + ':' + dev });
			seen[dev] = true;
		});
		Object.keys(ifaceToDev).forEach(function(iface) {
			var dev = ifaceToDev[iface];
			if (seen[dev]) return;
			var dtype;
			if (/^br-/.test(dev)) dtype = _('Bridge');
			else if (['wireguard', 'pppoe', 'pptp', 'l2tp'].indexOf(ifaceProto[iface]) >= 0) dtype = _('Tunnel Interface');
			else dtype = _('Interface');
			out.push({ name: iface, label: dtype + ': "' + iface + '"', sort: 'zzz:' + iface });
			seen[dev] = true;
		});
		out.sort(function(a, b) { return a.sort < b.sort ? -1 : (a.sort > b.sort ? 1 : 0); });
		return out;
	});
}

function callSafe(method, params) {
	try {
		return Promise.resolve(pw.call(method, params || {})).catch(function() { return null; });
	} catch (e) { return Promise.resolve(null); }
}

/*
 * loadEnv(): binary/capability detection + node lists.
 * Capabilities upstream computes server side are detected with fs.list() (allowed by luci-base ACL)
 * and the rpc `com_version`; sing-box build tags come from rpc `get_singbox_tags` when provided by
 * the backend, else from `sing-box version` via fs.exec_direct, else a conservative default.
 */
function loadEnv() {
	var env = { bins: {} };
	return uci.load([CONF, 'network']).catch(function() { return uci.load(CONF); }).then(function() {
		return Promise.all(['/bin', '/usr/bin', '/sbin', '/usr/sbin'].map(listDir));
	}).then(function(dirs) {
		dirs.forEach(function(list) { list.forEach(function(e) { if (e.type != 'directory') env.bins[e.name] = true; }); });
		var app = uci.sections(CONF, 'global_app')[0] || {};
		var findCom = function(com) {
			var path = app[com.replace(/-/g, '_') + '_file'] || ('/usr/bin/' + com);
			var dir = path.replace(/\/[^/]*$/, '') || '/', base = path.replace(/^.*\//, '');
			if (['/bin', '/usr/bin', '/sbin', '/usr/sbin'].indexOf(dir) >= 0)
				return Promise.resolve(env.bins[base] ? path : null);
			return listDir(dir).then(function(l) {
				return l.some(function(e) { return e.name == base && e.type != 'directory'; }) ? path : null;
			});
		};
		/* when the directory listing is not permitted/empty, ask the backend (com_version) */
		var viaRpc = function(com) {
			return findCom(com).then(function(p) {
				if (p) return p;
				return callSafe('com_version', { com: com }).then(function(r) {
					return (r && r.code == 1 && r.data) ? (app[com.replace(/-/g, '_') + '_file'] || '/usr/bin/' + com) : null;
				});
			});
		};
		return Promise.all([viaRpc('xray'), viaRpc('sing-box')]);
	}).then(function(paths) {
		env.xray_path = paths[0];
		env.singbox_path = paths[1];
		env.has_xray = !!paths[0];
		env.has_singbox = !!paths[1];
		env.has_sslocal = !!env.bins.sslocal;
		env.has_ssr_local = !!env.bins['ssr-local'];
		env.has_geoview = !!env.bins.geoview;
		env.plugins = ['xray-plugin', 'v2ray-plugin', 'obfs-local', 'shadow-tls'].filter(function(p) { return env.bins[p]; });
		if (!env.has_singbox) {
			env.singbox_tags = '';
			env.singbox_version = '';
			return;
		}
		return Promise.all([
			callSafe('com_version', { com: 'sing-box' }),
			callSafe('get_singbox_tags', {}),
		]).then(function(res) {
			var ver = res[0] && (res[0].data || res[0].result) || '';
			var tags = res[1] && (res[1].result || res[1].tags || res[1].data) || '';
			if (ver && tags) return [ver, tags];
			return L.resolveDefault(fs.exec_direct(env.singbox_path, ['version']), '').then(function(out) {
				out = out || '';
				var mv = /^sing-box version (\S+)/m.exec(out), mt = /^Tags:\s*(.*)$/m.exec(out);
				return [ver || (mv ? mv[1] : ''), tags || (mt ? mt[1] : (out ? '' : null))];
			});
		}).then(function(vt) {
			env.singbox_version = String(vt[0] || '').replace(/^v/, '');
			/* unknown tags (no backend support / no exec permission): assume the usual OpenWrt build */
			env.singbox_tags = (vt[1] == null) ? 'with_quic,with_utls,with_wireguard' : String(vt[1]);
		});
	}).then(function() {
		env.ge114 = env.has_singbox && compareVersions((env.singbox_version.match(/[^v]+/) || [''])[0], '>=', '1.14.0');
		env.ge115 = env.has_singbox && compareVersions((env.singbox_version.match(/[^v]+/) || [''])[0], '>=', '1.15.0');
		env.hasTag = function(t) { return (env.singbox_tags || '').indexOf(t) >= 0; };
		return getNetworkDevices(env).catch(function() { return []; });
	}).then(function(netdevs) {
		env.netdevs = netdevs;
		return env;
	});
}

/* api.get_valid_nodes() */
function protoLabel(p) {
	switch (p) {
	case 'vmess': return 'VMess';
	case 'vless': return 'VLESS';
	case 'shadowsocks': return 'SS';
	case 'shadowsocksr': return 'SSR';
	case 'wireguard': return 'WG';
	case 'hysteria': return 'HY';
	case 'hysteria2': return 'HY2';
	case 'anytls': return 'AnyTLS';
	case 'ssh': return 'SSH';
	default: return p ? p.charAt(0).toUpperCase() + p.slice(1) : '';
	}
}

function getValidNodes() {
	var other = uci.sections(CONF, 'global_other')[0] || {};
	var show_node_info = other.show_node_info || '0';
	var defaults = [], others = [];
	var push = function(e) { ((!e.group || e.group === '') ? defaults : others).push(e); };
	uci.sections(CONF, 'nodes').forEach(function(s) {
		var e = Object.assign({}, s);
		e.id = e['.name'];
		if (!e.type || !e.remarks) return;
		var type_name = e.type == 'sing-box' ? 'Sing-Box' : e.type;
		if (e.protocol && SPECIAL_PROTOCOLS.indexOf(e.protocol) >= 0) {
			e.remark = trim(type_name + ' ' + _(e.protocol) + '：[' + e.remarks + ']');
			e.node_type = 'special';
			push(e);
		}
		var port = e.port || e.hysteria_hop || e.hysteria2_hop;
		var is_realm = e.protocol == 'hysteria2' && e.hysteria2_realms;
		if ((port && e.address) || is_realm) {
			var address = e.address;
			if (isIP(address) || isHostname(address) || is_realm) {
				var tn = type_name;
				if ((e.type == 'sing-box' || e.type == 'Xray') && e.protocol)
					tn += ' ' + protoLabel(e.protocol);
				if (isIPv6(address)) address = '[' + address + ']';
				if (is_realm) tn += ' Realm';
				var n = Object.assign({}, e);
				n.remark = trim(tn + '：[' + e.remarks + ']');
				if (show_node_info == '1' && !is_realm)
					n.remark = trim(tn + '：[' + e.remarks + '] ' + address + ':' + String(port || '').replace(/:/g, '-'));
				n.node_type = 'normal';
				push(n);
			}
		}
	});
	return defaults.concat(others);
}

/* api.get_node_list() */
function getNodeList() {
	var list = { socks_list: [], normal_list: [] };
	uci.sections(CONF, 'socks').forEach(function(s) {
		if (s.node)
			list.socks_list.push({ id: s['.name'], remark: _('Socks Config') + ' [' + (s.port || '') + _('Port') + ']', group: 'Socks' });
	});
	getValidNodes().forEach(function(e) {
		if (e.node_type == 'normal')
			list.normal_list.push({ id: e['.name'], remark: e.remark, type: e.type, chain_proxy: e.chain_proxy, group: e.group });
		if (e.protocol && e.protocol.charAt(0) == '_') {
			var k = e.protocol.substr(1) + '_list';
			(list[k] = list[k] || []).push({ id: e['.name'], remark: e.remark, group: e.group, o: e });
		}
	});
	return list;
}

/* ------------------------------------------------------------ spec builders */

function addChain(S, ctx, special) {
	var o = S.add('ListValue', 'chain_proxy', _('Chain Proxy'));
	o.value('', _('Close(Not use)'));
	if (!special) {
		o.value('1', _('Preproxy Node'));
		o.value('3', _('Outbound Interface'));
	}
	o.value('2', _('Landing Node'));

	var o1 = S.add('NodeList', 'preproxy_node', _('Preproxy Node'), _('Only support a layer of proxy.'));
	o1.depends({ chain_proxy: '1', hysteria2_realms: false });
	var o3 = S.add('Value', 'outbound_iface', _('Outbound Interface'));
	o3.depends({ chain_proxy: '3' });
	o3.value('', _('All'));
	ctx.env.netdevs.forEach(function(d) { o3.value(d.name, d.label); });
	var o2 = S.add('NodeList', 'to_node', _('Landing Node'), _('Only support a layer of proxy.'));
	o2.depends({ chain_proxy: '2', hysteria2_realms: false });

	['socks_list', 'normal_list', 'balancing_list', 'urltest_list'].forEach(function(k) {
		(ctx.nodeList[k] || []).forEach(function(v) {
			if (v.id == ctx.sid) return;
			o1.value(v.id, v.remark, nodeGroupLabel(v.group));
			if (k == 'normal_list')
				o2.value(v.id, v.remark, nodeGroupLabel(v.group));
		});
	});
}

function addNodeSelection(S, ctx, listName, listTitle, listDesc, special) {
	var o = S.add('ListValue', 'node_add_mode', _('Node Addition Method'));
	o.depends({ protocol: special });
	o.set({ default: 'manual' });
	o.value('manual', _('Manual'));
	o.value('batch', _('Batch'));

	o = S.add('NodeMulti', listName, listTitle, listDesc);
	o.depends({ node_add_mode: 'manual' });
	['socks_list', 'normal_list'].forEach(function(k) {
		(ctx.nodeList[k] || []).forEach(function(v) { o.value(v.id, v.remark, v.group || ''); });
	});

	o = S.add('CheckList', 'node_group', _('Select Group'));
	o.depends({ node_add_mode: 'batch' });
	o.set({ cast: 'string' });
	o.value('default', _('default'));
	ctx.groups.forEach(function(g) { o.value(urlEncode(g), g); });

	o = S.add('Value', 'node_match_rule', _('Node Matching Rules'));
	o.depends({ node_add_mode: 'batch' });
	o.desc = _('Example: <code>^A && B && !C && D$</code><br>This means the node remark must start with A (^), include B, exclude C (!), and end with D ($).<br>Conditions are joined by <code>&&</code> (AND), and their order does not affect the result.<br>Multiple groups can be separated by <code>||</code> (OR), matching succeeds if any group matches.<br>Example: <code>A && B || C && D</code> means (A AND B) OR (C AND D).');
}

function timeDesc() {
	return _('The time format is numbers + units, such as \'10s\', \'2h45m\', and the supported time units are <code>s</code>, <code>m</code>, <code>h</code>, which correspond to seconds, minutes, and hours, respectively.') + '<br>' +
		_('When the unit is not filled in, it defaults to seconds.');
}

function pinDesc() {
	return _('Once set, connects only when the server’s chain fingerprint matches.') +
		'<a href="javascript:void(0)" onclick="return window.pw2FetchCertSha256 && window.pw2FetchCertSha256(this)">→ ' + _('Fetch Manually') + '</a>';
}

function addUserAgent(S, deps) {
	var o = S.add('Value', 'user_agent', _('User-Agent'));
	o.set({ default: '' });
	o.value('', _('default'));
	USER_AGENTS.forEach(function(u) { o.value(u[0], u[1]); });
	deps.forEach(function(d) { o.depends(d); });
}

function addDomainResolver(S) {
	var o = S.add('ListValue', 'domain_resolver', _('Domain DNS Resolve'), _('If the node address is a domain name, this DNS will be used for resolution.'));
	o.value('', _('Auto'));
	o.value('tcp', 'TCP');
	o.value('udp', 'UDP');
	o.value('https', 'HTTPS');

	o = S.add('Value', 'domain_resolver_dns', 'DNS');
	o.set({ datatype: 'or(ipaddr,ipaddrport)', default: '114.114.114.114' });
	o.value('114.114.114.114');
	o.value('223.5.5.5:53');
	o.depends({ domain_resolver: 'tcp' });
	o.depends({ domain_resolver: 'udp' });

	o = S.add('Value', 'domain_resolver_dns_https', 'DNS');
	o.value('https://120.53.53.53/dns-query', 'DNSPod');
	o.value('https://223.5.5.5/dns-query', 'AliDNS');
	o.set({ default: 'https://120.53.53.53/dns-query' });
	o.depends({ domain_resolver: 'https' });
}

function addHy2Common(S, realmDeps) {
	var o = S.add('Value', 'hysteria2_hop', _('Port hopping range'), _('Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).'));
	o.depends({ protocol: 'hysteria2', hysteria2_realms: false });

	o = S.add('Value', 'hysteria2_hop_interval', _('Hop Interval(second)'), _('Supports a fixed value or a random range (e.g., 30, 5-30), minimum 5.'));
	o.set({ datatype: 'or(uinteger,portrange)', placeholder: '30', default: '30' });
	o.depends({ protocol: 'hysteria2', hysteria2_realms: false });

	o = S.add('Flag', 'hysteria2_realms', _('Realms'));
	o.set({ default: '0' });
	o.depends(realmDeps);

	o = S.add('Value', 'hysteria2_realm_url', _('Realm URL'), _('Example:') + 'realm://public@realm.hy2.io/your-realm-name');
	o.depends({ hysteria2_realms: '1' });
	o.set({ enc: 'trim', validate: function(v) { return parseRealmUri(v) ? true : _('Invalid Realm URL.'); } });

	o = S.add('DynamicList', 'hysteria2_realm_stun', _('Realm STUN'));
	o.set({ default: REALM_STUN.slice() });
	o.depends({ hysteria2_realms: '1' });

	o = S.add('Flag', 'hysteria2_realm_upnp', _('Enable') + ' UPnP/NAT-PMP', _('Enable UPnP/NAT-PMP port mapping on your gateway to improve hole punching success.'));
	o.set({ default: '0' });
	o.depends({ hysteria2_realms: '1' });

	o = S.add('Value', 'hysteria2_auth_password', _('Auth Password'));
	o.set({ password: true });
	o.depends({ protocol: 'hysteria2' });

	o = S.add('ListValue', 'hysteria2_obfs_type', _('Obfs Type'));
	o.value('', _('Disable'));
	o.value('salamander');
	o.value('gecko');
	o.depends({ protocol: 'hysteria2' });

	o = S.add('Value', 'hysteria2_obfs_password', _('Obfs Password'));
	o.depends({ hysteria2_obfs_type: 'salamander' });
	o.depends({ hysteria2_obfs_type: 'gecko' });

	o = S.add('Value', 'hysteria2_obfs_MinPacketSize', _('Gecko Packet Size (min)'));
	o.set({ datatype: 'uinteger', placeholder: '512', default: '512' });
	o.depends({ hysteria2_obfs_type: 'gecko' });

	o = S.add('Value', 'hysteria2_obfs_MaxPacketSize', _('Gecko Packet Size (max)'));
	o.set({ datatype: 'uinteger', placeholder: '1200', default: '1200' });
	o.depends({ hysteria2_obfs_type: 'gecko' });

	S.add('Value', 'hysteria2_up_mbps', _('Max upload Mbps')).depends({ protocol: 'hysteria2' });
	S.add('Value', 'hysteria2_down_mbps', _('Max download Mbps')).depends({ protocol: 'hysteria2' });

	o = S.add('Value', 'hysteria2_stream_recv_win', _('QUIC stream receive window') + ' (MB)');
	o.set({ datatype: 'range(1,1000)', placeholder: '8' });
	o.depends({ protocol: 'hysteria2' });

	o = S.add('Value', 'hysteria2_conn_recv_win', _('QUIC connection receive window') + ' (MB)');
	o.set({ datatype: 'range(1,1000)', placeholder: '20' });
	o.depends({ protocol: 'hysteria2' });

	o = S.add('Value', 'hysteria2_idle_timeout', _('Idle Timeout'), _('Units:seconds') + ' (4~120)');
	o.set({ datatype: 'range(4,120)' });
	o.depends({ protocol: 'hysteria2' });

	o = S.add('Value', 'hysteria2_keep_alive_period', _('QUIC KeepAlive interval'), _('Units:seconds') + ' (2~60)');
	o.set({ datatype: 'range(2,60)' });
	o.depends({ protocol: 'hysteria2' });

	o = S.add('Flag', 'hysteria2_disable_mtu_discovery', _('Disable MTU detection'));
	o.set({ default: '0' });
	o.depends({ protocol: 'hysteria2' });
}

function addFinalMaskText(S) {
	var o = S.add('TextValue', 'finalmask', '　', _('An FinalMaskObject in JSON format, used for sharing.') + '<br>' +
		_('Custom finalmask overrides mkcp, hysteria2, fragment, noise, and related settings.'));
	o.depends({ use_finalmask: true });
	o.set({ rows: 10, wrap: 'off', enc: 'b64json', validate: function(v) {
		return isJsonObject(normJsonText(v)) ? true : 'FinalMask ' + _('Must be JSON text!');
	} });
}

function addPemCert(S) {
	var o = S.add('TextValue', 'tls_certificate_pem', '　', _('Full certificate (chain), PEM format.'));
	o.set({ default: '', rows: 5, wrap: 'off', enc: 'pem' });
	o.depends({ tls_certificate: true });
}

function addCipherSuites(S, deps) {
	var o = S.add('DynamicList', 'cipherSuites', _('Cipher Suites'),
		'<a href="https://go.dev/src/crypto/tls/cipher_suites.go#L44" target="_blank">***</a> ' + _('Configures the list of supported cipher suites.'));
	CIPHER_SUITES.forEach(function(c) { o.value(c); });
	deps.forEach(function(d) { o.depends(d); });
}

function addAlpn(S, name, title, extra, deps) {
	var o = S.add('ListValue', name, title);
	o.set({ default: 'default' });
	o.value('default', _('Default'));
	ALPN_LIST.concat(extra || []).forEach(function(a) { o.value(a); });
	deps.forEach(function(d) { o.depends(d); });
	return o;
}

function addProbeUrl(S, name) {
	var o = S.add('Value', name, _('Probe URL'));
	PROBE_URLS.forEach(function(p) { o.value(p[0], p[1]); });
	o.set({ default: PROBE_URLS[2][0] });
	o.desc = _('The URL used to detect the connection status.');
	return o;
}

/* ---- Xray (client/type/2_xray.lua) */
function xraySpecs(S, ctx) {
	var o = S.add('ListValue', 'protocol', _('Protocol'));
	o.value('vmess', _('Vmess'));
	o.value('vless', _('VLESS'));
	o.value('http', _('HTTP'));
	o.value('socks', _('Socks'));
	o.value('shadowsocks', _('Shadowsocks'));
	o.value('trojan', _('Trojan'));
	o.value('wireguard', _('WireGuard'));
	o.value('hysteria2', _('Hysteria2'));
	o.value('masque', 'MASQUE');
	o.value('_balancing', _('Balancing'));
	o.value('_shunt', _('Shunt'));
	o.value('_iface', _('Custom Interface'));
	o.set({ kindSwitch: true });
	var protocols = o.values.map(function(v) { return v[0]; });
	var kind = ctx.kind;

	if (kind == '_balancing') {
		addNodeSelection(S, ctx, 'balancing_node', _('Load balancing node list'),
			_('Load balancing node list, <a target=\'_blank\' href=\'https://xtls.github.io/config/routing.html#balancerobject\'>document</a>'), '_balancing');

		o = S.add('ListValue', 'balancingStrategy', _('Balancing Strategy'));
		o.depends({ protocol: '_balancing' });
		['random', 'roundRobin', 'leastPing', 'leastLoad'].forEach(function(v) { o.value(v); });
		o.set({ default: 'random' });

		o = S.add('NodeList', 'fallback_node', _('Fallback Node'));
		o.value('', _('Close(Not use)'));
		o.value('_direct', _('Direct Connection'));
		o.depends({ protocol: '_balancing' });
		var fallback_list = [];
		(ctx.nodeList.balancing_list || []).forEach(function(e) {
			if (e.id != ctx.sid)
				fallback_list.push({ id: e.id, remark: e.remark, group: e.group, fallback: e.o.fallback_node });
		});
		var MAX_DEPTH = 3;
		var find = function(id) { for (var i = 0; i < fallback_list.length; i++) if (fallback_list[i].id == id) return fallback_list[i]; return null; };
		var willLoop = function(start, target, depth) {
			depth = depth || 0;
			if (depth >= MAX_DEPTH) return false;
			var v = find(target);
			if (!v) return false;
			var fb = v.fallback;
			if (!fb || fb == '' || fb == '_direct') return false;
			if (fb == start) return true;
			return willLoop(start, fb, depth + 1);
		};
		var depthOf = function(id, depth) {
			depth = depth || 0;
			if (depth >= MAX_DEPTH) return depth;
			var v = find(id);
			if (!v) return depth;
			var fb = v.fallback;
			if (!fb || fb == '' || fb == '_direct') return depth;
			return depthOf(fb, depth + 1);
		};
		fallback_list.forEach(function(v) {
			if (depthOf(v.id) < MAX_DEPTH && !willLoop(ctx.sid, v.id))
				o.value(v.id, v.remark, nodeGroupLabel(v.group));
		});
		['socks_list', 'normal_list', 'urltest_list'].forEach(function(k) {
			(ctx.nodeList[k] || []).forEach(function(v) { o.value(v.id, v.remark, nodeGroupLabel(v.group)); });
		});

		o = S.add('Flag', 'useCustomProbeUrl', _('Use Custom Probe URL'), _('By default the built-in probe URL will be used, enable this option to use a custom probe URL.'));
		o.depends({ protocol: '_balancing' });

		o = addProbeUrl(S, 'probeUrl');
		o.depends({ useCustomProbeUrl: true });

		o = S.add('Value', 'probeInterval', _('Probe Interval'));
		o.depends({ protocol: '_balancing' });
		o.set({ default: '1m', placeholder: '1m' });
		o.desc = _('The interval between initiating probes.') + '<br>' + timeDesc();

		o = S.add('Value', 'expected', _('Preferred Node Count'));
		o.depends({ balancingStrategy: 'leastLoad' });
		o.set({ datatype: 'uinteger', default: '2', placeholder: '2' });
		o.desc = _('The load balancer selects the optimal number of nodes, and traffic is randomly distributed among them.');

		o = S.add('Value', 'tolerance', _('Failure Tolerance (%)'));
		o.depends({ balancingStrategy: 'leastLoad' });
		o.set({ datatype: 'uinteger', default: '10', placeholder: '10' });
		o.desc = _('The maximum acceptable speed test failure rate. For example, 1 means allowing a 1% failure rate.');
	}

	if (kind == '_iface') {
		o = S.add('Value', 'iface', _('Interface'));
		o.depends({ protocol: '_iface' });
		ctx.env.netdevs.forEach(function(d) { o.value(d.name, d.label); });
	}

	if (kind == 'normal') {
		S.add('Value', 'address', _('Address (Support Domain Name)'));
		S.add('Value', 'port', _('Port')).set({ datatype: 'port' });

		o = S.add('Value', 'uuid', _('ID')).set({ password: true });
		o.depends({ protocol: 'vmess' }); o.depends({ protocol: 'vless' });

		o = S.add('Value', 'username', _('Username'));
		['http', 'socks', 'masque'].forEach(function(p) { o.depends({ protocol: p }); });

		o = S.add('Value', 'password', _('Password')).set({ password: true });
		['http', 'socks', 'shadowsocks', 'trojan', 'masque'].forEach(function(p) { o.depends({ protocol: p }); });

		o = S.add('Flag', 'masque_warp', 'WARP').set({ default: '0' });
		o.depends({ protocol: 'masque' });
		[['masque_warp_private_key', _('WARP Device Private Key')], ['masque_warp_public_key', _('WARP Endpoint Public Key')]].forEach(function(f) {
			var t = S.add('TextValue', f[0], f[1]);
			t.set({ rows: 3, wrap: 'off', enc: 'escnl' });
			t.depends({ protocol: 'masque', masque_warp: '1' });
		});
		S.add('DynamicList', 'masque_warp_address', 'WARP ' + _('Local Address')).depends({ protocol: 'masque', masque_warp: '1' });
		S.add('Value', 'masque_path', _('MASQUE Path')).depends({ protocol: 'masque' });
		o = S.add('TextValue', 'masque_headers', _('Custom HTTP Headers'));
		o.set({ rows: 5, wrap: 'off', enc: 'escnl', validate: function(v) { return validateHeaders(v, true); } });
		o.depends({ protocol: 'masque' });

		o = S.add('ListValue', 'security', _('Encrypt Method'));
		XRAY_VMESS_SECURITY.forEach(function(t) { o.value(t); });
		o.depends({ protocol: 'vmess' });

		o = S.add('Value', 'encryption', _('Encrypt Method') + ' (encryption)');
		o.set({ default: 'none', placeholder: 'none', enc: 'nonedefault' });
		o.depends({ protocol: 'vless' });

		o = S.add('ListValue', 'ss_method', _('Encrypt Method'));
		XRAY_SS_METHODS.forEach(function(t) { o.value(t); });
		o.depends({ protocol: 'shadowsocks' });

		o = S.add('ListValue', 'flow', _('flow')).set({ default: '' });
		o.value('', _('Disable'));
		o.value('xtls-rprx-vision');
		o.value('xtls-rprx-vision-udp443');
		o.depends({ protocol: 'vless' });

		addHy2Common(S, { protocol: 'hysteria2' });

		o = S.add('Flag', 'tls', _('TLS')).set({ default: '0' });
		['vmess', 'vless', 'http', 'socks', 'trojan', 'shadowsocks'].forEach(function(p) { o.depends({ protocol: p }); });

		o = S.add('Flag', 'reality', _('REALITY')).set({ default: '0' });
		['raw', 'ws', 'grpc', 'httpupgrade', 'xhttp'].forEach(function(t) { o.depends({ tls: true, transport: t }); });

		addAlpn(S, 'alpn', _('alpn'), [], [{ tls: true, reality: false }, { protocol: 'masque' }]);

		o = S.add('Value', 'tls_serverName', 'SNI ' + _('Domain'));
		o.depends({ tls: true }); o.depends({ protocol: 'hysteria2' }); o.depends({ protocol: 'masque' });

		var pinDeps = [{ tls: true, reality: false }, { protocol: 'hysteria2' }, { protocol: 'masque' }];
		o = S.add('Value', 'tls_pinSHA256', _('TLS Chain Fingerprint (SHA256)'), pinDesc());
		pinDeps.forEach(function(d) { o.depends(d); });
		o = S.add('Value', 'tls_CertByName', _('TLS Certificate Name (CertName)'), _('TLS is used to verify the leaf certificate name.'));
		pinDeps.forEach(function(d) { o.depends(d); });
		o = S.add('Flag', 'tls_certificate', _('TLS Certificate (PEM)')).set({ default: '0' });
		pinDeps.forEach(function(d) { o.depends(d); });
		addPemCert(S);

		o = S.add('Flag', 'ech', _('ECH')).set({ default: '0' });
		o.depends({ tls: true, reality: false }); o.depends({ protocol: 'hysteria2', hysteria2_realms: false }); o.depends({ protocol: 'masque' });
		o = S.add('TextValue', 'ech_config', _('ECH Config'));
		o.set({ default: '', rows: 5, wrap: 'soft', enc: 'oneline' });
		o.depends({ ech: true });

		S.add('Value', 'reality_publicKey', _('Public Key')).depends({ tls: true, reality: true });
		S.add('Value', 'reality_shortId', _('Short Id')).depends({ tls: true, reality: true });
		S.add('Value', 'reality_spiderX', _('Spider X')).set({ placeholder: '/' }).depends({ tls: true, reality: true });

		S.add('Flag', 'utls', _('uTLS')).set({ default: '0' }).depends({ tls: true, reality: false });
		o = S.add('ListValue', 'fingerprint', _('Finger Print'));
		FP_XRAY.forEach(function(f) { o.value(f); });
		o.set({ default: 'chrome' });
		o.depends({ tls: true, utls: true }); o.depends({ tls: true, reality: true });

		S.add('Flag', 'use_mldsa65Verify', _('ML-DSA-65')).set({ default: '0' }).depends({ tls: true, reality: true });
		addCipherSuites(S, [{ tls: true, reality: false }, { protocol: 'masque' }]);
		o = S.add('TextValue', 'reality_mldsa65Verify', 'ML-DSA-65 ' + _('Public key'));
		o.set({ default: '', rows: 5, wrap: 'soft', enc: 'oneline' });
		o.depends({ use_mldsa65Verify: true });

		o = S.add('ListValue', 'transport', _('Transport'));
		o.value('raw', 'RAW (TCP)'); o.value('mkcp', 'mKCP'); o.value('ws', 'WebSocket'); o.value('grpc', 'gRPC');
		o.value('httpupgrade', 'HttpUpgrade'); o.value('xhttp', 'XHTTP');
		['vmess', 'vless', 'socks', 'shadowsocks', 'trojan'].forEach(function(p) { o.depends({ protocol: p }); });

		S.add('Value', 'wireguard_public_key', _('Public Key')).depends({ protocol: 'wireguard' });
		S.add('Value', 'wireguard_secret_key', _('Private Key')).depends({ protocol: 'wireguard' });
		S.add('Value', 'wireguard_preSharedKey', _('Pre shared key')).depends({ protocol: 'wireguard' });
		S.add('DynamicList', 'wireguard_local_address', _('Local Address')).depends({ protocol: 'wireguard' });
		S.add('Value', 'wireguard_mtu', _('MTU')).set({ default: '1420' }).depends({ protocol: 'wireguard' });
		S.add('Value', 'wireguard_reserved', _('Reserved'), _('Decimal numbers separated by "," or Base64-encoded strings.')).depends({ protocol: 'wireguard' });
		S.add('Value', 'wireguard_keepAlive', _('Keep Alive')).set({ default: '0' }).depends({ protocol: 'wireguard' });

		o = S.add('ListValue', 'tcp_guise', _('Camouflage Type'));
		o.value('none', 'none'); o.value('http', 'http');
		o.depends({ transport: 'raw' });
		S.add('DynamicList', 'tcp_guise_http_host', _('HTTP Host')).depends({ tcp_guise: 'http' });
		S.add('DynamicList', 'tcp_guise_http_path', _('HTTP Path')).set({ placeholder: '/' }).depends({ tcp_guise: 'http' });

		o = S.add('ListValue', 'mkcp_guise', _('Camouflage Type'), _('<br />none: default, no masquerade, data sent is packets with no characteristics.<br />srtp: disguised as an SRTP packet, it will be recognized as video call data (such as FaceTime).<br />utp: packets disguised as uTP will be recognized as bittorrent downloaded data.<br />wechat-video: packets disguised as WeChat video calls.<br />dtls: disguised as DTLS 1.2 packet.<br />wireguard: disguised as a WireGuard packet. (not really WireGuard protocol)<br />dns: Disguising traffic as DNS requests.'));
		MKCP_HEADERS.forEach(function(h) { o.value(h); });
		o.depends({ transport: 'mkcp' });
		S.add('Value', 'mkcp_domain', _('Camouflage Domain'), _('Use it together with the DNS disguised type. You can fill in any domain.')).depends({ mkcp_guise: 'dns' });
		S.add('Value', 'mkcp_mtu', _('KCP MTU')).set({ datatype: 'uinteger', default: '1350' }).depends({ transport: 'mkcp' });
		S.add('Value', 'mkcp_seed', _('KCP Seed')).depends({ transport: 'mkcp' });

		S.add('Value', 'ws_host', _('WebSocket Host')).depends({ transport: 'ws' });
		S.add('Value', 'ws_path', _('WebSocket Path')).set({ placeholder: '/' }).depends({ transport: 'ws' });
		S.add('Value', 'ws_heartbeatPeriod', _('HeartbeatPeriod(second)')).set({ datatype: 'integer' }).depends({ transport: 'ws' });

		S.add('Value', 'grpc_serviceName', 'ServiceName').depends({ transport: 'grpc' });
		o = S.add('ListValue', 'grpc_mode', 'gRPC ' + _('Transfer mode'));
		o.value('gun'); o.value('multi');
		o.depends({ transport: 'grpc' });
		S.add('Flag', 'grpc_health_check', _('Health check')).depends({ transport: 'grpc' });
		S.add('Value', 'grpc_idle_timeout', _('Idle timeout')).set({ default: '10' }).depends({ grpc_health_check: true });
		S.add('Value', 'grpc_health_check_timeout', _('Health check timeout')).set({ default: '20' }).depends({ grpc_health_check: true });
		S.add('Flag', 'grpc_permit_without_stream', _('Permit without stream')).set({ default: '0' }).depends({ grpc_health_check: true });
		S.add('Value', 'grpc_initial_windows_size', _('Initial Windows Size')).set({ default: '0' }).depends({ transport: 'grpc' });

		S.add('Value', 'httpupgrade_host', _('HttpUpgrade Host')).depends({ transport: 'httpupgrade' });
		S.add('Value', 'httpupgrade_path', _('HttpUpgrade Path')).set({ placeholder: '/' }).depends({ transport: 'httpupgrade' });

		o = S.add('ListValue', 'xhttp_mode', 'XHTTP ' + _('Mode'));
		o.depends({ transport: 'xhttp' });
		o.set({ default: 'auto' });
		['auto', 'packet-up', 'stream-up', 'stream-one'].forEach(function(m) { o.value(m); });
		S.add('Value', 'xhttp_host', _('XHTTP Host')).depends({ transport: 'xhttp' });
		S.add('Value', 'xhttp_path', _('XHTTP Path')).set({ placeholder: '/' }).depends({ transport: 'xhttp' });
		S.add('Flag', 'use_xhttp_extra', _('XHTTP Extra')).set({ default: '0' }).depends({ transport: 'xhttp' });
		o = S.add('TextValue', 'xhttp_extra', '　', _('An XHttpObject in JSON format, used for sharing.'));
		o.depends({ use_xhttp_extra: true });
		o.set({ rows: 10, wrap: 'off', enc: 'b64json', sideEffect: 'download_address', validate: function(v) {
			return isJsonObject(normJsonText(v)) ? true : 'XHTTP Extra ' + _('Must be JSON text!');
		} });

		addUserAgent(S, [{ tcp_guise: 'http' }, { transport: 'ws' }, { transport: 'httpupgrade' }, { transport: 'xhttp' }, { transport: 'grpc' }, { protocol: 'masque' }]);

		o = S.add('Flag', 'mux', 'Mux', _('Enable Mux.Cool'));
		o.depends({ protocol: 'vmess' });
		['raw', 'ws', 'grpc', 'httpupgrade'].forEach(function(t) { o.depends({ protocol: 'vless', transport: t }); });
		['http', 'socks', 'shadowsocks', 'trojan'].forEach(function(p) { o.depends({ protocol: p }); });
		S.add('Value', 'mux_concurrency', _('Mux concurrency')).set({ default: '-1' }).depends({ mux: true });
		S.add('Value', 'xudp_concurrency', _('XUDP Mux concurrency')).set({ default: '8' }).depends({ mux: true });

		o = S.add('Flag', 'use_finalmask', 'FinalMask').set({ default: '0' });
		['vmess', 'vless', 'trojan', 'shadowsocks', 'wireguard'].forEach(function(p) { o.depends({ protocol: p }); });
		o.depends({ protocol: 'hysteria2', hysteria2_realms: false });
		o.depends({ protocol: 'masque' });
		addFinalMaskText(S);

		S.add('Flag', 'tcp_fast_open', 'TCP ' + _('Fast Open'), _('Need node support required')).set({ default: '0' });
		S.add('Flag', 'tcpMptcp', 'tcpMptcp', _('Enable Multipath TCP, need to be enabled in both server and client configuration.')).set({ default: '0' });

		addDomainResolver(S);

		o = S.add('ListValue', 'domain_strategy', _('Domain Strategy'), _('If is domain name, The requested domain name will be resolved to IP before connect.'));
		o.set({ default: '' });
		o.value('', _('Auto'));
		o.value('UseIPv4', _('IPv4 Only'));
		o.value('UseIPv6', _('IPv6 Only'));

		S.add('Flag', 'happy_eyeballs', _('Enable Happy Eyeballs'), _('Attempts IPv4 and IPv6 simultaneously; automatically uses the faster connection.')).set({ default: '0' });

		protocols.forEach(function(v) {
			if (v.charAt(0) == '_') return;
			var cond = { protocol: v };
			if (v == 'hysteria2') cond.hysteria2_realms = false;
			S.get('address').depends(cond);
			S.get('port').depends(cond);
			S.get('domain_resolver').depends(cond);
			S.get('happy_eyeballs').depends(cond);
			S.get('domain_strategy').depends(Object.assign({}, cond, { happy_eyeballs: false }));
			if (v != 'hysteria2') {
				S.get('tcp_fast_open').depends({ protocol: v });
				S.get('tcpMptcp').depends({ protocol: v });
			}
		});
	}

	if (kind != '_shunt')
		addChain(S, ctx, kind == '_iface' || kind == '_balancing');
}

/* ---- sing-box (client/type/1_sing-box.lua) */
function singboxSpecs(S, ctx) {
	var env = ctx.env, tag = env.hasTag;
	var o = S.add('ListValue', 'protocol', _('Protocol'));
	o.value('socks', 'Socks');
	o.value('http', 'HTTP');
	o.value('shadowsocks', 'Shadowsocks');
	if (tag('with_shadowsocksr')) o.value('shadowsocksr', 'ShadowsocksR');
	o.value('vmess', 'Vmess');
	o.value('trojan', 'Trojan');
	if (tag('with_wireguard')) o.value('wireguard', 'WireGuard');
	if (tag('with_quic')) o.value('hysteria', 'Hysteria');
	o.value('vless', 'VLESS');
	if (tag('with_quic')) o.value('tuic', 'TUIC');
	if (tag('with_quic')) o.value('hysteria2', 'Hysteria2');
	o.value('anytls', 'AnyTLS');
	o.value('ssh', 'SSH');
	if (tag('with_naive_outbound')) o.value('naive', 'NaïveProxy');
	if (env.ge114) o.value('snell', 'Snell');
	if (env.ge115 && tag('with_quic')) o.value('masque', 'MASQUE');
	o.value('_urltest', _('URLTest'));
	o.value('_shunt', _('Shunt'));
	o.value('_iface', _('Custom Interface'));
	o.set({ kindSwitch: true });
	var protocols = o.values.map(function(v) { return v[0]; });
	var kind = ctx.kind;

	if (kind == '_urltest') {
		addNodeSelection(S, ctx, 'urltest_node', _('URLTest node list'),
			_('List of nodes to test, <a target=\'_blank\' href=\'https://sing-box.sagernet.org/configuration/outbound/urltest\'>document</a>'), '_urltest');
		o = addProbeUrl(S, 'urltest_url');
		o.depends({ protocol: '_urltest' });

		o = S.add('Value', 'urltest_interval', _('Test interval'));
		o.depends({ protocol: '_urltest' });
		o.set({ default: '3m', placeholder: '3m' });
		o.desc = _('The interval between initiating probes.') + '<br>' + timeDesc() + '<br>' + _('Test interval must be less or equal than idle timeout.');

		o = S.add('Value', 'urltest_tolerance', _('Test tolerance'), _('The test tolerance in milliseconds.'));
		o.depends({ protocol: '_urltest' });
		o.set({ datatype: 'uinteger', placeholder: '50', default: '50' });

		o = S.add('Value', 'urltest_idle_timeout', _('Idle timeout'));
		o.depends({ protocol: '_urltest' });
		o.set({ placeholder: '30m', default: '30m' });
		o.desc = _('The idle timeout.') + '<br>' + timeDesc();

		o = S.add('Flag', 'urltest_interrupt_exist_connections', _('Interrupt existing connections'));
		o.depends({ protocol: '_urltest' });
		o.set({ default: '0' });
		o.desc = _('Interrupt existing connections when the selected outbound has changed.');
	}

	if (kind == '_iface') {
		o = S.add('Value', 'iface', _('Interface'));
		o.depends({ protocol: '_iface' });
		env.netdevs.forEach(function(d) { o.value(d.name, d.label); });
	}

	if (kind == 'normal') {
		S.add('Value', 'address', _('Address (Support Domain Name)'));
		S.add('Value', 'port', _('Port')).set({ datatype: 'port' });

		o = S.add('Value', 'uuid', _('ID')).set({ password: true });
		['vmess', 'vless', 'tuic'].forEach(function(p) { o.depends({ protocol: p }); });
		o = S.add('Value', 'username', _('Username'));
		['http', 'socks', 'ssh', 'naive', 'masque'].forEach(function(p) { o.depends({ protocol: p }); });
		o = S.add('Value', 'password', _('Password')).set({ password: true });
		['http', 'socks', 'shadowsocks', 'shadowsocksr', 'trojan', 'tuic', 'anytls', 'ssh', 'naive', 'masque'].forEach(function(p) { o.depends({ protocol: p }); });

		S.add('Value', 'masque_path', _('MASQUE Path')).depends({ protocol: 'masque' });
		o = S.add('TextValue', 'masque_headers', _('Custom HTTP Headers'));
		o.set({ rows: 5, wrap: 'off', enc: 'escnl', validate: function(v) { return validateHeaders(v, false); } });
		o.depends({ protocol: 'masque' });

		if (env.ge114) {
			S.get('password').depends({ protocol: 'snell' });
			S.add('Value', 'snell_psk', _('Pre shared key')).set({ rmempty: false }).depends({ protocol: 'snell' });
			o = S.add('ListValue', 'snell_version', _('Version'));
			o.value('4'); o.value('6');
			o.depends({ protocol: 'snell' });
			S.add('Flag', 'snell_reuse', _('reuse')).depends({ protocol: 'snell' });
			o = S.add('ListValue', 'snell_network', _('Transport'));
			o.value('', 'TCP UDP'); o.value('tcp', 'TCP'); o.value('udp', 'UDP');
			o.depends({ protocol: 'snell' });
			o = S.add('ListValue', 'snell_obfs_mode', _('Camouflage Type'));
			o.value('none'); o.value('http');
			o.depends({ protocol: 'snell', snell_version: '4' });
			S.add('Value', 'snell_obfs_host', _('HTTP Host')).depends({ protocol: 'snell', snell_version: '4', snell_obfs_mode: 'http' });
			o = S.add('ListValue', 'snell_mode', _('Mode'));
			o.value('default'); o.value('unshaped'); o.value('unsafe-raw');
			o.depends({ protocol: 'snell', snell_version: '6' });
		}

		o = S.add('ListValue', 'security', _('Encrypt Method'));
		SB_VMESS_SECURITY.forEach(function(t) { o.value(t); });
		o.depends({ protocol: 'vmess' });

		o = S.add('ListValue', 'ss_method', _('Encrypt Method'));
		SB_SS_NEW.concat(SB_SS_OLD).forEach(function(t) { o.value(t); });
		o.depends({ protocol: 'shadowsocks' });

		if (tag('with_shadowsocksr')) {
			o = S.add('ListValue', 'ssr_method', _('Encrypt Method'));
			SB_SS_OLD.forEach(function(t) { o.value(t); });
			o.depends({ protocol: 'shadowsocksr' });
			o = S.add('ListValue', 'ssr_protocol', _('Protocol'));
			SSR_PROTOCOLS.forEach(function(t) { o.value(t); });
			o.depends({ protocol: 'shadowsocksr' });
			S.add('Value', 'ssr_protocol_param', _('Protocol_param')).depends({ protocol: 'shadowsocksr' });
			o = S.add('ListValue', 'ssr_obfs', _('Obfs'));
			SSR_OBFS.forEach(function(t) { o.value(t); });
			o.depends({ protocol: 'shadowsocksr' });
			S.add('Value', 'ssr_obfs_param', _('Obfs_param')).depends({ protocol: 'shadowsocksr' });
		}

		o = S.add('Flag', 'uot', _('UDP over TCP'));
		['socks', 'shadowsocks', 'naive'].forEach(function(p) { o.depends({ protocol: p }); });

		S.add('Value', 'alter_id', 'Alter ID').set({ datatype: 'uinteger', default: '0' }).depends({ protocol: 'vmess' });
		S.add('Flag', 'global_padding', 'global_padding', _('Protocol parameter. Will waste traffic randomly if enabled.')).set({ default: '0' }).depends({ protocol: 'vmess' });
		S.add('Flag', 'authenticated_length', 'authenticated_length', _('Protocol parameter. Enable length block encryption.')).set({ default: '0' }).depends({ protocol: 'vmess' });

		o = S.add('ListValue', 'flow', _('flow')).set({ default: '' });
		o.value('', _('Disable'));
		o.value('xtls-rprx-vision');
		o.depends({ protocol: 'vless', tls: true });

		if (tag('with_quic')) {
			S.add('Value', 'hysteria_hop', _('Port hopping range'), _('Format as 1000:2000 or 1000-2000 Multiple groups are separated by commas (,).')).depends({ protocol: 'hysteria' });
			S.add('Value', 'hysteria_hop_interval', _('Hop Interval(second)'), _('Example:') + '30 (≥5)').set({ datatype: 'uinteger', placeholder: '30', default: '30' }).depends({ protocol: 'hysteria' });
			S.add('Value', 'hysteria_obfs', _('Obfs Password')).depends({ protocol: 'hysteria' });
			o = S.add('ListValue', 'hysteria_auth_type', _('Auth Type'));
			o.value('disable', _('Disable')); o.value('string', _('STRING')); o.value('base64', _('BASE64'));
			o.depends({ protocol: 'hysteria' });
			o = S.add('Value', 'hysteria_auth_password', _('Auth Password')).set({ password: true });
			o.depends({ protocol: 'hysteria', hysteria_auth_type: 'string' });
			o.depends({ protocol: 'hysteria', hysteria_auth_type: 'base64' });
			S.add('Value', 'hysteria_up_mbps', _('Max upload Mbps')).set({ default: '10' }).depends({ protocol: 'hysteria' });
			S.add('Value', 'hysteria_down_mbps', _('Max download Mbps')).set({ default: '50' }).depends({ protocol: 'hysteria' });
			S.add('Value', 'hysteria_recv_window_conn', _('QUIC stream receive window')).depends({ protocol: 'hysteria' });
			S.add('Value', 'hysteria_recv_window', _('QUIC connection receive window')).depends({ protocol: 'hysteria' });
			S.add('Flag', 'hysteria_disable_mtu_discovery', _('Disable MTU detection')).depends({ protocol: 'hysteria' });

			o = S.add('ListValue', 'tuic_congestion_control', _('Congestion control algorithm')).set({ default: 'cubic' });
			o.value('bbr', _('BBR')); o.value('cubic', _('CUBIC')); o.value('new_reno', _('New Reno'));
			o.depends({ protocol: 'tuic' });
			o = S.add('ListValue', 'tuic_udp_relay_mode', _('UDP relay mode')).set({ default: 'native' });
			o.value('native', _('native')); o.value('quic', _('QUIC'));
			o.depends({ protocol: 'tuic' });
			S.add('Flag', 'tuic_zero_rtt_handshake', _('Enable 0-RTT QUIC handshake')).set({ default: '0' }).depends({ protocol: 'tuic' });
			S.add('Value', 'tuic_heartbeat', _('Heartbeat interval(second)')).set({ datatype: 'uinteger', default: '3' }).depends({ protocol: 'tuic' });
			addAlpn(S, 'tuic_alpn', _('QUIC TLS ALPN'), ['spdy/3.1', 'h3,spdy/3.1'], [{ protocol: 'tuic' }]);

			addHy2Common(S, env.ge114 ? { protocol: 'hysteria2' } : { protocol: '__hide' });
		}

		o = S.add('TextValue', 'ssh_priv_key', _('Private Key'));
		o.set({ rows: 5, wrap: 'off', enc: 'sshkey' });
		o.depends({ protocol: 'ssh' });
		S.add('Value', 'ssh_priv_key_pp', _('Private Key Passphrase')).set({ password: true }).depends({ protocol: 'ssh' });
		S.add('DynamicList', 'ssh_host_key', _('Host Key'), _('Accept any if empty.')).depends({ protocol: 'ssh' });
		S.add('DynamicList', 'ssh_host_key_algo', _('Host Key Algorithms')).depends({ protocol: 'ssh' });
		S.add('Value', 'ssh_client_version', _('Client Version'), _('Random version will be used if empty.')).depends({ protocol: 'ssh' });

		S.add('Value', 'naive_insecure_concurrency', _('Concurrent Tunnels')).set({ datatype: 'uinteger', placeholder: '0', default: '0' }).depends({ protocol: 'naive' });
		S.add('Flag', 'naive_quic', _('QUIC')).set({ default: '0' }).depends({ protocol: 'naive' });
		o = S.add('ListValue', 'naive_congestion_control', _('Congestion control algorithm')).set({ default: 'bbr' });
		o.value('bbr', _('BBR')); o.value('bbr2', _('BBRv2')); o.value('cubic', _('CUBIC')); o.value('reno', _('New Reno'));
		o.depends({ naive_quic: '1' });

		o = S.add('Flag', 'tls', _('TLS')).set({ default: '0' });
		['vmess', 'vless', 'http', 'trojan', 'shadowsocks', 'anytls'].forEach(function(p) { o.depends({ protocol: p }); });

		addAlpn(S, 'alpn', _('ALPN'), [], [{ tls: true }, { protocol: 'hysteria' }]);

		var quicTls = ['hysteria', 'tuic', 'hysteria2', 'masque'];
		o = S.add('Flag', 'tls_disable_sni', _('Disable SNI'), _('Do not send server name in ClientHello.')).set({ default: '0' });
		o.depends({ tls: true }); quicTls.forEach(function(p) { o.depends({ protocol: p }); });
		o = S.add('Value', 'tls_serverName', 'SNI ' + _('Domain'));
		o.depends({ tls: true }); ['hysteria', 'tuic', 'hysteria2', 'naive', 'masque'].forEach(function(p) { o.depends({ protocol: p }); });
		o = S.add('Flag', 'tls_allowInsecure', _('allowInsecure'), _('Whether unsafe connections are allowed. When checked, Certificate validation will be skipped.')).set({ default: '0' });
		o.depends({ tls: true }); quicTls.forEach(function(p) { o.depends({ protocol: p }); });
		o = S.add('Value', 'tls_pinSHA256', _('TLS Chain Fingerprint (SHA256)'), pinDesc());
		o.depends({ tls: true }); quicTls.forEach(function(p) { o.depends({ protocol: p }); });
		o = S.add('Flag', 'tls_certificate', _('TLS Certificate (PEM)')).set({ default: '0' });
		o.depends({ tls: true, reality: false }); ['hysteria', 'tuic', 'hysteria2', 'naive', 'masque'].forEach(function(p) { o.depends({ protocol: p }); });
		addPemCert(S);
		addCipherSuites(S, [{ tls: true }, { protocol: 'masque' }]);

		o = S.add('Flag', 'ech', _('ECH')).set({ default: '0' });
		o.depends({ tls: true, flow: '', reality: false });
		o.depends({ protocol: 'tuic' }); o.depends({ protocol: 'hysteria' });
		o.depends({ protocol: 'hysteria2', hysteria2_realms: false });
		o.depends({ protocol: 'naive' }); o.depends({ protocol: 'masque' });
		o = S.add('TextValue', 'ech_config', _('ECH Config'));
		o.set({ default: '', rows: 5, wrap: 'off', enc: 'pem' });
		o.depends({ ech: true });
		S.add('Value', 'ech_query_server_name', _('ECH Query Domain'), _('Overrides the domain name used for ECH HTTPS record queries.')).depends({ ech: true });

		if (tag('with_utls')) {
			S.add('Flag', 'utls', _('uTLS')).set({ default: '0' }).depends({ tls: true });
			o = S.add('ListValue', 'fingerprint', _('Finger Print'));
			FP_SB.forEach(function(f) { o.value(f); });
			o.set({ default: 'chrome' });
			o.depends({ utls: true });
			o = S.add('Flag', 'reality', _('REALITY')).set({ default: '0' });
			['vless', 'vmess', 'shadowsocks', 'socks', 'trojan', 'anytls', 'http'].forEach(function(p) { o.depends({ protocol: p, tls: true }); });
			S.add('Value', 'reality_publicKey', _('Public Key')).depends({ reality: true });
			S.add('Value', 'reality_shortId', _('Short Id')).depends({ reality: true });
		}

		S.add('Flag', 'anytls_disable_reuse', _('Disable TLS Reuse')).set({ default: '0' }).depends({ protocol: 'anytls' });

		o = S.add('ListValue', 'transport', _('Transport'));
		o.value('tcp', 'TCP'); o.value('http', 'HTTP'); o.value('ws', 'WebSocket'); o.value('httpupgrade', 'HTTPUpgrade');
		if (tag('with_quic')) o.value('quic', 'QUIC');
		o.value('grpc', tag('with_grpc') ? 'gRPC' : 'gRPC-lite');
		['vmess', 'vless', 'socks', 'shadowsocks', 'trojan'].forEach(function(p) { o.depends({ protocol: p }); });

		if (tag('with_wireguard')) {
			S.add('Value', 'wireguard_public_key', _('Public Key')).depends({ protocol: 'wireguard' });
			S.add('Value', 'wireguard_secret_key', _('Private Key')).depends({ protocol: 'wireguard' });
			S.add('Value', 'wireguard_preSharedKey', _('Pre shared key')).depends({ protocol: 'wireguard' });
			S.add('DynamicList', 'wireguard_local_address', _('Local Address')).depends({ protocol: 'wireguard' });
			S.add('Value', 'wireguard_mtu', _('MTU')).set({ default: '1420' }).depends({ protocol: 'wireguard' });
			S.add('Flag', 'wireguard_system_interface', _('System interface')).set({ default: '0' }).depends({ protocol: 'wireguard' });
			S.add('Value', 'wireguard_interface_name', _('System interface name')).depends({ protocol: 'wireguard' });
			S.add('Value', 'wireguard_reserved', _('Reserved'), _('Decimal numbers separated by "," or Base64-encoded strings.')).depends({ protocol: 'wireguard' });
		}

		o = S.add('ListValue', 'tcp_guise', _('Camouflage Type'));
		o.value('none', 'none'); o.value('http', 'http');
		o.depends({ transport: 'tcp' });
		S.add('DynamicList', 'tcp_guise_http_host', _('HTTP Host')).depends({ tcp_guise: 'http' });
		S.add('DynamicList', 'tcp_guise_http_path', _('HTTP Path')).set({ placeholder: '/' }).depends({ tcp_guise: 'http' });

		S.add('DynamicList', 'http_host', _('HTTP Host')).depends({ transport: 'http' });
		S.add('Value', 'http_path', _('HTTP Path')).set({ placeholder: '/' }).depends({ transport: 'http' });
		S.add('Flag', 'http_h2_health_check', _('Health check')).depends({ tls: true, transport: 'http' });
		S.add('Value', 'http_h2_read_idle_timeout', _('Idle timeout')).set({ default: '15' }).depends({ http_h2_health_check: true });
		S.add('Value', 'http_h2_health_check_timeout', _('Health check timeout')).set({ default: '15' }).depends({ http_h2_health_check: true });

		S.add('Value', 'ws_host', _('WebSocket Host')).depends({ transport: 'ws' });
		S.add('Value', 'ws_path', _('WebSocket Path')).set({ placeholder: '/' }).depends({ transport: 'ws' });
		S.add('Flag', 'ws_enableEarlyData', _('Enable early data')).depends({ transport: 'ws' });
		S.add('Value', 'ws_maxEarlyData', _('Early data length')).set({ default: '1024' }).depends({ ws_enableEarlyData: true });
		S.add('Value', 'ws_earlyDataHeaderName', _('Early data header name'), _('Recommended value: Sec-WebSocket-Protocol')).depends({ ws_enableEarlyData: true });

		S.add('Value', 'httpupgrade_host', _('HTTPUpgrade Host')).depends({ transport: 'httpupgrade' });
		S.add('Value', 'httpupgrade_path', _('HTTPUpgrade Path')).set({ placeholder: '/' }).depends({ transport: 'httpupgrade' });

		S.add('Value', 'grpc_serviceName', 'ServiceName').depends({ transport: 'grpc' });
		S.add('Flag', 'grpc_health_check', _('Health check')).depends({ transport: 'grpc' });
		S.add('Value', 'grpc_idle_timeout', _('Idle timeout')).set({ default: '15' }).depends({ grpc_health_check: true });
		S.add('Value', 'grpc_health_check_timeout', _('Health check timeout')).set({ default: '15' }).depends({ grpc_health_check: true });
		S.add('Flag', 'grpc_permit_without_stream', _('Permit without stream')).set({ default: '0' }).depends({ grpc_health_check: true });

		addUserAgent(S, [{ tcp_guise: 'http' }, { transport: 'http' }, { transport: 'ws' }, { transport: 'httpupgrade' }, { protocol: 'naive' }, { protocol: 'masque' }]);

		o = S.add('Flag', 'mux', _('Mux')).set({ rmempty: false });
		o.depends({ protocol: 'vmess' }); o.depends({ protocol: 'vless', flow: '' });
		o.depends({ protocol: 'shadowsocks', uot: '' }); o.depends({ protocol: 'trojan' });
		o = S.add('ListValue', 'mux_type', _('Mux'));
		o.value('smux'); o.value('yamux'); o.value('h2mux');
		o.depends({ mux: true });
		S.add('Value', 'mux_concurrency', _('Mux concurrency')).set({ default: '4' }).depends({ mux: true, tcpbrutal: false });
		S.add('Flag', 'mux_padding', _('Padding')).set({ default: '0' }).depends({ mux: true });
		S.add('Flag', 'tcpbrutal', _('TCP Brutal')).set({ default: '0' }).depends({ mux: true });
		S.add('Value', 'tcpbrutal_up_mbps', _('Max upload Mbps')).set({ default: '10' }).depends({ tcpbrutal: true });
		S.add('Value', 'tcpbrutal_down_mbps', _('Max download Mbps')).set({ default: '50' }).depends({ tcpbrutal: true });

		o = S.add('Flag', 'shadowtls', 'ShadowTLS').set({ default: '0' });
		o.depends({ protocol: 'vmess', tls: false }); o.depends({ protocol: 'shadowsocks', tls: false });
		o = S.add('ListValue', 'shadowtls_version', 'ShadowTLS ' + _('Version')).set({ default: '1' });
		o.value('1', 'ShadowTLS v1'); o.value('2', 'ShadowTLS v2'); o.value('3', 'ShadowTLS v3');
		o.depends({ shadowtls: true });
		o = S.add('Value', 'shadowtls_password', 'ShadowTLS ' + _('Password')).set({ password: true });
		o.depends({ shadowtls: true, shadowtls_version: '2' }); o.depends({ shadowtls: true, shadowtls_version: '3' });
		S.add('Value', 'shadowtls_serverName', 'ShadowTLS ' + _('Domain')).depends({ shadowtls: true });
		if (tag('with_utls')) {
			S.add('Flag', 'shadowtls_utls', 'ShadowTLS ' + _('uTLS')).set({ default: '0' }).depends({ shadowtls: true });
			o = S.add('ListValue', 'shadowtls_fingerprint', 'ShadowTLS ' + _('Finger Print'));
			['chrome', 'firefox', 'edge', 'safari', 'qq', 'ios', 'random'].forEach(function(f) { o.value(f); });
			o.set({ default: 'chrome' });
			o.depends({ shadowtls: true, shadowtls_utls: true });
		}

		S.add('Flag', 'plugin_enabled', _('plugin')).set({ default: '0' }).depends({ protocol: 'shadowsocks' });
		o = S.add('ListValue', 'plugin', 'SIP003 ' + _('plugin')).set({ default: 'obfs-local' });
		o.depends({ plugin_enabled: true });
		o.value('obfs-local'); o.value('v2ray-plugin');
		S.add('Value', 'plugin_opts', _('opts')).depends({ plugin_enabled: true });

		addDomainResolver(S);
		o = S.add('ListValue', 'domain_strategy', _('Domain Strategy'), _('If is domain name, The requested domain name will be resolved to IP before connect.'));
		o.set({ default: '' });
		o.value('', _('Auto'));
		o.value('prefer_ipv4', _('Prefer IPv4'));
		o.value('prefer_ipv6', _('Prefer IPv6'));
		o.value('ipv4_only', _('IPv4 Only'));
		o.value('ipv6_only', _('IPv6 Only'));

		protocols.forEach(function(v) {
			if (v.charAt(0) == '_') return;
			var cond = { protocol: v };
			if (v == 'hysteria2') cond.hysteria2_realms = false;
			S.get('address').depends(cond);
			S.get('port').depends(cond);
			S.get('domain_resolver').depends(cond);
			S.get('domain_strategy').depends(cond);
		});
	}

	if (kind != '_shunt')
		addChain(S, ctx, kind == '_iface' || kind == '_urltest');
}

/* ---- SS-Rust (client/type/3_ss-rust.lua) */
function ssrustSpecs(S, ctx) {
	S.add('Value', 'address', _('Address (Support Domain Name)'));
	S.add('Value', 'port', _('Port')).set({ datatype: 'port' });
	S.add('Value', 'password', _('Password')).set({ password: true });
	var o = S.add('Value', 'method', _('Encrypt Method'));
	SSRUST_METHODS.forEach(function(t) { o.value(t); });
	S.add('Value', 'timeout', _('Connection Timeout')).set({ datatype: 'uinteger', default: '300' });
	S.add('Flag', 'tcp_fast_open', 'TCP ' + _('Fast Open'), _('Need node support required')).set({ default: '0' });
	S.add('Flag', 'plugin_enabled', _('plugin')).set({ default: '0' });
	o = S.add('Value', 'plugin', 'SIP003 ' + _('plugin'), _('Supports custom SIP003 plugins, Make sure the plugin is installed.'));
	o.set({ default: 'none', enc: 'plugin', bins: ctx.env.bins });
	o.value('none', _('none'));
	ctx.env.plugins.forEach(function(p) { o.value(p); });
	o.depends({ plugin_enabled: true });
	o.validate = function(v) {
		if (v && v !== '' && v !== 'none' && !ctx.env.bins[v])
			return v + ': ' + _('Can\'t find this file!');
		return true;
	};
	S.add('Value', 'plugin_opts', _('opts')).depends({ plugin_enabled: true });
}

/* ---- SSR (client/type/4_ssr.lua) */
function ssrSpecs(S, ctx) {
	S.add('Value', 'address', _('Address (Support Domain Name)'));
	S.add('Value', 'port', _('Port')).set({ datatype: 'port' });
	S.add('Value', 'password', _('Password')).set({ password: true });
	var o = S.add('ListValue', 'method', _('Encrypt Method'));
	SSR_METHODS.forEach(function(t) { o.value(t); });
	o = S.add('ListValue', 'protocol', _('Protocol'));
	SSR_PROTOCOLS.forEach(function(t) { o.value(t); });
	S.add('Value', 'protocol_param', _('Protocol_param'));
	o = S.add('ListValue', 'obfs', _('Obfs'));
	SSR_OBFS.forEach(function(t) { o.value(t); });
	S.add('Value', 'obfs_param', _('Obfs_param'));
	S.add('Value', 'timeout', _('Connection Timeout')).set({ datatype: 'uinteger', default: '300' });
	S.add('Flag', 'tcp_fast_open', 'TCP ' + _('Fast Open'), _('Need node support required')).set({ default: '0' });
}

/* ---- _shunt node options (client/include/shunt_options.lua, verify_option = nil) */
function shuntSpecs(S, ctx, typeName) {
	var o;
	if (typeName == 'Xray') {
		o = S.add('ListValue', 'domainStrategy', _('Domain Strategy'));
		o.value('AsIs'); o.value('IPIfNonMatch'); o.value('IPOnDemand');
		o.set({ default: 'IPOnDemand' });
		o.desc = '<br /><ul><li>' + _('\'AsIs\': Only use domain for routing. Default value.') +
			'</li><li>' + _('\'IPIfNonMatch\': When no rule matches current domain, resolves it into IP addresses (A or AAAA records) and try all rules again.') +
			'</li><li>' + _('\'IPOnDemand\': As long as there is a IP-based rule, resolves the domain into IP immediately.') + '</li></ul>';
		o = S.add('ListValue', 'domainMatcher', _('Domain matcher'));
		o.value('hybrid'); o.value('linear');
	}
	S.add('Flag', 'fakedns', '<a style="color:#FF8C00">FakeDNS</a> ' + _('Main switch'),
		_('Use FakeDNS work in the domain that proxy.') + '<br>' + _('Suitable scenarios for let the node servers get the target domain names.') + '<br>' +
		_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.'));
	S.add('Flag', 'write_ipset_direct', _('Direct DNS result write to IPSet'),
		_('Perform the matching direct domain name rules into IP to IPSet/NFTSet, and then connect directly (not entering the core).') + ' ' + _('Maybe conflict with some special circumstances.'))
		.set({ default: '1', rmempty: false });
	if (ctx.env.has_geoview) {
		S.add('Flag', 'enable_geoview_ip', _('Enable GeoIP Data Parsing'),
			'<ul><li>' + _('Analyzes and preloads GeoIP data to enhance the shunt performance.') + '</li><li>' +
			_('Note: Increases resource usage.') + ' ' + _('Maybe conflict with some special circumstances.') + '</li></ul>')
			.set({ default: '1', rmempty: false, flushOnChange: true });
	}
	o = S.add('ListValue', 'shunt_group', _('Shunt Rule Group'));
	o.value('', _('default'));
	var groups = {};
	uci.sections(CONF, 'shunt_rules').forEach(function(r) { if (r.group && r.group !== '') groups[r.group] = true; });
	Object.keys(groups).forEach(function(g) { o.value(g); });
	o.set({ shuntGroupSwitch: true });
	S.add('ShuntTable', '_shunt_table', ' ');
}

/* Returns the spec list for a node of `type` whose protocol kind is `kind`
 * ('normal' | '_balancing' | '_urltest' | '_shunt' | '_iface'). */
function getSpecs(type, ctx) {
	var S = new SpecList();
	if (type == 'sing-box') singboxSpecs(S, ctx);
	else if (type == 'Xray') xraySpecs(S, ctx);
	else if (type == 'SS-Rust') ssrustSpecs(S, ctx);
	else if (type == 'SSR') ssrSpecs(S, ctx);
	if ((type == 'sing-box' || type == 'Xray') && ctx.kind == '_shunt')
		shuntSpecs(S, ctx, type);
	return S;
}

function protocolKind(type, protocol) {
	if (type != 'sing-box' && type != 'Xray') return 'normal';
	if (type == 'Xray' && protocol == '_balancing') return '_balancing';
	if (type == 'sing-box' && protocol == '_urltest') return '_urltest';
	if (protocol == '_shunt') return '_shunt';
	if (protocol == '_iface') return '_iface';
	return 'normal';
}

function availableTypes(env) {
	var t = [];
	if (env.has_singbox) t.push(['sing-box', 'Sing-Box']);
	if (env.has_xray) t.push(['Xray', 'Xray']);
	if (env.has_sslocal) t.push(['SS-Rust', 'Shadowsocks Rust']);
	if (env.has_ssr_local) t.push(['SSR', 'ShadowsocksR Libev']);
	return t;
}

function makeCtx(env, sid, kind) {
	var groups = {};
	uci.sections(CONF, 'nodes').forEach(function(s) {
		if (s['.name'] != sid && s.group && s.group !== '') groups[s.group] = true;
	});
	return { env: env, sid: sid, kind: kind, nodeList: getNodeList(), groups: Object.keys(groups) };
}

/* -------------------------------------------- dependency evaluation helpers */

function depNorm(v) {
	if (v === true) return '1';
	if (v === false) return '';
	return v == null ? '' : String(v);
}

function depsSatisfied(deps, lookup) {
	if (!deps || !deps.length) return true;
	for (var i = 0; i < deps.length; i++) {
		var ok = true;
		for (var k in deps[i]) {
			if (lookup(k) !== depNorm(deps[i][k])) { ok = false; break; }
		}
		if (ok) return true;
	}
	return false;
}

/* Virtual form: which options would be visible for stored `data` and what they would show.
 * Returns get(name) -> null | {checkbox, checked, value} as expected by sharelink.buildUrl. */
function virtualForm(S, data) {
	var active = {}, cur = {};
	var stored = function(sp) {
		var v = data[sp.name];
		if (sp.enc && ENC[sp.enc] && v != null && !Array.isArray(v)) v = ENC[sp.enc].decode(v);
		if (sp.name == 'node_group' && v != null) v = toArray(v);
		if (v == null || (Array.isArray(v) && !v.length && sp.cls != 'DynamicList')) {
			if (sp.cls == 'Flag') v = sp.default != null ? String(sp.default) : '0';
			else if (sp.default != null) v = sp.default;
			else if (sp.cls == 'ListValue' && sp.values.length) v = sp.values[0][0];
			else v = '';
		}
		return v;
	};
	S.list.forEach(function(sp) { cur[sp.name] = stored(sp); });
	var lookup = function(k) {
		var sp = S.map[k];
		if (!sp || !active[k]) return '';
		var v = cur[k];
		if (sp.cls == 'Flag') return v == '1' ? '1' : '';
		if (Array.isArray(v)) return v.join(' ');
		return v == null ? '' : String(v);
	};
	for (var pass = 0; pass < 12; pass++) {
		var changed = false;
		S.list.forEach(function(sp) {
			var a = depsSatisfied(sp.deps, lookup);
			if (active[sp.name] !== a) { active[sp.name] = a; changed = true; }
		});
		if (!changed) break;
	}
	return function(name) {
		var sp = S.map[name];
		if (!sp || !active[name]) return null;
		var v = cur[name];
		if (sp.cls == 'Flag') return { checkbox: true, checked: v == '1', value: v };
		if (Array.isArray(v)) v = v.length ? v[0] : '';
		return { checkbox: false, checked: false, value: v == null ? '' : String(v) };
	};
}

/* ---------------------------------------------------------- custom widgets */

var UIGroupedSelect = ui.AbstractElement.extend({
	/* entries: [{key, label, group}] (group '' = ungrouped, shown first) */
	__init__: function(value, entries, options) {
		this.value = (value == null) ? null : String(Array.isArray(value) ? value[0] : value).split(/\s+/)[0];
		this.entries = entries || [];
		this.options = Object.assign({}, options);
	},
	render: function() {
		var self = this;
		var sel = E('select', { 'class': 'cbi-input-select', 'id': this.options.id ? 'widget.' + this.options.id : null,
			'disabled': this.options.disabled ? '' : null });
		var known = {}, groups = [], byGroup = {};
		this.entries.forEach(function(e) {
			known[e.key] = true;
			if (!e.group) {
				sel.appendChild(E('option', { 'value': e.key }, [e.label]));
			} else {
				if (!byGroup[e.group]) { byGroup[e.group] = []; groups.push(e.group); }
				byGroup[e.group].push(e);
			}
		});
		if (this.value != null && this.value !== '' && !known[this.value])
			sel.insertBefore(E('option', { 'value': this.value }, ['( ' + this.value + ' )']), sel.firstChild);
		groups.forEach(function(g) {
			var og = E('optgroup', { 'label': g + ' (' + byGroup[g].length + ')' });
			byGroup[g].forEach(function(e) { og.appendChild(E('option', { 'value': e.key }, [e.label])); });
			sel.appendChild(og);
		});
		if (this.value != null) sel.value = this.value;
		if (sel.selectedIndex < 0 && sel.options.length) sel.selectedIndex = 0;

		var children = [];
		if (this.entries.length > 12) {
			var search = E('input', { 'type': 'search', 'class': 'cbi-input-text pw-gsel-search', 'placeholder': '🔍 ' + _('Search nodes...') });
			search.addEventListener('input', function() {
				var q = search.value.trim().toLowerCase();
				Array.prototype.forEach.call(sel.querySelectorAll('option'), function(op) {
					op.hidden = !!q && op.textContent.toLowerCase().indexOf(q) < 0 && !op.selected;
				});
				Array.prototype.forEach.call(sel.querySelectorAll('optgroup'), function(og) {
					og.hidden = !Array.prototype.some.call(og.children, function(op) { return !op.hidden; });
				});
			});
			children.push(search);
		}
		children.push(sel);
		var frame = E('div', { 'id': this.options.id, 'class': 'pw-gsel' }, children);
		this.node = frame;
		this.setUpdateEvents(sel, 'change', 'blur');
		this.setChangeEvents(sel, 'change');
		dom.bindClassInstance(frame, this);
		return frame;
	},
	getValue: function() { var s = this.node.querySelector('select'); return s ? s.value : null; },
	setValue: function(v) {
		var s = this.node.querySelector('select');
		if (!s) return;
		v = v == null ? '' : String(v);
		if (!Array.prototype.some.call(s.options, function(o) { return o.value === v; }))
			s.insertBefore(E('option', { 'value': v }, ['( ' + v + ' )']), s.firstChild);
		s.value = v;
	}
});

var UINodeCheckList = ui.AbstractElement.extend({
	/* multi-select checkbox list grouped by node group with search and select/deselect visible */
	__init__: function(values, entries, options) {
		this.values = toArray(values);
		this.entries = entries || [];
		this.options = Object.assign({ grouped: true }, options);
	},
	render: function() {
		var self = this, sel = {};
		this.values.forEach(function(v) { sel[v] = true; });
		var groups = [], byGroup = {};
		var known = {};
		this.entries.forEach(function(e) {
			known[e.key] = true;
			var g = self.options.grouped ? (e.group || _('default')) : '';
			if (!byGroup[g]) { byGroup[g] = []; groups.push(g); }
			byGroup[g].push(e);
		});
		/* selected keys that no longer exist are kept (shown as raw id) so a save does not drop them silently */
		this.values.forEach(function(v) {
			if (!known[v]) {
				var g = self.options.grouped ? _('default') : '';
				if (!byGroup[g]) { byGroup[g] = []; groups.push(g); }
				byGroup[g].push({ key: v, label: v + ' (?)', group: '' });
			}
		});
		var counter = E('span', { 'class': 'pw-ncl-count' });
		var search = E('input', { 'type': 'search', 'class': 'cbi-input-text', 'placeholder': '🔍 ' + _('Search nodes...') });
		var list = E('div', { 'class': 'pw-ncl-list' });
		var boxes = [];
		var updateCounts = function() {
			var visible = boxes.filter(function(b) { return !b.closest('.pw-ncl-item').hidden; });
			var q = search.value.trim();
			var pool = q ? visible : boxes;
			counter.innerHTML = _('Selected:') + ' <b>' + pool.filter(function(b) { return b.checked; }).length + '/' + pool.length + '</b>';
			list.querySelectorAll('.pw-ncl-group').forEach(function(gd) {
				var bs = Array.prototype.slice.call(gd.querySelectorAll('input[type=checkbox]'));
				var c = gd.querySelector('.pw-ncl-gcount');
				if (c) c.textContent = '(' + bs.filter(function(b) { return b.checked; }).length + '/' + bs.length + ')';
			});
		};
		groups.forEach(function(g) {
			var items = byGroup[g].map(function(e) {
				var cb = E('input', { 'type': 'checkbox', 'value': e.key });
				cb.checked = !!sel[e.key];
				boxes.push(cb);
				return E('label', { 'class': 'pw-ncl-item', 'data-label': String(e.label).toLowerCase() }, [cb, ' ', E('span', {}, [e.label])]);
			});
			if (self.options.grouped) {
				var det = E('details', { 'class': 'pw-ncl-group' }, [
					E('summary', {}, [E('span', {}, [g]), ' ', E('span', { 'class': 'pw-ncl-gcount' })]),
					E('div', { 'class': 'pw-ncl-items' }, items)
				]);
				if (byGroup[g].some(function(e) { return sel[e.key]; })) det.open = true;
				list.appendChild(det);
			} else {
				list.appendChild(E('div', { 'class': 'pw-ncl-items pw-ncl-flat' }, items));
			}
		});
		search.addEventListener('input', function() {
			var q = search.value.trim().toLowerCase();
			list.querySelectorAll('.pw-ncl-item').forEach(function(it) {
				it.hidden = !!q && it.getAttribute('data-label').indexOf(q) < 0;
			});
			list.querySelectorAll('.pw-ncl-group').forEach(function(gd) {
				var any = Array.prototype.some.call(gd.querySelectorAll('.pw-ncl-item'), function(i) { return !i.hidden; });
				gd.hidden = !any;
				if (q) gd.open = any;
			});
			updateCounts();
		});
		var setVisible = function(state) {
			boxes.forEach(function(b) { if (!b.closest('.pw-ncl-item').hidden) b.checked = state; });
			updateCounts();
			list.dispatchEvent(new Event('change', { bubbles: true }));
		};
		var tools = E('div', { 'class': 'pw-ncl-tools' }, [
			search,
			E('button', { 'class': 'cbi-button cbi-button-neutral', 'type': 'button', 'click': function(ev) { ev.preventDefault(); setVisible(true); } }, [_('Select all')]),
			E('button', { 'class': 'cbi-button cbi-button-neutral', 'type': 'button', 'click': function(ev) { ev.preventDefault(); setVisible(false); } }, [_('DeSelect all')]),
			counter
		]);
		if (this.entries.length <= 8 && !this.options.grouped)
			tools = E('div', { 'class': 'pw-ncl-tools' }, [counter]);
		var frame = E('div', { 'id': this.options.id, 'class': 'pw-ncl' }, [tools, list]);
		list.addEventListener('change', updateCounts);
		this.node = frame;
		this.boxes = boxes;
		updateCounts();
		this.setUpdateEvents(list, 'change');
		this.setChangeEvents(list, 'change');
		dom.bindClassInstance(frame, this);
		return frame;
	},
	getValue: function() {
		return this.boxes.filter(function(b) { return b.checked; }).map(function(b) { return b.value; });
	},
	setValue: function(v) {
		var want = {};
		toArray(v).forEach(function(x) { want[x] = true; });
		this.boxes.forEach(function(b) { b.checked = !!want[b.value]; });
		this.node.querySelector('.pw-ncl-list').dispatchEvent(new Event('change', { bubbles: true }));
	}
});

/* ---------------------------------------------------- form option classes */

function pwCheckDepends(section_id) {
	var self = this;
	var section = this.section;
	var lookup = function(name) {
		var o = null;
		for (var i = 0; i < section.children.length; i++)
			if (section.children[i].option === name) { o = section.children[i]; break; }
		if (!o || !o.isActive(section_id)) return '';
		var v = o.formvalue(section_id);
		if (o instanceof form.Flag) return v == o.enabled ? '1' : '';
		if (Array.isArray(v)) return v.join(' ');
		return v == null ? '' : String(v);
	};
	return depsSatisfied(self.pwdeps, lookup);
}

var CBINodeList = form.ListValue.extend({
	__name__: 'CBI.PWNodeList',
	renderWidget: function(section_id, option_index, cfgvalue) {
		var value = (cfgvalue != null) ? cfgvalue : this.default;
		var opts = {
			id: this.cbid(section_id),
			mode: 'single',
			optional: false,
			disabled: (this.readonly != null) ? this.readonly : this.map.readonly
		};
		/* shared grouped/searchable picker of pw.js when available (same look as other pages) */
		var Picker = (pw && typeof pw.NodePicker === 'function') ? pw.NodePicker : UIGroupedSelect;
		var w = new Picker(value, this.entries, opts);
		return w.render();
	}
});

var CBINodeMulti = form.MultiValue.extend({
	__name__: 'CBI.PWNodeMulti',
	renderWidget: function(section_id, option_index, cfgvalue) {
		var value = (cfgvalue != null) ? cfgvalue : this.default;
		var w = new UINodeCheckList(value, this.entries, {
			id: this.cbid(section_id),
			grouped: this.grouped !== false
		});
		return w.render();
	}
});

function makePicker(value, entries) {
	var Picker = (pw && typeof pw.NodePicker === 'function') ? pw.NodePicker : UIGroupedSelect;
	return new Picker(value, entries, { mode: 'single', optional: false });
}

/* Shunt rule table (rows = shunt_rules of the selected group + Default); values live on the node */
var CBIShuntTable = form.Value.extend({
	__name__: 'CBI.PWShuntTable',
	load: function() { return null; },
	renderFrame: function(section_id, in_table, option_index, nodes) {
		var el = E('div', { 'class': 'cbi-value pw-shunt-wrap', 'id': 'cbi-' + CONF + '-' + section_id + '-' + this.option,
			'data-field': this.cbid(section_id), 'data-name': this.option, 'data-index': option_index }, nodes);
		dom.bindClassInstance(el, this);
		return el;
	},
	renderWidget: function(section_id) {
		var self = this, sid = this.nodeId;
		var grp = (uci.get(CONF, sid, 'shunt_group') || '').toLowerCase();
		var rules = [];
		uci.sections(CONF, 'shunt_rules').forEach(function(e) {
			if ((e.group || '').toLowerCase() == grp)
				rules.push({ id: e['.name'], remarks: e.remarks || e['.name'], node_opt: e['.name'], node_def: '',
					fake_opt: e['.name'] + '_fakedns', tag_opt: e['.name'] + '_proxy_tag' });
		});
		rules.push({ id: '.default', remarks: _('Default'), node_opt: 'default_node', node_def: '_direct',
			fake_opt: 'default_fakedns', tag_opt: 'default_proxy_tag' });
		this.rules = rules;
		var normal = {};
		(this.nodeList.normal_list || []).forEach(function(n) { normal[n.id] = true; });
		var nodeEntries = [];
		Object.keys(this.nodeList).forEach(function(k) {
			if (k == 'shunt_list') return;
			self.nodeList[k].forEach(function(v) { nodeEntries.push({ key: v.id, label: v.remark, group: nodeGroupLabel(v.group) }); });
		});
		var base = [
			{ key: '', label: _('Close (Not use)'), group: '' },
			{ key: '_default', label: _('Use default node'), group: '' },
			{ key: '_direct', label: _('Direct Connection'), group: '' },
			{ key: '_blackhole', label: _('Blackhole (Block)'), group: '' }
		];
		var rows = rules.map(function(r, i) {
			var isDefault = (i == rules.length - 1);
			var nodeVal = uci.get(CONF, sid, r.node_opt);
			if (nodeVal == null) nodeVal = r.node_def;
			var entries = base.filter(function(e) { return !(isDefault && e.key == '_default'); }).concat(nodeEntries);
			var nodeSel = makePicker(nodeVal, entries);
			var nodeEl = nodeSel.render();
			var fake = E('input', { 'type': 'checkbox' });
			fake.checked = uci.get(CONF, sid, r.fake_opt) == '1';
			var tagSel = makePicker(uci.get(CONF, sid, r.tag_opt) || '',
				[{ key: '', label: _('Close (Not use)'), group: '' }].concat(nodeEntries));
			var tagEl = tagSel.render();
			var fakeCell = E('div', { 'class': 'td', 'data-title': 'FakeDNS' }, [E('label', { 'class': 'pw-switch' }, [fake])]);
			var tagCell = E('div', { 'class': 'td', 'data-title': _('Preproxy') }, [tagEl]);
			var refresh = function() {
				var v = nodeSel.getValue();
				if (v === '' || v === '_direct') { fake.checked = false; fakeCell.style.visibility = 'hidden'; }
				else fakeCell.style.visibility = '';
				if (!v || v.charAt(0) == '_' || /^socks_/.test(v) || !normal[v]) {
					tagSel.setValue('');
					tagCell.style.visibility = 'hidden';
				} else tagCell.style.visibility = '';
			};
			nodeEl.addEventListener('change', refresh);
			nodeEl.addEventListener('pw-np-change', refresh);
			r.ui = { node: nodeSel, fake: fake, tag: tagSel };
			r.refresh = refresh;
			var title = isDefault ? E('span', { 'style': 'color:red' }, [r.remarks])
				: E('a', { 'href': L.url('admin/services/passwall2/shunt_rules', r.id), 'target': '_blank' }, [r.remarks]);
			return E('div', { 'class': 'tr' }, [
				E('div', { 'class': 'td', 'data-title': _('Rule') }, [title]),
				E('div', { 'class': 'td', 'data-title': _('Node') }, [nodeEl]),
				fakeCell, tagCell
			]);
		});
		var tipFake = _('Use FakeDNS work in the domain that proxy.') + '\n' + _('Suitable scenarios for let the node servers get the target domain names.') + '\n' +
			_('Such as: DNS unlocking of streaming media, reducing DNS query latency, etc.');
		var tipTag = _('Set the node to be used as a pre-proxy.') + '\n' + _('Each rule has a separate switch that controls whether this rule uses the pre-proxy or not.');
		var table = E('div', { 'class': 'table cbi-section-table pw-shunt-table' }, [
			E('div', { 'class': 'tr table-titles' }, [
				E('div', { 'class': 'th' }, [_('Rule')]),
				E('div', { 'class': 'th' }, [_('Node')]),
				E('div', { 'class': 'th' }, [E('a', { 'style': 'color:#FF8C00', 'title': tipFake }, ['FakeDNS'])]),
				E('div', { 'class': 'th' }, [E('a', { 'style': 'color:red', 'title': tipTag }, [_('Preproxy')])])
			])
		].concat(rows));
		window.requestAnimationFrame(function() { rules.forEach(function(r) { r.refresh(); }); });
		return E('div', { 'class': 'pw-shunt' }, [table]);
	},
	formvalue: function() { return null; },
	isValid: function() { return true; },
	checkDepends: function() { return true; },
	parse: function(section_id) {
		var sid = this.nodeId;
		(this.rules || []).forEach(function(r) {
			if (!r.ui) return;
			var nv = r.ui.node.getValue();
			if (nv == null || nv === '') uci.unset(CONF, sid, r.node_opt);
			else uci.set(CONF, sid, r.node_opt, nv);
			if (r.ui.fake.checked) uci.set(CONF, sid, r.fake_opt, '1');
			else uci.unset(CONF, sid, r.fake_opt);
			var tv = r.ui.tag.getValue();
			if (tv == null || tv === '') uci.unset(CONF, sid, r.tag_opt);
			else uci.set(CONF, sid, r.tag_opt, tv);
		});
		return Promise.resolve();
	}
});

/*
 * buildForm(section, S, ctx, hooks): turn specs into LuCI form options.
 * hooks: { onKindChange(newProtocol), onShuntGroupChange(value) }
 */
function buildForm(s, S, ctx, hooks) {
	hooks = hooks || {};
	var opts = {};
	S.list.forEach(function(sp) {
		var o;
		switch (sp.cls) {
		case 'Value': o = s.option(form.Value, sp.name, sp.title, sp.desc); break;
		case 'ListValue': o = s.option(form.ListValue, sp.name, sp.title, sp.desc); break;
		case 'Flag': o = s.option(form.Flag, sp.name, sp.title, sp.desc); break;
		case 'DynamicList': o = s.option(form.DynamicList, sp.name, sp.title, sp.desc); break;
		case 'TextValue': o = s.option(form.TextValue, sp.name, sp.title, sp.desc); break;
		case 'NodeList': o = s.option(CBINodeList, sp.name, sp.title, sp.desc); break;
		case 'NodeMulti': o = s.option(CBINodeMulti, sp.name, sp.title, sp.desc); break;
		case 'CheckList': o = s.option(CBINodeMulti, sp.name, sp.title, sp.desc); o.grouped = false; break;
		case 'ShuntTable':
			o = s.option(CBIShuntTable, sp.name, sp.title);
			o.nodeId = ctx.sid;
			o.nodeList = ctx.nodeList;
			opts[sp.name] = o;
			return;
		default: return;
		}
		o.pwspec = sp;
		if (sp.cls == 'NodeList' || sp.cls == 'NodeMulti' || sp.cls == 'CheckList') {
			o.entries = sp.values.map(function(v) { return { key: v[0], label: v[1], group: v[2] }; });
			sp.values.forEach(function(v) { o.value(v[0], v[1]); });
		} else {
			sp.values.forEach(function(v) { o.value(v[0], v[1]); });
		}
		if (sp.default != null) o.default = Array.isArray(sp.default) ? sp.default.slice() : String(sp.default);
		if (sp.datatype) o.datatype = sp.datatype;
		if (sp.placeholder) o.placeholder = sp.placeholder;
		if (sp.password) o.password = true;
		if (sp.rmempty === false) o.rmempty = false;
		if (sp.rows) o.rows = sp.rows;
		if (sp.wrap) o.wrap = sp.wrap;
		if (sp.cls == 'TextValue') o.monospace = true;

		o.pwdeps = sp.deps;
		o.checkDepends = pwCheckDepends;

		var enc = sp.enc && ENC[sp.enc];
		if (enc || sp.cls == 'CheckList') {
			o.load = function(section_id) {
				var v = uci.get(CONF, section_id, sp.name);
				if (sp.cls == 'CheckList') return v == null ? null : toArray(v);
				return (v == null) ? null : enc.decode(v);
			};
		}
		if (sp.validate) {
			var userValidate = sp.validate;
			o.validate = function(section_id, value) {
				if (value == null || value === '' || (Array.isArray(value) && !value.length)) return true;
				return userValidate(value);
			};
		}

		o.write = function(section_id, value) {
			var v = value;
			if (sp.cls == 'DynamicList' || sp.cls == 'NodeMulti') v = dedup(toArray(value));
			else if (sp.cls == 'CheckList') v = dedup(toArray(value)).join(' ');
			if (sp.enc == 'plugin') {
				if (!v || v == 'none') return uci.unset(CONF, section_id, sp.name);
			} else if (enc) {
				v = enc.encode(v);
			}
			if (sp.flushOnChange) {
				var old = uci.get(CONF, section_id, sp.name) || '0';
				if ((v || '0') != old) uci.set(CONF, '@global[0]', 'flush_set', '1');
			}
			if (Array.isArray(v) && !v.length) uci.unset(CONF, section_id, sp.name);
			else uci.set(CONF, section_id, sp.name, v);
			if (sp.sideEffect == 'download_address') {
				var addr = null;
				try {
					var data = JSON.parse(normJsonText(value));
					addr = (data && data.extra && data.extra.downloadSettings && data.extra.downloadSettings.address) ||
						(data && data.downloadSettings && data.downloadSettings.address);
				} catch (e) { addr = null; }
				if (addr && addr !== '')
					uci.set(CONF, section_id, 'download_address', String(addr).replace(/^\[/, '').replace(/\]$/, ''));
				else
					uci.unset(CONF, section_id, 'download_address');
			}
		};
		o.remove = function(section_id) {
			if (sp.flushOnChange) {
				var old = uci.get(CONF, section_id, sp.name) || '0';
				if (old != '0') uci.set(CONF, '@global[0]', 'flush_set', '1');
			}
			uci.unset(CONF, section_id, sp.name);
			if (sp.sideEffect == 'download_address')
				uci.unset(CONF, section_id, 'download_address');
		};
		if (sp.kindSwitch && hooks.onKindChange) {
			o.onchange = function(ev, section_id, value) {
				var oldKind = ctx.kind;
				var newKind = protocolKind(ctx.type, value);
				if (newKind != oldKind) hooks.onKindChange(value);
			};
		}
		if (sp.shuntGroupSwitch && hooks.onShuntGroupChange) {
			o.onchange = function(ev, section_id, value) { hooks.onShuntGroupChange(value); };
		}
		opts[sp.name] = o;
	});
	return opts;
}

/* map-level dependency settling (LuCI only does two passes; chains here are deeper) */
function installDependsHandler(m) {
	m.checkDepends = function(ev, n) {
		for (var pass = 0; pass < 12; pass++) {
			var changed = false;
			for (var i = 0; i < this.children.length; i++)
				if (this.children[i].checkDepends(ev, pass > 0 ? 1 : n))
					changed = true;
			if (!changed) break;
		}
		ui.tabs.updateTabs(ev, this.root);
	};
}

/* Apply share-link import fields to a rendered map section */
function applyFields(s, sid, fields, sharelink) {
	var applied = 0;
	s.children.forEach(function(o) {
		if (!o.option || !(o.option in fields) || o.option === 'type') return;
		var v = fields[o.option];
		if (v === undefined || v === null) return;
		var el = o.getUIElement(sid);
		if (!el) return;
		if (o instanceof form.Flag) {
			el.setValue(sharelink.truthy(v) ? o.enabled : o.disabled);
		} else if (o instanceof form.DynamicList && !(o instanceof form.MultiValue)) {
			el.setValue(String(v) === '' ? [] : [String(v)]);
		} else {
			var sv = String(v);
			if (typeof el.addChoices === 'function' && o.keylist && o.keylist.indexOf(sv) < 0 && sv !== '') {
				var lab = {}; lab[sv] = sv;
				try { el.addChoices([sv], lab); } catch (e) {}
			}
			el.setValue(sv);
		}
		var node = el.node;
		if (node) {
			node.setAttribute('data-changed', true);
			node.dispatchEvent(new CustomEvent('widget-change', { bubbles: true }));
		}
		applied++;
	});
	return applied;
}

/* live-form getter for sharelink.buildUrl */
function formGetter(s, sid) {
	return function(name) {
		for (var i = 0; i < s.children.length; i++) {
			var o = s.children[i];
			if (o.option !== name) continue;
			if (!o.isActive(sid)) return null;
			if (o instanceof form.Flag) {
				var c = o.formvalue(sid) == o.enabled;
				return { checkbox: true, checked: c, value: c ? '1' : '0' };
			}
			var v = o.formvalue(sid);
			if (Array.isArray(v)) v = v.length ? v[0] : '';
			return { checkbox: false, checked: false, value: v == null ? '' : String(v) };
		}
		return null;
	};
}

/* ------------------------------------------------------------- self tests */

function selfTest() {
	var fails = [];
	var eq = function(n, a, b) { if (JSON.stringify(a) !== JSON.stringify(b)) fails.push(n + ': got ' + JSON.stringify(a) + ' expected ' + JSON.stringify(b)); };
	var env = { netdevs: [{ name: 'eth0', label: 'Ethernet Adapter: "eth0"' }], bins: { 'obfs-local': true }, plugins: ['obfs-local'],
		has_geoview: false, ge114: true, ge115: false, hasTag: function(t) { return ['with_quic', 'with_utls', 'with_wireguard'].indexOf(t) >= 0; } };
	var ctx = function(kind) { return { env: env, sid: 'self', kind: kind, nodeList: { socks_list: [], normal_list: [{ id: 'n1', remark: 'X', group: '' }] }, groups: ['g 1'] }; };

	eq('urlEncode', urlEncode('a b/中'), 'a%20b%2F%E4%B8%AD');
	eq('ipv6', [isIPv6('::1'), isIPv6('2001:db8::1'), isIPv6('fe80::1:2:3:4:5:6:7:8'), isIPv6('1.2.3.4'), isIPv6('::ffff:1.2.3.4')], [true, true, false, false, true]);
	eq('hostname', [isHostname('example.com'), isHostname('1.2.3'), isHostname('a_b'), isHostname('-x')], [true, false, true, false]);
	eq('cmpver', [compareVersions('1.14.0-beta.1', '>=', '1.14.0'), compareVersions('1.13.9', '>=', '1.14.0'), compareVersions('1.15.0', '>=', '1.15.0')], [true, false, true]);
	eq('realm', parseRealmUri('realm://public@realm.hy2.io/your-realm-name?stun=a:1&STUN=b:2'),
		{ scheme: 'realm', token: 'public', server_url: 'realm.hy2.io', address: 'realm.hy2.io', port: 443, realm_id: 'your-realm-name', stun_servers: ['a:1', 'b:2'] });
	eq('realm.bad', parseRealmUri('http://x'), null);
	eq('realm.v6', parseRealmUri('realm+http://t@[::1]:8080/id/').port, 8080);
	eq('headers.ok', validateHeaders('X-A: 1\nx-b:2', true), true);
	eq('headers.dup', typeof validateHeaders('X-A: 1\nx-a:2', true), 'string');
	eq('headers.host', typeof validateHeaders('Host: a', true), 'string');
	eq('headers.host.sb', validateHeaders('Host: a', false), true);
	eq('pem', ENC.pem.encode(' -----BEGIN-----  \r\n abc \r\n\r\n-----END----- '), '-----BEGIN-----\\nabc\\n-----END-----');
	eq('pem.dec', ENC.pem.decode('a\\nb'), 'a\nb');
	eq('b64json', ENC.b64json.decode(ENC.b64json.encode('\n {"a":"ü"} \n')), '{"a":"ü"}');
	eq('nonedefault', ENC.nonedefault.encode('  '), 'none');

	/* Xray vless reality: visible fields */
	var S = getSpecs('Xray', Object.assign(ctx('normal'), { type: 'Xray' }));
	var g = virtualForm(S, { protocol: 'vless', tls: '1', reality: '1', transport: 'raw', address: 'a', port: '1' });
	eq('xray.vless.reality', [!!g('reality_publicKey'), !!g('fingerprint'), !!g('utls'), !!g('alpn'), !!g('flow'), !!g('address'), !!g('tcp_guise'), g('fingerprint').value],
		[true, true, false, false, true, true, true, 'chrome']);
	g = virtualForm(S, { protocol: 'hysteria2', hysteria2_realms: '1' });
	eq('xray.hy2.realm', [!!g('address'), !!g('port'), !!g('hysteria2_realm_url'), !!g('hysteria2_hop'), !!g('tcp_fast_open'), !!g('preproxy_node'), !!g('tls_serverName')],
		[false, false, true, false, false, false, true]);
	g = virtualForm(S, { protocol: 'vmess', chain_proxy: '1' });
	eq('xray.chain', [!!g('preproxy_node'), !!g('to_node'), !!g('domain_strategy'), !!g('mux')], [true, false, true, true]);
	g = virtualForm(S, { protocol: 'vmess', happy_eyeballs: '1' });
	eq('xray.happy', !!g('domain_strategy'), false);
	eq('xray.default.protocol', virtualForm(S, {})('protocol').value, 'vmess');

	/* sing-box */
	S = getSpecs('sing-box', Object.assign(ctx('normal'), { type: 'sing-box' }));
	g = virtualForm(S, { protocol: 'shadowsocks', uot: '1' });
	eq('sb.mux.uot', !!g('mux'), false);
	g = virtualForm(S, { protocol: 'shadowsocks' });
	eq('sb.mux.nouot', [!!g('mux'), !!g('shadowtls'), !!g('plugin_enabled'), !!g('transport')], [true, true, true, true]);
	g = virtualForm(S, { protocol: 'vless', tls: '1', flow: 'xtls-rprx-vision' });
	eq('sb.ech.flow', [!!g('ech'), !!g('flow'), !!g('mux')], [false, true, false]);
	g = virtualForm(S, { protocol: 'tuic' });
	eq('sb.tuic', [!!g('uuid'), !!g('password'), !!g('tls_serverName'), !!g('tls_allowInsecure'), !!g('tuic_alpn'), !!g('alpn')], [true, true, true, true, true, false]);
	eq('sb.snell', !!getSpecs('sing-box', Object.assign(ctx('normal'), { type: 'sing-box' })).get('snell_psk'), true);
	eq('sb.masque.gate', S.get('protocol').values.some(function(v) { return v[0] == 'masque'; }), false);
	eq('sb.default.protocol', virtualForm(S, {})('protocol').value, 'socks');

	/* special kinds */
	S = getSpecs('Xray', Object.assign(ctx('_balancing'), { type: 'Xray' }));
	eq('xray.balancing.chain', S.get('chain_proxy').values.map(function(v) { return v[0]; }), ['', '2']);
	eq('xray.balancing.group', S.get('node_group').values, [['default', 'default', ''], ['g%201', 'g 1', '']]);
	S = getSpecs('sing-box', Object.assign(ctx('_shunt'), { type: 'sing-box' }));
	eq('sb.shunt', [!!S.get('chain_proxy'), !!S.get('fakedns'), !!S.get('domainStrategy'), !!S.get('_shunt_table')], [false, true, false, true]);
	S = getSpecs('Xray', Object.assign(ctx('normal'), { type: 'Xray' }));
	eq('xray.chain.order', S.get('chain_proxy').values.map(function(v) { return v[0]; }), ['', '1', '3', '2']);
	eq('xray.preproxy.self', S.get('preproxy_node').values.map(function(v) { return v[0]; }), ['n1']);
	eq('kind', [protocolKind('Xray', '_urltest'), protocolKind('sing-box', '_urltest'), protocolKind('Xray', '_balancing'), protocolKind('SSR', '_shunt')],
		['normal', '_urltest', '_balancing', 'normal']);
	return fails;
}

return baseclass.extend({
	CONF: CONF,
	PROBE_URLS: PROBE_URLS,
	SPECIAL_PROTOCOLS: SPECIAL_PROTOCOLS,
	loadEnv: loadEnv,
	getValidNodes: getValidNodes,
	getNodeList: getNodeList,
	protoLabel: protoLabel,
	getSpecs: getSpecs,
	protocolKind: protocolKind,
	availableTypes: availableTypes,
	makeCtx: makeCtx,
	virtualForm: virtualForm,
	buildForm: buildForm,
	installDependsHandler: installDependsHandler,
	applyFields: applyFields,
	formGetter: formGetter,
	urlEncode: urlEncode,
	isIPv6: isIPv6,
	isIP: isIP,
	isHostname: isHostname,
	compareVersions: compareVersions,
	parseRealmUri: parseRealmUri,
	UIGroupedSelect: UIGroupedSelect,
	UINodeCheckList: UINodeCheckList,
	selfTest: selfTest
});
