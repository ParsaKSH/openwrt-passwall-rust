'use strict';
'require baseclass';

/*
 * passwall2 share-link codec (port of upstream node_config/link_share_man.htm)
 * and a tiny self-contained QR code generator (no CDN, no third party code).
 *
 * Export:  buildUrl(get, type, remarks) -> { url } | { error }
 *          `get(name)` returns null when the (unprefixed) option is absent or
 *          hidden in the form, else { checkbox: bool, checked: bool, value: string }.
 *          This mirrors upstream, which reads only the fields present in the DOM.
 * Import:  parse(link, env) -> { ok, type, protocol, fields: {opt: value}, error }
 *          `env` = { has_xray, has_singbox, has_ss_rust, ss_type, trojan_type,
 *          vmess_type, vless_type, hysteria2_type } (core choice like upstream).
 * QR:      qrMatrix(text) -> boolean[][] ; qrSVG(text, px) -> SVG markup string.
 */

function padright(str, cnt, pad) {
	return str + Array(cnt + 1).join(pad);
}

function utf8Bytes(str) {
	return unescape(encodeURIComponent(str));
}

function b64EncodeUnicode(str) {
	return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
		return String.fromCharCode(parseInt(p1, 16));
	}));
}

function b64encutf8safe(str) {
	return b64EncodeUnicode(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64DecodeUnicode(str) {
	try {
		return decodeURIComponent(Array.prototype.map.call(atob(str), function(c) {
			return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
		}).join(''));
	} catch (e) {}
	return str;
}

function b64decutf8safe(str) {
	var orig = str;
	str = str.replace(/-/g, '+').replace(/_/g, '/');
	var l = (4 - str.length % 4) % 4;
	if (l)
		str = padright(str, l, '=');
	var text = b64DecodeUnicode(str);
	if (text !== str)
		return text;
	return orig;
}

function b64encsafe(str) {
	/* upstream uses btoa() directly (Latin-1). Non Latin-1 input would throw;
	 * upstream quirk: we fall back to UTF-8 bytes instead of aborting the export. */
	var b;
	try { b = btoa(str); } catch (e) { b = btoa(utf8Bytes(str)); }
	return b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64decsafe(str) {
	var orig = str;
	try {
		str = str.replace(/-/g, '+').replace(/_/g, '/');
		var pad = (4 - str.length % 4) % 4;
		if (pad) str += '='.repeat(pad);
		return atob(str);
	} catch (e) {
		return orig;
	}
}

/* binary string (from atob) -> JS string, decoding UTF-8 when valid */
function binToStr(bin) {
	try { return decodeURIComponent(escape(bin)); } catch (e) { return bin; }
}

function dictvalue(d, key) {
	var v = d[key];
	if (typeof (v) === 'undefined' || v === '')
		return '';
	return b64decsafe(v);
}

function safeDecode(s) {
	try { return decodeURIComponent(s); } catch (e) { return s; }
}

function is_json(str) {
	if (typeof str !== 'string') return false;
	try {
		var o = JSON.parse(str);
		return (o !== null && typeof o === 'object');
	} catch (e) { return false; }
}

function unbracketIP(server) {
	if (!server) return '';
	return server.replace(/^\[/, '').replace(/\]$/, '');
}

var IPV6_RE = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

function parseNodeUrl(url) {
	/* Use HTTPS's default port 443 so URL parsing preserves an explicit :80. */
	var str = 'https' + url.substring(url.indexOf('://'));
	var u = new URL(str);
	return {
		hash: u.hash,
		host: u.host,
		hostname: u.hostname,
		port: u.port,
		search: u.search,
		passwd: u.username || u.password
	};
}

/* trojan/vless/hy2/anytls/snell style query parsing (first two '=' parts only) */
function parseQuery(search, lowerKeys, replaceSlash) {
	var q = {};
	if (!search || search.length <= 1)
		return q;
	var s = replaceSlash ? search.replace('/?', '?') : search;
	var params = (s.split('?')[1] || '').split('&');
	for (var i = 0; i < params.length; i++) {
		var kv = params[i].split('=');
		var k = safeDecode(kv[0]);
		if (lowerKeys) k = k.toLowerCase();
		q[k] = safeDecode(kv[1] || '');
	}
	return q;
}

function insecure(q, keys) {
	for (var i = 0; i < keys.length; i++)
		if ((q[keys[i]] ?? '0') !== '0')
			return true;
	return false;
}

/* -------------------------------------------------------------------- export */

function buildUrl(get, v_type, remarks) {
	var g = function(name) { return get(name) || null; };
	var val = function(name) { var o = g(name); return o ? (o.value == null ? '' : String(o.value)) : ''; };
	var checked = function(name) { var o = g(name); return !!(o && o.checked); };
	var query = function(param, src, default_value) {
		var o = g(src);
		if (!o) return '';
		var ret = '&' + param + '=';
		if (o.checkbox)
			return ret + (o.checked ? '1' : '0');
		var result = encodeURIComponent(o.value == null ? '' : String(o.value));
		if (result.trim() == '')
			return default_value ? ret + default_value : '';
		return ret + result;
	};
	var proto = function() { return val('protocol'); };
	var v_alias = remarks != null ? String(remarks) : val('remarks');

	var known = (v_type === 'SS-Rust' || v_type === 'SSR' || v_type === 'Hysteria2' || v_type === 'Xray' || v_type === 'sing-box');
	var protocol = '';
	if (v_type === 'SS-Rust') protocol = 'ss';
	else if (v_type === 'SSR') protocol = 'ssr';
	else if (v_type === 'Hysteria2') protocol = 'hysteria2';

	var _address = '';
	if (known) {
		var v_server = val('address');
		_address = IPV6_RE.test(v_server) ? '[' + v_server + ']' : v_server;
	}

	var isCore = (v_type === 'sing-box' || v_type === 'Xray');
	var url = null, params;

	var transportParams = function(variant) {
		/* variant: 'ss' | 'vless' | 'trojan' */
		var p = '';
		var t = val('transport');
		if (t === 'ws') {
			p += query('host', 'ws_host');
			p += query('path', 'ws_path');
			if (v_type == 'sing-box' && checked('ws_enableEarlyData')) {
				if (variant === 'vless')
					p += encodeURIComponent('?ed=' + val('ws_maxEarlyData'));
				else
					p += '?ed=' + val('ws_maxEarlyData');
			}
		} else if (t === 'http') {
			p += query('host', 'http_host');
			p += query('path', 'http_path');
		} else if (t === 'raw' || t === 'tcp') {
			t = 'tcp';
			p += query('headerType', 'tcp_guise');
			p += query('host', 'tcp_guise_http_host');
			p += query('path', 'tcp_guise_http_path');
		} else if (t === 'mkcp') {
			t = 'kcp';
			p += query('headerType', 'mkcp_guise');
			p += query('seed', 'mkcp_seed');
		} else if (t === 'quic') {
			p += query('headerType', 'quic_guise');
			p += query('key', 'quic_key');
			p += query('quicSecurity', 'quic_security');
		} else if (t === 'grpc') {
			p += query('path', 'grpc_serviceName');
			p += query('serviceName', 'grpc_serviceName');
			p += query('mode', 'grpc_mode');
		} else if (t === 'xhttp' && variant !== 'trojan') {
			p += query('host', 'xhttp_host');
			p += query('path', 'xhttp_path');
			p += query('mode', 'xhttp_mode');
			if (checked('use_xhttp_extra'))
				p += query('extra', 'xhttp_extra');
		} else if (t === 'httpupgrade' && variant === 'vless') {
			p += query('host', 'httpupgrade_host');
			p += query('path', 'httpupgrade_path');
		}
		p += '&type=' + t;
		return p;
	};

	var genST = function(paramStr) {
		try {
			var obj = {};
			var list = paramStr.split(';');
			for (var i = 0; i < list.length; i++) {
				var kv = list[i].split('=');
				if (kv.length === 2) {
					var k = kv[0].trim(), v = kv[1].trim();
					var m = k.match(/^v(\d+)$/);
					if (m && v === '1') obj.version = m[1];
					else if (k === 'passwd') obj.password = v;
					else obj[k] = v;
				}
			}
			return b64encsafe(JSON.stringify(obj));
		} catch (e) {
			return '';
		}
	};

	if (v_type === 'SS-Rust' || (isCore && proto() === 'shadowsocks')) {
		protocol = 'ss';
		var v_method = g('method') ? val('method') : val('ss_method');
		var v_password = val('password');
		var v_port = val('port');
		url = b64encsafe(v_method + ':' + v_password) + '@' + _address + ':' + v_port + '/?';
		var shadow_tls = false;
		params = '';
		if (checked('tcp_fast_open'))
			params += '&tfo=1';
		if (g('plugin')) {
			/* SIP003 plugin field visible (SS-Rust, or sing-box with plugin enabled) */
			var plugin_raw = val('plugin');
			var v_plugin = plugin_raw;
			if (v_plugin && v_plugin != 'none') {
				if (v_plugin == 'simple-obfs' || v_plugin == 'obfs-local')
					v_plugin = 'obfs-local';
				var v_plugin_opts = val('plugin_opts');
				if (v_plugin_opts)
					v_plugin += ';' + v_plugin_opts;
				params += '&plugin=' + encodeURIComponent(v_plugin);
				if (plugin_raw == 'shadow-tls' && v_plugin_opts) {
					params = 'shadow-tls=' + genST(v_plugin_opts);
					shadow_tls = true;
				}
			}
		} else if (isCore) {
			params += transportParams('ss');
			if (checked('tls')) {
				var v_security = 'tls';
				if (g('fingerprint') && val('fingerprint') != '')
					params += '&fp=' + val('fingerprint');
				if (checked('reality')) {
					v_security = 'reality';
					params += query('pbk', 'reality_publicKey');
					params += query('sid', 'reality_shortId');
					params += query('spx', 'reality_spiderX');
					params += query('pqv', 'reality_mldsa65Verify');
				}
				params += '&security=' + v_security;
				params += query('alpn', 'alpn');
				params += query('sni', 'tls_serverName');
				params += query('allowinsecure', 'tls_allowInsecure');
				params += query('pcs', 'tls_pinSHA256');
				params += query('vcn', 'tls_CertByName');
				params += query('ech', 'ech_config');
			}
			if (checked('uot'))
				params += '&udp=1';
			if (checked('use_finalmask'))
				params += query('fm', 'finalmask');
			if (checked('shadowtls')) {
				var st = '';
				var stv = val('shadowtls_version');
				if (stv) st += 'v' + stv + '=1;';
				var stp = val('shadowtls_password');
				if (stp) st += 'passwd=' + stp + ';';
				var sth = val('shadowtls_serverName');
				if (sth) st += 'host=' + sth + ';';
				if (checked('shadowtls_utls')) {
					var stf = val('shadowtls_fingerprint');
					if (stf) st += 'fingerprint=' + stf;
				}
				params = 'shadow-tls=' + genST(st);
				shadow_tls = true;
			}
		}
		if (shadow_tls)
			url = b64encsafe(v_method + ':' + v_password + '@' + _address + ':' + v_port) + '?';
		else
			params += '&group=';
		params += '#' + encodeURIComponent(v_alias);
		if (params[0] == '&')
			params = params.substring(1);
		url += params;
	} else if (v_type === 'SSR') {
		var ssr_str = _address + ':' + val('port') + ':' + val('protocol') + ':' + val('method') + ':' +
			val('obfs') + ':' + b64encsafe(val('password')) +
			'/?obfsparam=' + b64encsafe(val('obfs_param')) +
			'&protoparam=' + b64encsafe(val('protocol_param')) +
			'&remarks=' + b64encutf8safe(v_alias);
		url = b64encsafe(ssr_str);
	} else if (isCore && proto() === 'vmess') {
		protocol = 'vmess';
		var info = {};
		info.v = '2';
		info.ps = v_alias;
		info.add = val('address');
		info.port = val('port');
		info.id = val('uuid');
		var vt = val('transport');
		if (vt === 'ws') {
			info.host = val('ws_host');
			info.path = val('ws_path');
			if (v_type == 'sing-box' && checked('ws_enableEarlyData'))
				info.path = info.path + '?ed=' + val('ws_maxEarlyData');
		} else if (vt === 'http') {
			info.host = val('http_host');
			info.path = val('http_path');
		} else if (vt === 'raw' || vt === 'tcp') {
			vt = 'tcp';
			info.type = val('tcp_guise');
			if (info.type === 'http') {
				info.host = val('tcp_guise_http_host');
				info.path = val('tcp_guise_http_path');
			}
		} else if (vt === 'mkcp') {
			vt = 'kcp';
			info.type = val('mkcp_guise');
			info.seed = val('mkcp_seed');
		} else if (vt === 'quic') {
			info.type = g('quic_guise') ? val('quic_guise') : undefined;
			info.key = g('quic_key') ? val('quic_key') : undefined;
			info.securty = g('quic_security') ? val('quic_security') : undefined;
		} else if (vt === 'grpc') {
			info.path = val('grpc_serviceName');
		}
		info.net = vt;
		info.security = val('security') || 'auto';
		info.scy = info.security;
		if (checked('tls')) {
			info.tls = 'tls';
			info.sni = val('tls_serverName');
			info.alpn = g('alpn') ? val('alpn') : undefined;
			if (info.alpn === 'default') info.alpn = undefined;
			info.fp = g('fingerprint') ? val('fingerprint') : undefined;
			info.pcs = g('tls_pinSHA256') ? val('tls_pinSHA256') : undefined;
			if (checked('tls_allowInsecure')) info.insecure = '1';
		}
		if (checked('tcp_fast_open')) info.tfo = '1';
		if (checked('use_finalmask')) {
			info.fm = val('finalmask');
			if (info.fm) info.fm = encodeURI(info.fm);
		}
		url = b64EncodeUnicode(JSON.stringify(info));
	} else if (isCore && proto() === 'vless') {
		protocol = 'vless';
		url = encodeURIComponent(val('uuid')) + '@' + _address + ':' + val('port') + '?';
		params = transportParams('vless');
		if (v_type === 'sing-box')
			params += '&encryption=none';
		else
			params += query('encryption', 'encryption');
		if (checked('tls')) {
			var vs = 'tls';
			if (g('fingerprint') && val('fingerprint') != '')
				params += '&fp=' + val('fingerprint');
			if (checked('reality')) {
				vs = 'reality';
				params += query('pbk', 'reality_publicKey');
				params += query('sid', 'reality_shortId');
				params += query('spx', 'reality_spiderX');
				params += query('pqv', 'reality_mldsa65Verify');
			}
			if (g('flow') && val('flow'))
				params += '&flow=' + val('flow');
			params += '&security=' + vs;
			params += query('alpn', 'alpn');
			params += query('sni', 'tls_serverName');
			params += query('allowinsecure', 'tls_allowInsecure');
			params += query('pcs', 'tls_pinSHA256');
			params += query('vcn', 'tls_CertByName');
			params += query('ech', 'ech_config');
		}
		if (checked('tcp_fast_open')) params += '&tfo=1';
		if (checked('use_finalmask')) params += query('fm', 'finalmask');
		params += '#' + encodeURI(v_alias);
		if (params[0] == '&') params = params.substring(1);
		url += params;
	} else if (isCore && proto() === 'trojan') {
		protocol = 'trojan';
		url = encodeURIComponent(val('password')) + '@' + _address + ':' + val('port') + '/?';
		params = transportParams('trojan');
		var ts = 'none';
		if (checked('tls')) {
			ts = 'tls';
			if (g('fingerprint') && val('fingerprint') != '')
				params += '&fp=' + val('fingerprint');
			if (checked('reality')) {
				ts = 'reality';
				params += query('pbk', 'reality_publicKey');
				params += query('sid', 'reality_shortId');
				params += query('spx', 'reality_spiderX');
				params += query('pqv', 'reality_mldsa65Verify');
			}
			params += query('alpn', 'alpn');
			params += query('sni', 'tls_serverName');
			params += query('allowinsecure', 'tls_allowInsecure');
			params += query('pcs', 'tls_pinSHA256');
			params += query('vcn', 'tls_CertByName');
			params += query('ech', 'ech_config');
		}
		params += '&security=' + ts;
		if (checked('tcp_fast_open')) params += '&tfo=1';
		if (checked('use_finalmask')) params += query('fm', 'finalmask');
		params += '#' + encodeURI(v_alias);
		if (params[0] == '&') params = params.substring(1);
		url += params;
	} else if (isCore && proto() === 'hysteria2') {
		protocol = 'hysteria2';
		params = '';
		params += query('sni', 'tls_serverName');
		params += query('insecure', 'tls_allowInsecure');
		params += query('pinSHA256', 'tls_pinSHA256');
		params += query('pcs', 'tls_pinSHA256');
		params += query('vcn', 'tls_CertByName');
		if (g('hysteria2_obfs_type') && val('hysteria2_obfs_type') != '') {
			params += query('obfs', 'hysteria2_obfs_type');
			params += query('obfs-password', 'hysteria2_obfs_password');
			if (val('hysteria2_obfs_type') === 'gecko') {
				params += query('minPacketSize', 'hysteria2_obfs_MinPacketSize');
				params += query('maxPacketSize', 'hysteria2_obfs_MaxPacketSize');
			}
		}
		params += query('mport', 'hysteria2_hop');
		if (checked('use_finalmask')) params += query('fm', 'finalmask');
		params = params.replace(/^&/, '');
		url = _address + ':' + val('port') + '?' + params + '#' + encodeURI(v_alias);
		if (g('hysteria2_auth_password'))
			url = encodeURIComponent(val('hysteria2_auth_password')) + '@' + url;
	} else if (v_type === 'sing-box' && proto() === 'tuic') {
		protocol = 'tuic';
		url = encodeURIComponent(val('uuid')) + ':' + encodeURIComponent(val('password')) +
			'@' + _address + ':' + val('port') + '?';
		params = '';
		params += query('sni', 'tls_serverName');
		params += query('disable_sni', 'tls_disable_sni');
		params += query('alpn', 'tuic_alpn');
		params += query('congestion_control', 'tuic_congestion_control');
		params += query('udp_relay_mode', 'tuic_udp_relay_mode');
		params += query('allowinsecure', 'tls_allowInsecure');
		params += query('pcs', 'tls_pinSHA256');
		params += '#' + encodeURI(v_alias);
		if (params[0] == '&') params = params.substring(1);
		url += params;
	} else if (v_type === 'sing-box' && proto() === 'anytls') {
		protocol = 'anytls';
		url = encodeURIComponent(val('password')) + '@' + _address + ':' + val('port') + '?';
		params = '';
		if (checked('tls')) {
			var as = 'tls';
			if (g('fingerprint') && val('fingerprint') != '')
				params += '&fp=' + val('fingerprint');
			if (checked('reality')) {
				as = 'reality';
				params += query('pbk', 'reality_publicKey');
				params += query('sid', 'reality_shortId');
			}
			params += '&security=' + as;
			params += query('alpn', 'alpn');
			params += query('sni', 'tls_serverName');
			params += query('insecure', 'tls_allowInsecure');
			params += query('pcs', 'tls_pinSHA256');
		}
		params += '#' + encodeURI(v_alias);
		if (params[0] == '&') params = params.substring(1);
		url += params;
	} else if (v_type === 'sing-box' && proto() === 'naive') {
		protocol = 'naive+https';
		url = encodeURIComponent(val('username')) + ':' + encodeURIComponent(val('password')) +
			'@' + _address + ':' + val('port') + '?';
		params = 'security=tls';
		params += query('sni', 'tls_serverName');
		params += query('insecure-concurrency', 'naive_insecure_concurrency');
		params += query('ech', 'ech_config');
		params += query('uot', 'uot');
		if (checked('naive_quic')) {
			protocol = 'naive+quic';
			params += query('congestion_control', 'naive_congestion_control');
		}
		params += '#' + encodeURI(v_alias);
		if (params[0] == '&') params = params.substring(1);
		url += params;
	} else if (v_type === 'sing-box' && proto() === 'snell') {
		protocol = 'snell';
		var psk = val('snell_psk');
		url = encodeURIComponent(psk) + '@' + _address + ':' + val('port') + '?';
		params = 'psk=' + encodeURIComponent(psk);
		if (val('password') !== '')
			params += '&userkey=' + encodeURIComponent(val('password'));
		params += query('version', 'snell_version');
		if (val('snell_version') === '4') {
			params += query('obfs', 'snell_obfs_mode');
			params += query('obfs-host', 'snell_obfs_host');
		} else {
			params += query('mode', 'snell_mode');
		}
		params += query('reuse', 'snell_reuse');
		params += '#' + encodeURI(v_alias);
		if (params[0] == '&') params = params.substring(1);
		url += params;
	}

	if (url)
		return { url: protocol.toLowerCase() + '://' + url };
	return { error: 'unsupported', type: v_type };
}

/* -------------------------------------------------------------------- import */

function getCore(value, cands) {
	/* api.get_core: configured value if available, else first available candidate */
	if (value) {
		for (var i = 0; i < cands.length; i++)
			if (cands[i][0] && cands[i][1] === value)
				return value;
	}
	for (var j = 0; j < cands.length; j++)
		if (cands[j][0])
			return cands[j][1];
	return null;
}

function coreTypes(env) {
	/* env: { has_xray, has_singbox, has_ss_rust, conf: @global_subscribe[0] } */
	var c = env.conf || {};
	return {
		ss_type: getCore(c.ss_type, [[env.has_ss_rust, 'shadowsocks-rust'], [env.has_singbox, 'sing-box'], [env.has_xray, 'xray']]),
		trojan_type: getCore(c.trojan_type, [[env.has_singbox, 'sing-box'], [env.has_xray, 'xray']]),
		vmess_type: getCore(c.vmess_type, [[env.has_xray, 'xray'], [env.has_singbox, 'sing-box']]),
		vless_type: getCore(c.vless_type, [[env.has_xray, 'xray'], [env.has_singbox, 'sing-box']]),
		hysteria2_type: getCore(c.hysteria2_type, [[env.has_singbox, 'sing-box'], [env.has_xray, 'xray']])
	};
}

function parse(link, env) {
	env = env || {};
	var has_xray = !!env.has_xray, has_singbox = !!env.has_singbox;
	var ss_type = env.ss_type, trojan_type = env.trojan_type, vmess_type = env.vmess_type,
		vless_type = env.vless_type, hysteria2_type = env.hysteria2_type;
	var fields = {};
	var type = null;
	var prefix = null; /* null = no core selected (upstream dom_prefix) */
	var set = function(k, v) { if (prefix !== null || k === 'remarks') fields[k] = v; };
	var invalid = function() { return { ok: false, error: 'invalid' }; };

	if (!link)
		return invalid();
	link = String(link).split(/\r\n|\r|\n/, 1)[0];
	link = link.replace(/&amp;/gi, '&').replace(/\s*#\s*/, '#').trim();
	var link_split = link.split('://');
	var link_type = link_split[0];
	var rest = link_split[1] || '';

	var wsEarly = function(path) {
		if (prefix == 'singbox' && path && path.length > 1) {
			var dat = path.split('?');
			var pp = {};
			var arr = (dat[1] || '').split('&');
			for (var i = 0; i < arr.length; i++) {
				var kv = arr[i].split('=');
				pp[safeDecode(kv[0]).toLowerCase()] = safeDecode(kv[1] || '');
			}
			if (pp.ed) {
				set('ws_path', dat[0]);
				set('ws_enableEarlyData', true);
				set('ws_maxEarlyData', pp.ed);
				set('ws_earlyDataHeaderName', 'Sec-WebSocket-Protocol');
			}
		}
	};

	var transport = function(q, variant) {
		/* q.type already lower-cased and normalized by caller */
		var t = q.type;
		if (prefix == 'xray' && t === 'http')
			set('transport', 'xhttp');
		else if (t !== undefined)
			set('transport', t);
		if (t === 'raw' || t === 'tcp') {
			set('tcp_guise', q.headerType || 'none');
			if (q.headerType && q.headerType != 'none') {
				set('tcp_guise_http_host', q.host || '');
				set('tcp_guise_http_path', q.path || '');
			}
		} else if (t === 'ws') {
			set('ws_host', q.host || '');
			set('ws_path', q.path || '');
			wsEarly(q.path);
		} else if (t === 'http') {
			if (prefix == 'xray') {
				set('xhttp_mode', 'stream-one');
				set('xhttp_host', q.host || '');
				set('xhttp_path', q.path || '');
			} else {
				set('http_host', q.host || '');
				set('http_path', q.path || '');
			}
		} else if (t === 'quic') {
			set('quic_guise', q.headerType || 'none');
			set('quic_security', q.quicSecurity);
			set('quic_key', q.key);
		} else if (t === 'mkcp') {
			set('mkcp_guise', q.headerType || 'none');
			set('mkcp_seed', q.seed || '');
		} else if (t === 'grpc') {
			set('grpc_serviceName', (q.serviceName || q.path) || '');
			set('grpc_mode', q.mode || 'gun');
		} else if ((t === 'xhttp' && variant !== 'trojan') || (t === 'splithttp' && variant === 'vless')) {
			set('xhttp_host', q.host || '');
			set('xhttp_path', q.path || '');
			set('xhttp_mode', q.mode || 'auto');
			set('use_xhttp_extra', !!q.extra);
			set('xhttp_extra', q.extra || '');
		} else if (t === 'httpupgrade' && variant === 'vless') {
			set('httpupgrade_host', q.host || '');
			set('httpupgrade_path', q.path || '');
		}
	};

	var normType = function(t) {
		if (t === 'kcp' || t === 'mkcp') t = 'mkcp';
		if (t === 'h2') t = 'http';
		if (prefix == 'singbox' && t === 'raw') t = 'tcp';
		else if (prefix == 'xray' && t === 'tcp') t = 'raw';
		return t;
	};

	var tlsBlock = function(q, withFlow, sniVal) {
		if (q.security == 'tls') {
			set('tls', true);
			set('reality', false);
			if (withFlow) set('flow', q.flow || '');
			set('alpn', q.alpn || 'default');
			set('tls_serverName', sniVal);
			set('tls_allowInsecure', insecure(q, ['allowinsecure', 'allowInsecure', 'insecure']));
			if (q.fp && q.fp.trim() != '') {
				set('utls', true);
				set('fingerprint', q.fp);
			}
			set('ech', !!q.ech);
			set('ech_config', q.ech || '');
			set('tls_pinSHA256', q.pcs || '');
			set('tls_CertByName', q.vcn || '');
		}
		if (q.security == 'reality') {
			set('tls', true);
			set('reality', true);
			if (withFlow) set('flow', q.flow || '');
			set('alpn', q.alpn || 'default');
			set('tls_serverName', sniVal);
			if (q.fp && q.fp.trim() != '') {
				set('utls', true);
				set('fingerprint', q.fp);
			}
			set('reality_publicKey', q.pbk || '');
			set('reality_shortId', q.sid || '');
			set('reality_spiderX', q.spx || '');
			set('use_mldsa65Verify', !!q.pqv);
			set('reality_mldsa65Verify', q.pqv || '');
		}
	};

	var useCore = function(t) {
		type = t;
		prefix = (t === 'sing-box') ? 'singbox' : (t === 'Xray' ? 'xray' : (t === 'SS-Rust' ? 'ssrust' : 'ssr'));
		fields.type = t;
	};

	try {
		if (link_type === 'ssr') {
			var sstr = b64decsafe(rest.replace(/#.*/, '').trim());
			var ploc = sstr.indexOf('/?');
			var url0 = sstr, param = '';
			if (ploc > 0) {
				url0 = sstr.substr(0, ploc);
				param = sstr.substr(ploc + 2);
			}
			var ssm = url0.match(/^(.+):([^:]+):([^:]*):([^:]+):([^:]*):([^:]+)/);
			if (!ssm || ssm.length < 7)
				return invalid();
			var pdict = {};
			if (param.length > 2) {
				var a = param.split('&');
				for (var i = 0; i < a.length; i++) {
					var b = a[i].split('=');
					pdict[safeDecode(b[0])] = safeDecode(b[1] || '');
				}
			}
			useCore('SSR');
			set('address', unbracketIP(ssm[1]));
			set('port', ssm[2]);
			set('protocol', ssm[3]);
			set('method', ssm[4]);
			set('obfs', ssm[5]);
			set('password', binToStr(b64decsafe(ssm[6])));
			set('obfs_param', binToStr(dictvalue(pdict, 'obfsparam')));
			set('protocol_param', binToStr(dictvalue(pdict, 'protoparam')));
			var rem = pdict.remarks;
			if (typeof (rem) !== 'undefined' && rem !== '')
				set('remarks', b64decutf8safe(rem));
		}
		else if (link_type === 'ss') {
			var u0 = rest, sparam = '';
			var hloc = u0.indexOf('#');
			if (hloc >= 0) {
				sparam = u0.substr(hloc + 1);
				u0 = u0.substr(0, hloc);
			}
			u0 = u0.replace('/?', '?');
			var qi = u0.indexOf('?');
			var queryStr = '';
			if (qi >= 0) {
				queryStr = u0.substr(qi + 1);
				u0 = u0.substr(0, qi);
			}
			var qp = Object.fromEntries(new URLSearchParams(queryStr));
			var server, port, method, password, plugin, pluginOpts;
			var sip = u0.indexOf('@');
			if (sip !== -1) {
				var userInfo = binToStr(b64decsafe(safeDecode(u0.substr(0, sip))));
				var serverInfo = u0.substr(sip + 1).split(':');
				server = serverInfo[0];
				port = serverInfo[1];
				var ui = userInfo.indexOf(':');
				if (ui !== -1) {
					method = userInfo.substr(0, ui);
					password = userInfo.substr(ui + 1);
				} else {
					password = u0.substr(0, sip);
				}
			} else {
				var s2 = binToStr(b64decsafe(safeDecode(u0)));
				var m2022 = s2.match(/^([^:]+):([^:]+):([^@]+)@([^:]+):(\d+)$/);
				var mNormal = s2.match(/^([^:]+):([^@]+)@([^:]+):(\d+)$/);
				if (m2022) {
					method = m2022[1]; password = m2022[2] + ':' + m2022[3]; server = m2022[4]; port = m2022[5];
				} else if (mNormal) {
					method = mNormal[1]; password = mNormal[2]; server = mNormal[3]; port = mNormal[4];
				}
			}
			if (qp.plugin) {
				var pps = safeDecode(qp.plugin).split(';');
				plugin = pps.shift();
				pluginOpts = pps.join(';');
			}
			/* upstream quirk: compares against "Xray" (capital X), effectively ss_type!=='sing-box' */
			var needUpgrade = ss_type !== 'Xray' && ss_type !== 'sing-box' &&
				qp.type && qp.type !== 'tcp' && qp.headerType && qp.headerType !== 'none';
			if (has_xray && (ss_type == 'xray' || needUpgrade || qp.type === 'xhttp')) {
				useCore('Xray');
				set('protocol', 'shadowsocks');
			} else if (has_singbox && (ss_type == 'sing-box' || needUpgrade)) {
				useCore('sing-box');
				set('protocol', 'shadowsocks');
			} else if (ss_type == 'shadowsocks-rust') {
				useCore('SS-Rust');
			}
			var _m = (method || 'none').toLowerCase();
			var mapping = { 'chacha20-poly1305': 'chacha20-ietf-poly1305', 'xchacha20-poly1305': 'xchacha20-ietf-poly1305' };
			method = mapping[_m] || _m;
			set('address', unbracketIP(server));
			set('port', port);
			set('password', password || '');
			set('method', method || '');
			set('ss_method', method || '');
			set('tcp_fast_open', qp.tfo);
			if (plugin && plugin != 'none') {
				plugin = (plugin === 'simple-obfs') ? 'obfs-local' : plugin;
				set('plugin_enabled', true);
				set('plugin', plugin || 'none');
				set('plugin_opts', pluginOpts || '');
				if (plugin == 'obfs-local' && prefix == 'xray') {
					var obfs = (pluginOpts || '').match(/obfs=([^;]+)/);
					var obfs_host = (pluginOpts || '').match(/obfs-host=([^;]+)/);
					obfs = obfs ? obfs[1] : '';
					obfs_host = obfs_host ? obfs_host[1] : '';
					if (obfs === 'http') {
						set('transport', 'raw');
						set('tcp_guise', 'http');
						set('tcp_guise_http_host', obfs_host || '');
						set('tcp_guise_http_path', '/');
					} else if (obfs === 'tls') {
						set('tls', true);
						set('tls_serverName', obfs_host || '');
						set('tls_allowInsecure', true);
					}
				}
				if (plugin === 'shadow-tls') {
					pluginOpts = (pluginOpts || '').replace(/(^|;)password=/, '$1passwd=');
					pluginOpts = pluginOpts.replace(/(^|;)version=([123])(?=;|$)/, '$1v$2=1');
					if (prefix === 'ssrust') {
						set('plugin_opts', pluginOpts || '');
					} else if (prefix === 'singbox') {
						var opts = Object.fromEntries(pluginOpts.split(';').map(function(item) { return item.split('=', 2); }));
						var vk = Object.keys(opts).find(function(key) { return /^v[123]$/.test(key); });
						set('shadowtls', true);
						set('shadowtls_version', vk ? vk.slice(1) : '1');
						set('shadowtls_password', opts.passwd || '');
						set('shadowtls_serverName', opts.host || '');
						set('plugin_enabled', false);
					}
				}
			} else {
				set('plugin', 'none');
			}
			set('remarks', safeDecode(sparam));
			if (Object.keys(qp).length > 0 && !qp.plugin) {
				if (qp.security)
					tlsBlock(qp, false, qp.sni || '');
				qp.type = qp.type ? normType(qp.type.toLowerCase()) : undefined;
				transport(qp, 'ss');
				set('uot', qp.udp);
				set('use_finalmask', !!qp.fm);
				set('finalmask', qp.fm || '');
				if (qp['shadow-tls']) {
					var stObj = {};
					var stStr = '';
					try {
						stObj = JSON.parse(binToStr(b64decsafe(qp['shadow-tls'])));
						var out = [];
						if (stObj.version) out.push('v' + stObj.version + '=1');
						if (stObj.password) out.push('passwd=' + stObj.password);
						for (var k in stObj)
							if (k !== 'version' && k !== 'password')
								out.push(k + '=' + stObj[k]);
						stStr = out.join(';');
					} catch (e) { stObj = {}; stStr = ''; }
					if (prefix === 'ssrust') {
						set('plugin_enabled', true);
						set('plugin', 'shadow-tls');
						set('plugin_opts', stStr || '');
					} else if (prefix === 'singbox') {
						if (stObj && Object.keys(stObj).length > 0) {
							set('shadowtls', true);
							set('shadowtls_version', stObj.version || '1');
							set('shadowtls_password', stObj.password || '');
							set('shadowtls_serverName', stObj.host || '');
							if (stObj.fingerprint) {
								set('shadowtls_utls', true);
								set('shadowtls_fingerprint', stObj.fingerprint || 'chrome');
							}
						}
					}
				}
			}
		}
		else if (link_type === 'trojan') {
			useCore((trojan_type == 'sing-box' && has_singbox) ? 'sing-box' : 'Xray');
			set('protocol', 'trojan');
			var tm = parseNodeUrl(link);
			if (tm.passwd === '')
				return invalid();
			var tq = parseQuery(tm.search, false, true);
			set('mux', tq.mux === '1');
			set('address', unbracketIP(tm.hostname));
			set('port', tm.port || '443');
			set('password', safeDecode(tm.passwd));
			tq.type = normType(tq.type ? tq.type.toLowerCase() : 'tcp');
			transport(tq, 'trojan');
			tq.security = tq.security || 'tls';
			if (tq.security == 'tls') {
				set('tls', true);
				set('reality', false);
				set('alpn', tq.alpn || 'default');
				set('tls_serverName', tq.peer || tq.sni || '');
				if (tq.fp && tq.fp.trim() != '') {
					set('utls', true);
					set('fingerprint', tq.fp);
				}
				set('ech', !!tq.ech);
				set('ech_config', tq.ech || '');
				set('tls_pinSHA256', tq.pcs || '');
				set('tls_CertByName', tq.vcn || '');
				set('tls_allowInsecure', insecure(tq, ['allowinsecure', 'allowInsecure', 'insecure']));
			}
			if (tq.security == 'reality') {
				set('tls', true);
				set('reality', true);
				set('alpn', tq.alpn || 'default');
				set('tls_serverName', tq.peer || tq.sni || '');
				if (tq.fp && tq.fp.trim() != '') {
					set('utls', true);
					set('fingerprint', tq.fp);
				}
				set('reality_publicKey', tq.pbk || '');
				set('reality_shortId', tq.sid || '');
			}
			set('tcp_fast_open', tq.tfo);
			set('use_finalmask', !!tq.fm);
			set('finalmask', tq.fm || '');
			if (tm.hash)
				set('remarks', safeDecode(tm.hash.substr(1)));
		}
		else if (link_type === 'vmess') {
			var vstr = b64DecodeUnicode(rest.replace(/#.*/, '').trim());
			if (vmess_type == 'sing-box' && has_singbox)
				useCore('sing-box');
			else if (has_xray)
				useCore('Xray');
			set('protocol', 'vmess');
			var vm = {};
			if (is_json(vstr)) {
				vm = JSON.parse(vstr);
			} else if (vstr.indexOf('?') > 0) {
				vstr = vstr.replace('/?', '?');
				var vploc = vstr.indexOf('?');
				var vurl0 = vstr.substr(0, vploc);
				var paramStr = vstr.substr(vploc + 2);
				var vu = new URL('https://' + b64decsafe(vurl0));
				if (vu.username !== '') {
					vm.security = vu.username;
					vm.id = vu.password || vu.username;
				} else {
					vm.security = 'auto';
					vm.id = vu.password || vu.username;
				}
				vm.add = unbracketIP(vu.hostname);
				vm.port = vu.port || '443';
				var vparams = {};
				var pairs = paramStr.split('&');
				for (var pi = 0; pi < pairs.length; pi++) {
					var pv = pairs[pi];
					var si = pv.indexOf('=');
					if (si > 0)
						vparams[pv.substring(0, si)] = safeDecode(pv.substring(si + 1));
				}
				vm.ps = vparams.remark || vparams.remarks;
				vm.net = (vparams.obfs === 'websocket') ? 'ws' : (vparams.obfs || 'tcp');
				vm.path = vparams.path;
				vm.aid = vparams.alterId || '0';
				vm.tls = vparams.tls;
				vm.sni = vparams.peer;
				vm.tfo = vparams.tfo;
				if (is_json(vparams.obfsParam)) {
					var op = JSON.parse(vparams.obfsParam);
					if (op.header) vm.type = op.header;
					if (op.Host) vm.host = op.Host;
				} else {
					vm.host = vparams.obfsParam;
				}
				vm.allowinsecure = vparams.allowInsecure;
			} else {
				return invalid();
			}
			var str = function(x) { return (x === undefined || x === null) ? undefined : String(x); };
			set('remarks', str(vm.ps));
			set('address', unbracketIP(str(vm.add)));
			set('port', str(vm.port));
			set('uuid', str(vm.id));
			set('security', vm.security || vm.scy || 'auto');
			var vtls = (vm.tls === 'tls' || vm.tls === '1');
			set('tls', vtls);
			if (vtls) {
				set('tls_serverName', vm.sni || vm.host);
				set('alpn', vm.alpn || 'default');
				if (vm.fp && vm.fp !== '') {
					set('utls', true);
					set('fingerprint', vm.fp);
				}
				set('tls_pinSHA256', vm.pcs || '');
				set('tls_allowInsecure', insecure(vm, ['allowinsecure', 'allowInsecure', 'insecure']));
			}
			/* upstream throws when `net` is missing; default to tcp instead */
			var net = normType(String(vm.net || 'tcp').toLowerCase());
			if (net === 'http' || net === 'h2') net = 'http';
			if (prefix == 'xray' && net === 'http')
				set('transport', 'xhttp');
			else
				set('transport', net);
			if (net === 'raw' || net === 'tcp') {
				set('tcp_guise', (vm.host && vm.host != '') ? 'http' : 'none');
				if (vm.host && vm.host != '') {
					set('tcp_guise_http_host', vm.host);
					set('tcp_guise_http_path', vm.path || '');
				}
			} else if (net === 'ws') {
				set('ws_host', vm.host);
				set('ws_path', vm.path);
				wsEarly(vm.path);
			} else if (net === 'http') {
				if (prefix == 'xray') {
					set('xhttp_mode', 'stream-one');
					set('xhttp_host', vm.host || '');
					set('xhttp_path', vm.path || '');
				} else {
					set('http_host', vm.host || '');
					set('http_path', vm.path || '');
				}
			} else if (net === 'quic') {
				set('quic_security', vm.securty);
				set('quic_key', vm.key);
			} else if (net === 'mkcp') {
				set('mkcp_guise', vm.type || 'none');
				set('mkcp_seed', vm.seed || '');
			} else if (net === 'grpc') {
				set('grpc_serviceName', vm.path);
			}
			set('tcp_fast_open', vm.tfo);
			set('use_finalmask', !!vm.fm);
			set('finalmask', vm.fm || '');
		}
		else if (link_type === 'vless') {
			var vlm = parseNodeUrl(link);
			if (vlm.passwd === '')
				return invalid();
			var vq = parseQuery(vlm.search, false, true);
			/* upstream throws when `type` is absent; default to tcp instead */
			vq.type = (vq.type || 'tcp').toLowerCase();
			var vlcore = (vless_type == 'sing-box' && has_singbox) ? 'sing-box' : 'Xray';
			if (['xhttp', 'kcp', 'mkcp'].includes(vq.type) && vless_type !== 'xray' && has_xray)
				vlcore = 'Xray';
			useCore(vlcore);
			set('protocol', 'vless');
			set('uuid', vlm.passwd);
			set('address', unbracketIP(vlm.hostname));
			set('port', vlm.port || '443');
			set('encryption', vq.encryption || 'none');
			vq.security = (!vq.security && vq.flow) ? 'tls' : vq.security;
			if (vq.security)
				tlsBlock(vq, true, vq.sni || '');
			vq.type = normType(vq.type);
			transport(vq, 'vless');
			set('tcp_fast_open', vq.tfo);
			set('use_finalmask', !!vq.fm);
			set('finalmask', vq.fm || '');
			if (vlm.hash)
				set('remarks', safeDecode(vlm.hash.substr(1)));
		}
		else if (link_type === 'hysteria2' || link_type === 'hy2') {
			var hm = parseNodeUrl(link);
			if (hm.passwd === '')
				return invalid();
			var hq = parseQuery(hm.search, false, true);
			if ((hysteria2_type == 'sing-box' && has_singbox) || (hysteria2_type == 'xray' && has_xray)) {
				useCore((hysteria2_type == 'sing-box' && has_singbox) ? 'sing-box' : 'Xray');
				set('protocol', 'hysteria2');
				set('hysteria2_auth_password', safeDecode(hm.passwd));
				if (hq['obfs-password'] || hq.obfs_password) {
					set('hysteria2_obfs_type', hq.obfs || 'salamander');
					set('hysteria2_obfs_password', hq['obfs-password'] || hq.obfs_password);
				}
				if (hq.obfs === 'gecko') {
					set('hysteria2_obfs_MinPacketSize', hq.minPacketSize || '512');
					set('hysteria2_obfs_MaxPacketSize', hq.maxPacketSize || '1200');
				}
				set('hysteria2_hop', hq.mport || '');
				set('use_finalmask', !!hq.fm);
				set('finalmask', hq.fm || '');
			}
			set('address', unbracketIP(hm.hostname));
			set('port', hm.port || '443');
			set('tls_serverName', hq.sni || '');
			set('tls_allowInsecure', insecure(hq, ['allowinsecure', 'allowInsecure', 'insecure']));
			set('tls_pinSHA256', hq.pcs || hq.pinSHA256 || '');
			set('tls_CertByName', hq.vcn || '');
			if (hm.hash)
				set('remarks', safeDecode(hm.hash.substr(1)));
		}
		else if (link_type === 'tuic') {
			if (has_singbox)
				useCore('sing-box');
			set('protocol', 'tuic');
			var tu = new URL('https://' + rest);
			var username = tu.username, tpass = tu.password;
			if (!username || !tpass) {
				var decoded = safeDecode(username || tpass || '');
				var ci = decoded.indexOf(':');
				if (ci > -1) {
					username = decoded.slice(0, ci);
					tpass = decoded.slice(ci + 1);
				}
			}
			set('uuid', safeDecode(username));
			set('password', safeDecode(tpass));
			set('address', unbracketIP(tu.hostname));
			set('port', tu.port || '443');
			var tuq = parseQuery(tu.search, true, false);
			set('tuic_congestion_control', tuq.congestion_control || 'cubic');
			set('tuic_udp_relay_mode', tuq.udp_relay_mode || 'native');
			set('tuic_alpn', tuq.alpn || 'h3');
			set('tls_serverName', tuq.sni || '');
			set('tls_disable_sni', tuq.disable_sni === '1');
			set('tls_allowInsecure', insecure(tuq, ['allowinsecure', 'insecure', 'allow_insecure']));
			/* keys are lower-cased, so upstream's `pinSHA256` lookup never matched */
			set('tls_pinSHA256', tuq.pcs || tuq.pinsha256 || '');
			if (tu.hash)
				set('remarks', safeDecode(tu.hash.substr(1)));
		}
		else if (link_type === 'anytls') {
			if (has_singbox)
				useCore('sing-box');
			set('protocol', 'anytls');
			var am = parseNodeUrl(link);
			if (am.passwd === '')
				return invalid();
			set('password', am.passwd);
			set('address', unbracketIP(am.hostname));
			set('port', am.port || '443');
			var aq = parseQuery(am.search, true, true);
			aq.security = aq.security || 'tls';
			set('tls', true);
			if (aq.security == 'tls')
				set('reality', false);
			if (aq.security == 'reality') {
				set('reality', true);
				set('reality_publicKey', aq.pbk || '');
				set('reality_shortId', aq.sid || '');
			}
			set('alpn', aq.alpn || 'default');
			set('tls_serverName', aq.sni || aq.peer || '');
			if (aq.fp && aq.fp.trim() != '') {
				set('utls', true);
				set('fingerprint', aq.fp);
			}
			set('tls_allowInsecure', insecure(aq, ['allowinsecure', 'insecure']));
			set('tls_pinSHA256', aq.pcs || aq.pinsha256 || '');
			if (am.hash)
				set('remarks', safeDecode(am.hash.substr(1)));
		}
		else if (link_type === 'naive+https' || link_type === 'naive+quic') {
			if (has_singbox)
				useCore('sing-box');
			set('protocol', 'naive');
			var nu = new URL('https://' + rest);
			var nuser = nu.username, npass = nu.password;
			if (rest.split('@', 1)[0].indexOf(':') === -1) {
				npass = nuser;
				nuser = '';
			}
			set('username', safeDecode(nuser));
			set('password', safeDecode(npass));
			set('address', unbracketIP(nu.hostname));
			set('port', nu.port || '443');
			var nq = parseQuery(nu.search, false, false);
			set('naive_insecure_concurrency', nq['insecure-concurrency'] || '0');
			set('uot', (nq.uot ?? '0') === '1');
			set('tls_serverName', nq.sni || '');
			set('ech', !!nq.ech);
			set('ech_config', nq.ech || '');
			if (link_type === 'naive+quic') {
				set('naive_quic', true);
				set('naive_congestion_control', nq.congestion_control || 'bbr');
			}
			if (nu.hash)
				set('remarks', safeDecode(nu.hash.substr(1)));
		}
		else if (link_type === 'snell') {
			if (has_singbox)
				useCore('sing-box');
			set('protocol', 'snell');
			var sm = parseNodeUrl(link);
			set('address', unbracketIP(sm.hostname));
			set('port', sm.port || '443');
			var sq = parseQuery(sm.search, true, true);
			set('password', sq.userkey || '');
			set('snell_psk', sq.psk || sm.passwd || '');
			set('snell_version', sq.version || '4');
			set('snell_reuse', sq.reuse === '1');
			set('snell_obfs_mode', sq.obfs || 'none');
			set('snell_obfs_host', sq['obfs-host'] || sq.obfs_host || '');
			set('snell_mode', sq.mode || 'default');
			if (sm.hash)
				set('remarks', safeDecode(sm.hash.substr(1)));
		}
	} catch (e) {
		return { ok: false, error: 'invalid', exception: String(e) };
	}

	if (!prefix)
		return invalid();
	return { ok: true, type: type, protocol: fields.protocol, fields: fields };
}

/* Checkbox semantics of upstream opt.set(): `checked = val` (JS truthiness).
 * upstream quirk: the string "0" is truthy, so `tfo=0` enabled TFO; we treat
 * "0"/"false" as unchecked. */
function truthy(v) {
	if (v === '0' || v === 'false') return false;
	return !!v;
}

/* ------------------------------------------------------------------- QR code */
/* Byte-mode QR encoder (ISO/IEC 18004), ECC level M, versions 1..40, best mask. */

var QR_ECC_CW = {
	L: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
	M: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28]
};
var QR_ECC_BLOCKS = {
	L: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
	M: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49]
};
var QR_FORMAT_BITS = { L: 1, M: 0 };

function qrRawModules(ver) {
	var r = (16 * ver + 128) * ver + 64;
	if (ver >= 2) {
		var na = Math.floor(ver / 7) + 2;
		r -= (25 * na - 10) * na - 55;
		if (ver >= 7) r -= 36;
	}
	return r;
}

function qrDataCodewords(ver, ecl) {
	return Math.floor(qrRawModules(ver) / 8) - QR_ECC_CW[ecl][ver] * QR_ECC_BLOCKS[ecl][ver];
}

function gfMul(x, y) {
	var z = 0;
	for (var i = 7; i >= 0; i--) {
		z = (z << 1) ^ ((z >>> 7) * 0x11D);
		z ^= ((y >>> i) & 1) * x;
	}
	return z & 0xFF;
}

function rsDivisor(degree) {
	var res = [];
	for (var i = 0; i < degree - 1; i++) res.push(0);
	res.push(1);
	var root = 1;
	for (var k = 0; k < degree; k++) {
		for (var j = 0; j < res.length; j++) {
			res[j] = gfMul(res[j], root);
			if (j + 1 < res.length) res[j] ^= res[j + 1];
		}
		root = gfMul(root, 0x02);
	}
	return res;
}

function rsRemainder(data, divisor) {
	var res = divisor.map(function() { return 0; });
	for (var i = 0; i < data.length; i++) {
		var factor = data[i] ^ res.shift();
		res.push(0);
		for (var j = 0; j < divisor.length; j++)
			res[j] ^= gfMul(divisor[j], factor);
	}
	return res;
}

function qrAlignPositions(ver) {
	if (ver == 1) return [];
	var size = ver * 4 + 17;
	var na = Math.floor(ver / 7) + 2;
	var step = (ver == 32) ? 26 : Math.ceil((ver * 4 + 4) / (na * 2 - 2)) * 2;
	var res = [6];
	for (var pos = size - 7; res.length < na; pos -= step)
		res.splice(1, 0, pos);
	return res;
}

function qrEncode(text, ecl) {
	ecl = ecl || 'M';
	var bin = utf8Bytes(String(text));
	var bytes = [];
	for (var i = 0; i < bin.length; i++) bytes.push(bin.charCodeAt(i));

	var ver;
	for (ver = 1; ver <= 40; ver++) {
		var ccBits = ver <= 9 ? 8 : 16;
		if (4 + ccBits + bytes.length * 8 <= qrDataCodewords(ver, ecl) * 8) break;
	}
	if (ver > 40) {
		if (ecl === 'M') return qrEncode(text, 'L');
		throw new Error('Data too long for a QR code');
	}

	var bits = [];
	var push = function(val, len) { for (var b = len - 1; b >= 0; b--) bits.push((val >>> b) & 1); };
	push(0x4, 4);
	push(bytes.length, ver <= 9 ? 8 : 16);
	bytes.forEach(function(b) { push(b, 8); });
	var capBits = qrDataCodewords(ver, ecl) * 8;
	push(0, Math.min(4, capBits - bits.length));
	push(0, (8 - bits.length % 8) % 8);
	for (var pad = 0xEC; bits.length < capBits; pad ^= 0xEC ^ 0x11) push(pad, 8);
	var data = [];
	for (var d = 0; d < bits.length; d += 8) {
		var v = 0;
		for (var e = 0; e < 8; e++) v = (v << 1) | bits[d + e];
		data.push(v);
	}

	/* ECC and interleave */
	var numBlocks = QR_ECC_BLOCKS[ecl][ver];
	var blockEcc = QR_ECC_CW[ecl][ver];
	var rawCw = Math.floor(qrRawModules(ver) / 8);
	var numShort = numBlocks - rawCw % numBlocks;
	var shortLen = Math.floor(rawCw / numBlocks);
	var blocks = [];
	var div = rsDivisor(blockEcc);
	for (var bi = 0, k = 0; bi < numBlocks; bi++) {
		var dat = data.slice(k, k + shortLen - blockEcc + (bi < numShort ? 0 : 1));
		k += dat.length;
		var ecc = rsRemainder(dat, div);
		if (bi < numShort) dat.push(0);
		blocks.push(dat.concat(ecc));
	}
	var codewords = [];
	for (var ci = 0; ci < blocks[0].length; ci++)
		for (var bj = 0; bj < blocks.length; bj++)
			if (ci != shortLen - blockEcc || bj >= numShort)
				codewords.push(blocks[bj][ci]);

	return { version: ver, ecl: ecl, codewords: codewords, blocks: { num: numBlocks, ecc: blockEcc, numShort: numShort, shortLen: shortLen } };
}

function qrBuildMatrix(enc, mask) {
	var ver = enc.version;
	var size = ver * 4 + 17;
	var mod = [], fn = [];
	for (var y = 0; y < size; y++) {
		mod.push(new Array(size).fill(false));
		fn.push(new Array(size).fill(false));
	}
	var setF = function(x, y, dark) { mod[y][x] = dark; fn[y][x] = true; };

	for (var i = 0; i < size; i++) {
		setF(6, i, i % 2 == 0);
		setF(i, 6, i % 2 == 0);
	}
	var finder = function(cx, cy) {
		for (var dy = -4; dy <= 4; dy++)
			for (var dx = -4; dx <= 4; dx++) {
				var dist = Math.max(Math.abs(dx), Math.abs(dy));
				var xx = cx + dx, yy = cy + dy;
				if (xx >= 0 && xx < size && yy >= 0 && yy < size)
					setF(xx, yy, dist != 2 && dist != 4);
			}
	};
	finder(3, 3);
	finder(size - 4, 3);
	finder(3, size - 4);
	var ap = qrAlignPositions(ver);
	var na = ap.length;
	for (var ai = 0; ai < na; ai++)
		for (var aj = 0; aj < na; aj++) {
			if ((ai == 0 && aj == 0) || (ai == 0 && aj == na - 1) || (ai == na - 1 && aj == 0))
				continue;
			for (var ady = -2; ady <= 2; ady++)
				for (var adx = -2; adx <= 2; adx++)
					setF(ap[ai] + adx, ap[aj] + ady, Math.max(Math.abs(adx), Math.abs(ady)) != 1);
		}

	var drawFormat = function(m) {
		var data = (QR_FORMAT_BITS[enc.ecl] << 3) | m;
		var rem = data;
		for (var r = 0; r < 10; r++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
		var bits = ((data << 10) | rem) ^ 0x5412;
		var bit = function(n) { return ((bits >>> n) & 1) != 0; };
		for (var a = 0; a <= 5; a++) setF(8, a, bit(a));
		setF(8, 7, bit(6));
		setF(8, 8, bit(7));
		setF(7, 8, bit(8));
		for (var b = 9; b < 15; b++) setF(14 - b, 8, bit(b));
		for (var c = 0; c < 8; c++) setF(size - 1 - c, 8, bit(c));
		for (var d = 8; d < 15; d++) setF(8, size - 15 + d, bit(d));
		setF(8, size - 8, true);
	};
	drawFormat(0);
	if (ver >= 7) {
		var rem = ver;
		for (var r = 0; r < 12; r++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1F25);
		var vbits = (ver << 12) | rem;
		for (var vi = 0; vi < 18; vi++) {
			var vb = ((vbits >>> vi) & 1) != 0;
			var va = size - 11 + vi % 3, vbb = Math.floor(vi / 3);
			setF(va, vbb, vb);
			setF(vbb, va, vb);
		}
	}

	/* codewords zigzag */
	var data = enc.codewords;
	var idx = 0;
	for (var right = size - 1; right >= 1; right -= 2) {
		if (right == 6) right = 5;
		for (var vert = 0; vert < size; vert++)
			for (var j = 0; j < 2; j++) {
				var x = right - j;
				var upward = ((right + 1) & 2) == 0;
				var yy = upward ? size - 1 - vert : vert;
				if (!fn[yy][x] && idx < data.length * 8) {
					mod[yy][x] = ((data[idx >>> 3] >>> (7 - (idx & 7))) & 1) != 0;
					idx++;
				}
			}
	}

	var maskFn = [
		function(x, y) { return (x + y) % 2 == 0; },
		function(x, y) { return y % 2 == 0; },
		function(x, y) { return x % 3 == 0; },
		function(x, y) { return (x + y) % 3 == 0; },
		function(x, y) { return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 == 0; },
		function(x, y) { return x * y % 2 + x * y % 3 == 0; },
		function(x, y) { return (x * y % 2 + x * y % 3) % 2 == 0; },
		function(x, y) { return ((x + y) % 2 + x * y % 3) % 2 == 0; }
	][mask];
	for (var my = 0; my < size; my++)
		for (var mx = 0; mx < size; mx++)
			if (!fn[my][mx] && maskFn(mx, my))
				mod[my][mx] = !mod[my][mx];
	drawFormat(mask);
	return { size: size, modules: mod, isFunction: fn };
}

function qrPenalty(mod) {
	var size = mod.length, score = 0, dark = 0;
	var runScore = function(line) {
		var s = 0, run = 1;
		for (var i = 1; i <= line.length; i++) {
			if (i < line.length && line[i] === line[i - 1]) { run++; continue; }
			if (run >= 5) s += 3 + (run - 5);
			run = 1;
		}
		return s;
	};
	var finderLike = function(line) {
		var s = 0, str = line.map(function(b) { return b ? '1' : '0'; }).join('');
		var re = /(?=(10111010000|00001011101))/g;
		while (re.exec(str)) { s += 40; re.lastIndex++; }
		return s;
	};
	for (var y = 0; y < size; y++) {
		var col = [];
		for (var x = 0; x < size; x++) {
			col.push(mod[x][y]);
			if (mod[y][x]) dark++;
			if (x < size - 1 && y < size - 1) {
				var c = mod[y][x];
				if (c === mod[y][x + 1] && c === mod[y + 1][x] && c === mod[y + 1][x + 1]) score += 3;
			}
		}
		score += runScore(mod[y]) + runScore(col) + finderLike(mod[y]) + finderLike(col);
	}
	var total = size * size;
	var kk = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
	score += Math.max(0, kk) * 10;
	return score;
}

function qrMatrix(text) {
	var enc = qrEncode(text);
	var best = null, bestScore = Infinity;
	for (var m = 0; m < 8; m++) {
		var mat = qrBuildMatrix(enc, m);
		var p = qrPenalty(mat.modules);
		if (p < bestScore) { bestScore = p; best = mat; best.mask = m; }
	}
	best.version = enc.version;
	best.ecl = enc.ecl;
	return best;
}

function qrSVG(text, px) {
	var q = qrMatrix(text);
	var border = 4, n = q.size + border * 2;
	var path = '';
	for (var y = 0; y < q.size; y++)
		for (var x = 0; x < q.size; x++)
			if (q.modules[y][x])
				path += 'M' + (x + border) + ',' + (y + border) + 'h1v1h-1z';
	px = px || 200;
	return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + n + ' ' + n + '" width="' + px + '" height="' + px +
		'" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="#fff"/><path d="' + path + '" fill="#000"/></svg>';
}

/* Decode check used by selfTest: read format bits + codewords back from a matrix */
function qrVerify(q, enc) {
	var size = q.size, mod = q.modules;
	/* format bits copy 1 */
	var bits = 0;
	var get = function(x, y) { return mod[y][x] ? 1 : 0; };
	var fb = [];
	for (var a = 0; a <= 5; a++) fb[a] = get(8, a);
	fb[6] = get(8, 7); fb[7] = get(8, 8); fb[8] = get(7, 8);
	for (var b = 9; b < 15; b++) fb[b] = get(14 - b, 8);
	for (var i = 0; i < 15; i++) bits |= fb[i] << i;
	var fmt = (bits ^ 0x5412) >>> 10;
	var mask = fmt & 7;
	if ((fmt >>> 3) !== QR_FORMAT_BITS[enc.ecl] || mask !== q.mask) return 'format';
	/* second copy */
	var bits2 = 0;
	for (var c = 0; c < 8; c++) bits2 |= get(size - 1 - c, 8) << c;
	for (var d = 8; d < 15; d++) bits2 |= get(8, size - 15 + d) << d;
	if (bits2 !== bits) return 'format2';
	/* unmask + read */
	var fresh = qrBuildMatrix({ version: enc.version, ecl: enc.ecl, codewords: enc.codewords.map(function() { return 0; }) }, mask);
	var cw = [], cur = 0, n = 0;
	for (var right = size - 1; right >= 1; right -= 2) {
		if (right == 6) right = 5;
		for (var vert = 0; vert < size; vert++)
			for (var j = 0; j < 2; j++) {
				var x = right - j, upward = ((right + 1) & 2) == 0, y = upward ? size - 1 - vert : vert;
				if (!fresh.isFunction[y][x] && cw.length < enc.codewords.length) {
					/* fresh has data all-zero with mask applied => fresh module == mask bit */
					var bit = (mod[y][x] !== fresh.modules[y][x]) ? 1 : 0;
					cur = (cur << 1) | bit; n++;
					if (n == 8) { cw.push(cur); cur = 0; n = 0; }
				}
			}
	}
	for (var k = 0; k < enc.codewords.length; k++)
		if (cw[k] !== enc.codewords[k]) return 'codewords@' + k;
	/* de-interleave & RS syndrome check */
	var B = enc.blocks, blocks = [];
	for (var bi = 0; bi < B.num; bi++) blocks.push([]);
	var p = 0;
	for (var ci = 0; ci < B.shortLen + 1; ci++)
		for (var bj = 0; bj < B.num; bj++) {
			if (ci == B.shortLen - B.ecc && bj < B.numShort) continue;
			blocks[bj].push(cw[p++]);
		}
	var div = rsDivisor(B.ecc);
	for (var bk = 0; bk < blocks.length; bk++) {
		var blk = blocks[bk];
		var dataPart = blk.slice(0, blk.length - B.ecc), eccPart = blk.slice(blk.length - B.ecc);
		var re = rsRemainder(dataPart, div);
		for (var z = 0; z < re.length; z++) if (re[z] !== eccPart[z]) return 'rs@' + bk;
	}
	return true;
}

/* ---------------------------------------------------------------- self tests */

function selfTest() {
	var fails = [];
	var eq = function(name, a, b) {
		var sa = JSON.stringify(a), sb = JSON.stringify(b);
		if (sa !== sb) fails.push(name + ': got ' + sa + ' expected ' + sb);
	};
	var mkGet = function(o) {
		return function(name) {
			if (!(name in o)) return null;
			var v = o[name];
			if (typeof v === 'boolean') return { checkbox: true, checked: v, value: v ? '1' : '0' };
			return { checkbox: false, checked: false, value: v };
		};
	};
	var envAll = { has_xray: true, has_singbox: true, has_ss_rust: true };
	var envX = Object.assign({}, envAll, coreTypes({ has_xray: true, has_singbox: true, has_ss_rust: true, conf: {} }));

	/* core selection */
	eq('core.default', coreTypes({ has_xray: true, has_singbox: true, has_ss_rust: false, conf: {} }),
		{ ss_type: 'sing-box', trojan_type: 'sing-box', vmess_type: 'xray', vless_type: 'xray', hysteria2_type: 'sing-box' });
	eq('core.conf', coreTypes({ has_xray: true, has_singbox: true, has_ss_rust: true, conf: { ss_type: 'xray', vless_type: 'sing-box' } }).ss_type, 'xray');
	eq('core.missing', coreTypes({ has_xray: false, has_singbox: true, conf: { vmess_type: 'xray' } }).vmess_type, 'sing-box');

	/* SS export (spec 07 example) */
	eq('ss.export', buildUrl(mkGet({ address: '1.2.3.4', port: '8388', password: 'pass', method: 'aes-256-gcm',
		tcp_fast_open: false, plugin_enabled: true, plugin: 'obfs-local', plugin_opts: 'obfs=http' }), 'SS-Rust', 'name').url,
		'ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp&group=#name');
	eq('ss.export.plain', buildUrl(mkGet({ address: '::1', port: '8388', password: 'pw', method: 'none', tcp_fast_open: true }), 'SS-Rust', 'a b').url,
		'ss://bm9uZTpwdw@[::1]:8388/?tfo=1&group=#a%20b');
	/* SS import round trip (SIP002 + plugin) */
	var r = parse('ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp&group=#name', Object.assign({}, envAll, { ss_type: 'shadowsocks-rust' }));
	eq('ss.import.type', r.type, 'SS-Rust');
	eq('ss.import.fields', [r.fields.address, r.fields.port, r.fields.method, r.fields.password, r.fields.plugin_enabled, r.fields.plugin, r.fields.plugin_opts, r.fields.remarks],
		['1.2.3.4', '8388', 'aes-256-gcm', 'pass', true, 'obfs-local', 'obfs=http', 'name']);
	/* SS legacy base64 + 2022 key with colon */
	var legacy = 'ss://' + btoa('2022-blake3-aes-128-gcm:k1:k2@example.com:443') + '#x';
	r = parse(legacy, Object.assign({}, envAll, { ss_type: 'xray' }));
	eq('ss.legacy', [r.type, r.fields.protocol, r.fields.ss_method, r.fields.password, r.fields.address, r.fields.port],
		['Xray', 'shadowsocks', '2022-blake3-aes-128-gcm', 'k1:k2', 'example.com', '443']);
	/* SS with xray transport/tls */
	r = parse('ss://Y2hhY2hhMjAtcG9seTEzMDU6cHc@h.com:1/?type=ws&host=a.com&path=%2Fp&security=tls&sni=s.com&fp=chrome#n', Object.assign({}, envAll, { ss_type: 'xray' }));
	eq('ss.xray.ws', [r.fields.method, r.fields.transport, r.fields.ws_host, r.fields.ws_path, r.fields.tls, r.fields.tls_serverName, r.fields.utls, r.fields.fingerprint],
		['chacha20-ietf-poly1305', 'ws', 'a.com', '/p', true, 's.com', true, 'chrome']);
	/* SS without core -> invalid */
	eq('ss.nocore', parse('ss://YTpi@h:1#x', { has_xray: false, has_singbox: false, ss_type: null }).ok, false);
	/* SS shadow-tls sing-box */
	var stj = b64encsafe(JSON.stringify({ version: '3', password: 'x', host: 'y', fingerprint: 'chrome' }));
	r = parse('ss://' + b64encsafe('aes-128-gcm:p@h.com:443') + '?shadow-tls=' + stj + '#st', Object.assign({}, envAll, { ss_type: 'sing-box' }));
	eq('ss.shadowtls', [r.type, r.fields.shadowtls, r.fields.shadowtls_version, r.fields.shadowtls_password, r.fields.shadowtls_serverName, r.fields.shadowtls_utls, r.fields.shadowtls_fingerprint],
		['sing-box', true, '3', 'x', 'y', true, 'chrome']);
	var stExp = buildUrl(mkGet({ protocol: 'shadowsocks', address: 'h.com', port: '443', password: 'p', ss_method: 'aes-128-gcm',
		transport: 'tcp', tcp_guise: 'none', tls: false, shadowtls: true, shadowtls_version: '3', shadowtls_password: 'x', shadowtls_serverName: 'y',
		shadowtls_utls: true, shadowtls_fingerprint: 'chrome' }), 'sing-box', 'st').url;
	eq('ss.shadowtls.export', stExp, 'ss://' + b64encsafe('aes-128-gcm:p@h.com:443') + '?shadow-tls=' + stj + '#st');

	/* SSR round trip */
	var ssrGet = mkGet({ address: '1.1.1.1', port: '443', protocol: 'auth_aes128_md5', method: 'aes-256-cfb', obfs: 'tls1.2_ticket_auth',
		password: 'secret', obfs_param: 'o.com', protocol_param: '' });
	var ssrUrl = buildUrl(ssrGet, 'SSR', 'remark 中').url;
	r = parse(ssrUrl, envAll);
	eq('ssr.rt', [r.type, r.fields.address, r.fields.port, r.fields.protocol, r.fields.method, r.fields.obfs, r.fields.password, r.fields.obfs_param, r.fields.remarks],
		['SSR', '1.1.1.1', '443', 'auth_aes128_md5', 'aes-256-cfb', 'tls1.2_ticket_auth', 'secret', 'o.com', 'remark 中']);

	/* VMess export/import */
	var vmGet = mkGet({ protocol: 'vmess', address: 'v.com', port: '443', uuid: 'u-1', transport: 'ws', ws_host: 'h', ws_path: '/w',
		security: 'auto', tls: true, tls_serverName: 'sni', alpn: 'default', tcp_fast_open: false });
	var vmUrl = buildUrl(vmGet, 'Xray', 'vm').url;
	eq('vmess.json', JSON.parse(atob(vmUrl.substr(8))), { v: '2', ps: 'vm', add: 'v.com', port: '443', id: 'u-1', host: 'h', path: '/w', net: 'ws', security: 'auto', scy: 'auto', tls: 'tls', sni: 'sni' });
	r = parse(vmUrl, envX);
	eq('vmess.import', [r.type, r.fields.protocol, r.fields.address, r.fields.uuid, r.fields.transport, r.fields.ws_host, r.fields.ws_path, r.fields.tls, r.fields.tls_serverName, r.fields.alpn, r.fields.remarks],
		['Xray', 'vmess', 'v.com', 'u-1', 'ws', 'h', '/w', true, 'sni', 'default', 'vm']);
	r = parse('vmess://' + btoa(JSON.stringify({ add: 'a', port: 1, id: 'x', net: 'tcp', host: 'hh', path: '/' })), Object.assign({}, envX, { vmess_type: 'sing-box' }));
	eq('vmess.singbox.tcp', [r.type, r.fields.transport, r.fields.tcp_guise, r.fields.tcp_guise_http_host, r.fields.port], ['sing-box', 'tcp', 'http', 'hh', '1']);

	/* VLESS reality */
	var vl = 'vless://uuid-1@[2001:db8::1]:8443?type=tcp&security=reality&pbk=PBK&sid=ab&fp=chrome&flow=xtls-rprx-vision&sni=www.x.com#My%20Node';
	r = parse(vl, envX);
	eq('vless.import', [r.type, r.fields.uuid, r.fields.address, r.fields.port, r.fields.transport, r.fields.tcp_guise, r.fields.tls, r.fields.reality,
		r.fields.reality_publicKey, r.fields.reality_shortId, r.fields.flow, r.fields.tls_serverName, r.fields.fingerprint, r.fields.encryption, r.fields.remarks],
		['Xray', 'uuid-1', '2001:db8::1', '8443', 'raw', 'none', true, true, 'PBK', 'ab', 'xtls-rprx-vision', 'www.x.com', 'chrome', 'none', 'My Node']);
	var vlExp = buildUrl(mkGet({ protocol: 'vless', address: '2001:db8::1', port: '8443', uuid: 'uuid-1', transport: 'raw', tcp_guise: 'none',
		encryption: 'none', tls: true, reality: true, fingerprint: 'chrome', reality_publicKey: 'PBK', reality_shortId: 'ab', reality_spiderX: '',
		flow: 'xtls-rprx-vision', tls_serverName: 'www.x.com', tcp_fast_open: false }), 'Xray', 'My Node').url;
	eq('vless.export', vlExp, 'vless://uuid-1@[2001:db8::1]:8443?headerType=none&type=tcp&encryption=none&fp=chrome&pbk=PBK&sid=ab&flow=xtls-rprx-vision&security=reality&sni=www.x.com#My%20Node');
	/* vless xhttp forces xray even if vless_type sing-box */
	r = parse('vless://u@h:1?type=xhttp&path=%2Fx&mode=packet-up#n', Object.assign({}, envX, { vless_type: 'sing-box' }));
	eq('vless.xhttp', [r.type, r.fields.transport, r.fields.xhttp_path, r.fields.xhttp_mode], ['Xray', 'xhttp', '/x', 'packet-up']);
	/* sing-box ws early data */
	r = parse('vless://u@h:1?type=ws&path=%2Fws%3Fed%3D2048&security=tls#n', Object.assign({}, envX, { vless_type: 'sing-box' }));
	eq('vless.ed', [r.type, r.fields.ws_path, r.fields.ws_enableEarlyData, r.fields.ws_maxEarlyData, r.fields.ws_earlyDataHeaderName],
		['sing-box', '/ws', true, '2048', 'Sec-WebSocket-Protocol']);
	eq('vless.nouser', parse('vless://h.com:1?type=tcp', envX).ok, false);

	/* Trojan */
	r = parse('trojan://p%40ss@t.com:443?type=grpc&serviceName=svc&sni=s&allowInsecure=1#tj', envX);
	eq('trojan.import', [r.type, r.fields.password, r.fields.transport, r.fields.grpc_serviceName, r.fields.grpc_mode, r.fields.tls, r.fields.tls_allowInsecure, r.fields.tls_serverName, r.fields.mux],
		['sing-box', 'p@ss', 'grpc', 'svc', 'gun', true, true, 's', false]);
	eq('trojan.export', buildUrl(mkGet({ protocol: 'trojan', address: 't.com', port: '443', password: 'p@ss', transport: 'grpc', grpc_serviceName: 'svc',
		tls: true, tls_serverName: 's', tls_allowInsecure: true, alpn: 'default' }), 'sing-box', 'tj').url,
		'trojan://p%40ss@t.com:443/?path=svc&serviceName=svc&type=grpc&alpn=default&sni=s&allowinsecure=1&security=tls#tj');

	/* Hysteria2 */
	r = parse('hy2://pw@h.com:8443/?sni=s&obfs=salamander&obfs-password=op&mport=2000-3000&insecure=1#hy', envX);
	eq('hy2.import', [r.type, r.fields.protocol, r.fields.hysteria2_auth_password, r.fields.hysteria2_obfs_type, r.fields.hysteria2_obfs_password,
		r.fields.hysteria2_hop, r.fields.tls_allowInsecure, r.fields.port, r.fields.remarks],
		['sing-box', 'hysteria2', 'pw', 'salamander', 'op', '2000-3000', true, '8443', 'hy']);
	eq('hy2.export', buildUrl(mkGet({ protocol: 'hysteria2', address: 'h.com', port: '8443', hysteria2_auth_password: 'pw', tls_serverName: 's',
		tls_allowInsecure: true, tls_pinSHA256: '', hysteria2_obfs_type: 'salamander', hysteria2_obfs_password: 'op', hysteria2_hop: '2000-3000' }), 'sing-box', 'hy').url,
		'hysteria2://pw@h.com:8443?sni=s&insecure=1&obfs=salamander&obfs-password=op&mport=2000-3000#hy');
	eq('hy2.nocore', parse('hy2://pw@h:1', { has_xray: true, has_singbox: false, hysteria2_type: null }).ok, false);

	/* TUIC */
	r = parse('tuic://uuid%3Apass@t.com:443?congestion_control=bbr&alpn=h3&sni=s&disable_sni=1#tu', envX);
	eq('tuic.import', [r.fields.uuid, r.fields.password, r.fields.tuic_congestion_control, r.fields.tuic_udp_relay_mode, r.fields.tuic_alpn, r.fields.tls_disable_sni],
		['uuid', 'pass', 'bbr', 'native', 'h3', true]);
	/* AnyTLS, naive, snell */
	r = parse('anytls://pw@a.com:443?security=reality&pbk=k&sid=1#a', envX);
	eq('anytls', [r.fields.tls, r.fields.reality, r.fields.reality_publicKey, r.fields.alpn], [true, true, 'k', 'default']);
	r = parse('naive+quic://user:pa%20ss@n.com:443?sni=s&uot=1#nv', envX);
	eq('naive', [r.fields.username, r.fields.password, r.fields.naive_quic, r.fields.naive_congestion_control, r.fields.uot], ['user', 'pa ss', true, 'bbr', true]);
	r = parse('naive+https://onlypass@n.com#nv', envX);
	eq('naive.pw', [r.fields.username, r.fields.password, r.fields.port], ['', 'onlypass', '443']);
	eq('naive.export', buildUrl(mkGet({ protocol: 'naive', address: 'n.com', port: '443', username: 'user', password: 'pa ss',
		tls_serverName: 's', naive_insecure_concurrency: '0', uot: true, naive_quic: true, naive_congestion_control: 'bbr' }), 'sing-box', 'nv').url,
		'naive+quic://user:pa%20ss@n.com:443?security=tls&sni=s&insecure-concurrency=0&uot=1&congestion_control=bbr#nv');
	r = parse('snell://psk1@s.com:6000?version=4&obfs=http&obfs-host=b.com#sn', envX);
	eq('snell', [r.fields.snell_psk, r.fields.snell_version, r.fields.snell_obfs_mode, r.fields.snell_obfs_host], ['psk1', '4', 'http', 'b.com']);
	/* unsupported */
	eq('socks.invalid', parse('socks://a@b:1', envX).ok, false);
	eq('export.unsupported', buildUrl(mkGet({ protocol: 'socks', address: 'a', port: '1' }), 'Xray', 'x').error, 'unsupported');
	/* &amp; and whitespace before # */
	r = parse('trojan://pw@h.com:443?sni=a&amp;type=ws&amp;path=%2Fz   #  rem', envX);
	eq('trojan.amp', [r.fields.transport, r.fields.ws_path, r.fields.remarks], ['ws', '/z', 'rem']);
	eq('truthy', [truthy('1'), truthy('0'), truthy(''), truthy(true), truthy(undefined)], [true, false, false, true, false]);

	/* QR codes: internal decode consistency for several sizes/versions */
	['A', 'hello world', vlExp, ssrUrl, 'x'.repeat(300), 'y'.repeat(1200)].forEach(function(t, i) {
		var enc = qrEncode(t);
		var q = qrMatrix(t);
		var res = qrVerify(q, enc);
		if (res !== true) fails.push('qr#' + i + ': ' + res);
		if (q.size !== q.version * 4 + 17) fails.push('qr#' + i + ': size');
	});
	eq('qr.version.short', qrEncode('A').version, 1);
	eq('qr.capacity.v1M', qrDataCodewords(1, 'M'), 16);
	eq('qr.capacity.v40M', qrDataCodewords(40, 'M'), 2334);
	eq('qr.align.v7', qrAlignPositions(7), [6, 22, 38]);
	eq('qr.align.v32', qrAlignPositions(32), [6, 34, 60, 86, 112, 138]);
	return fails;
}

return baseclass.extend({
	b64EncodeUnicode: b64EncodeUnicode,
	b64DecodeUnicode: b64DecodeUnicode,
	b64encsafe: b64encsafe,
	b64decsafe: b64decsafe,
	unbracketIP: unbracketIP,
	isIPv6: function(s) { return IPV6_RE.test(s || ''); },
	getCore: getCore,
	coreTypes: coreTypes,
	buildUrl: buildUrl,
	parse: parse,
	truthy: truthy,
	qrMatrix: qrMatrix,
	qrSVG: qrSVG,
	selfTest: selfTest
});
