'use strict';
'require view';
'require dom';
'require form';
'require uci';
'require ui';
'require passwall2.pw as pw';

/*
 * Server user editor (upstream: model/cbi/passwall2/server/user_config.lua,
 * view/passwall2/server/gen_wireguard_key.htm). URL: server_user_config/<sid>.
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
		E('h2', {}, [ title ]),
		desc ? E('div', { 'class': 'cbi-map-descr' }, [ desc ]) : ''
	]);
}

/* Section id = path segment after "server_user_config". */
function getSid() {
	var p = L.env.requestpath || [];
	var i = p.indexOf('server_user_config');
	if (i >= 0 && p[i + 1])
		return p[i + 1];
	var m = /\/server_user_config\/([^\/?#]+)/.exec(window.location.pathname);
	return m ? decodeURIComponent(m[1]) : null;
}

/* func.js isBase64 (strict, padded, standard alphabet) */
function isBase64(str) {
	return /^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$/.test(str);
}

/* func.js isUUID (versions 1-5, RFC variant) */
function isUUID(str) {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(str);
}

/* api.gen_uuid(): `cat /proc/sys/kernel/random/uuid` -> random v4 UUID */
function genUUID() {
	var b = new Uint8Array(16);
	if (window.crypto && window.crypto.getRandomValues)
		window.crypto.getRandomValues(b);
	else
		for (var i = 0; i < 16; i++)
			b[i] = Math.floor(Math.random() * 256);
	b[6] = (b[6] & 0x0f) | 0x40;
	b[8] = (b[8] & 0x3f) | 0x80;
	var h = [];
	for (var j = 0; j < 16; j++)
		h.push((b[j] + 0x100).toString(16).substring(1));
	return h.slice(0, 4).join('') + '-' + h.slice(4, 6).join('') + '-' + h.slice(6, 8).join('') + '-' +
		h.slice(8, 10).join('') + '-' + h.slice(10, 16).join('');
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

function base64Validator(section_id, value) {
	if (value == null || value === '')
		return true;
	return isBase64(value) ? true : _('Must be Base64 text!');
}

return view.extend({
	load: function() {
		if (typeof(pw.loadCSS) == 'function') {
			try { pw.loadCSS(); } catch (e) {}
		}
		return uci.load(CONF);
	},

	render: function() {
		var sid = getSid();
		if (!sid || !/^[A-Za-z0-9_]+$/.test(sid) || !uci.get(CONF, sid)) {
			window.location.href = url('server');
			return E('div', {}, _('Collecting data...'));
		}

		var m, s, o;

		m = new form.Map(CONF);
		this.map = m;

		s = m.section(form.NamedSection, sid, 'user', _('User Config'));
		s.addremove = false;
		s.dynamic = false;

		o = s.option(form.Value, 'username', _('Username'));
		o.datatype = 'and(uciname,maxlength(24))';
		o.rmempty = false;
		o.validate = function(section_id, value) {
			var exists = false;
			uci.sections(CONF, 'user').forEach(function(u) {
				if (u['.name'] != section_id && u.username == value)
					exists = true;
			});
			if (exists)
				return _('This username already exists.');
			return true;
		};

		o = s.option(form.Value, 'password', _('Password'));
		o.rmempty = false;

		o = s.option(form.Value, 'uuid', 'UUID');
		o.default = genUUID();
		o.rmempty = false;
		o.validate = function(section_id, value) {
			if (value == null || value === '')
				return true;
			return isUUID(value) ? true : _('Must be UUID format!');
		};

		o = s.option(form.Value, 'wireguard_public_key', 'Wireguard ' + _('Public Key'));
		o.validate = base64Validator;

		o = s.option(form.Value, 'wireguard_private_key', 'Wireguard ' + _('Private Key'));
		o.validate = base64Validator;

		o = s.option(form.Button, '_gen_wireguard_key', _('Generate key'));
		o.inputtitle = _('Generate key');
		o.inputstyle = 'apply';
		o.onclick = function(ev, section_id) {
			return Promise.resolve().then(function() {
				return pw.call('gen_wireguard_key', {});
			}).then(function(res) {
				if (res && res.code == 1 && res.data) {
					var priv = m.lookupOption('wireguard_private_key', section_id);
					var pub = m.lookupOption('wireguard_public_key', section_id);
					if (priv && priv[0].getUIElement(section_id))
						priv[0].getUIElement(section_id).setValue(res.data.private_key || '');
					if (pub && pub[0].getUIElement(section_id))
						pub[0].getUIElement(section_id).setValue(res.data.public_key || '');
					if (priv) priv[0].triggerValidation(section_id);
					if (pub) pub[0].triggerValidation(section_id);
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

		o = s.option(form.Value, 'wireguard_pre_shared_key', 'Wireguard ' + _('Pre shared key'));
		o.validate = base64Validator;

		o = s.option(form.DynamicList, 'allowed_ips', 'Wireguard ' + _('Allowed IPs'));
		o.write = function(section_id, value) {
			var v = dedupe(value);
			return this.map.data.set(CONF, section_id, this.option, v.length ? v : null);
		};

		return m.render().then(function(mapEl) {
			return E('div', { 'class': 'pw-root' }, [
				header(_('User Config')),
				E('div', { 'class': 'pw-toolbar' }, [
					E('a', { 'class': 'btn cbi-button cbi-button-neutral', 'href': url('server') }, '« ' + _('Server-Side'))
				]),
				mapEl
			]);
		});
	},

	/* upstream m.redirect = server: go back to the list after Save & Apply */
	handleSaveApply: function(ev, mode) {
		var target = url('server');
		return this.handleSave(ev).then(function() {
			redirectAfterApply(target);
			return ui.changes.apply(mode == '0');
		});
	}
});
