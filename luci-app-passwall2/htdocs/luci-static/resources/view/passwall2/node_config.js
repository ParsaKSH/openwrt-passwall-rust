'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require dom';
'require passwall2.pw as pw';
'require passwall2.nodeform as nf';
'require passwall2.sharelink as sl';

/*
 * Node editor, node_config/<sid>
 * (upstream: model/cbi/passwall2/client/node_config.lua + client/type/*.lua,
 *  view/passwall2/node_config/{header,footer,link_share_man}.htm)
 *
 * Only the selected type's options are rendered (upstream reloads the page when the type
 * changes, and when the protocol switches between a normal and a special kind). Here the form is
 * rebuilt in place from the local UCI state; nothing is written until Save / Save & Apply.
 */

var CONF = 'passwall2';

function pageSid() {
	var req = L.env.requestpath || [], disp = L.env.dispatchpath || [];
	if (req.length > disp.length)
		return req[disp.length];
	var idx = req.indexOf('node_config');
	if (idx >= 0 && req[idx + 1])
		return req[idx + 1];
	var m = /[?&]id=([A-Za-z0-9_]+)/.exec(window.location.search);
	return m ? m[1] : null;
}

function trim(s) { return (s == null ? '' : String(s)).replace(/^\s+|\s+$/g, ''); }

function copyText(text) {
	if (navigator.clipboard && window.isSecureContext)
		return navigator.clipboard.writeText(text).then(function() { return true; }, function() { return legacyCopy(text); });
	return Promise.resolve(legacyCopy(text));
}

function legacyCopy(text) {
	var ta = E('textarea', { 'style': 'position:fixed;top:0;left:0;opacity:0' }, [text]);
	document.body.appendChild(ta);
	ta.select();
	var ok = false;
	try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
	document.body.removeChild(ta);
	return ok;
}

return view.extend({
	load: function() {
		return nf.loadEnv();
	},

	render: function(env) {
		var self = this;
		pw.loadCSS();
		this.env = env;
		this.sid = pageSid();
		var back = pw.url('node_list');

		if (!this.sid || !uci.get(CONF, this.sid) || uci.get(CONF, this.sid)['.type'] != 'nodes') {
			window.setTimeout(function() { window.location.href = back; }, 1500);
			return E('div', { 'class': 'pw-root' }, [
				pw.pageHeader(_('Node Config'), null, [E('a', { 'class': 'btn cbi-button', 'href': back }, [_('Back')])]),
				pw.card(null, E('p', {}, [_('Node not found, returning to the node list...')]))
			]);
		}

		window.pw2FetchCertSha256 = function(el) { return self.fetchCertSha256(el); };

		this.statusEl = E('span', { 'class': 'pw-share-status' });
		this.toolbarEl = E('div', { 'class': 'pw-share-toolbar' });
		this.qrEl = E('div', { 'class': 'pw-share-qr', 'style': 'display:none' });
		this.formBox = E('div', { 'class': 'pw-node-form' });
		this.typeNote = E('div');

		pw.redirectAfterApply(back);

		var root = E('div', { 'class': 'pw-root pw-node-config' }, [
			E('style', {}, [
				'.pw-node-config .pw-share-toolbar{display:flex;flex-wrap:wrap;gap:.4em;align-items:center}' +
				'.pw-node-config .pw-share-status:not(:empty){display:block;margin-top:.5em}' +
				'.pw-node-config .pw-share-qr{display:flex;flex-direction:column;align-items:center;gap:.5em;margin-top:.75em}' +
				'.pw-node-config .pw-share-qr svg{border-radius:8px;box-shadow:0 1px 6px rgba(0,0,0,.15)}' +
				'.pw-node-config .pw-share-qr code{word-break:break-all;max-width:100%;font-size:90%}' +
				'.pw-node-config .pw-ncl-tools{display:flex;flex-wrap:wrap;gap:.4em;align-items:center;margin-bottom:.4em}' +
				'.pw-node-config .pw-ncl-tools input[type=search]{flex:1 1 12em;min-width:10em}' +
				'.pw-node-config .pw-ncl-list{max-height:22em;overflow:auto;border:1px solid rgba(128,128,128,.3);border-radius:8px;padding:.3em .6em}' +
				'.pw-node-config .pw-ncl-group summary{cursor:pointer;font-weight:600;padding:.2em 0}' +
				'.pw-node-config .pw-ncl-items{display:flex;flex-direction:column;padding-left:1em}' +
				'.pw-node-config .pw-ncl-flat{padding-left:0;flex-direction:row;flex-wrap:wrap;gap:.2em 1.2em}' +
				'.pw-node-config .pw-ncl-item{display:flex;align-items:center;gap:.35em;padding:.1em 0;cursor:pointer}' +
				'.pw-node-config .pw-ncl-item[hidden]{display:none}' +
				'.pw-node-config .pw-gsel{display:flex;flex-direction:column;gap:.3em}' +
				'.pw-node-config .pw-shunt-table .td{vertical-align:middle}' +
				'.pw-node-config .pw-type-note{margin:.25em 0 .75em}'
			]),
			pw.pageHeader(_('Node Config'), this.sid, [
				E('a', { 'class': 'btn cbi-button', 'href': back }, [_('Back')])
			]),
			pw.card(null, this.toolbarEl, this.statusEl, this.qrEl),
			this.typeNote,
			this.formBox
		]);

		return this.renderMap().then(function() { return root; });
	},

	currentType: function() {
		var t = uci.get(CONF, this.sid, 'type');
		var avail = nf.availableTypes(this.env).map(function(x) { return x[0]; });
		if (!t && avail.length)
			t = avail[0];   /* new node without type: the type select defaults to the first core */
		return t || '';
	},

	renderMap: function() {
		var self = this, env = this.env, sid = this.sid;
		var type = this.currentType();
		var avail = nf.availableTypes(env);
		var typeOk = avail.some(function(x) { return x[0] == type; });
		var protocol = uci.get(CONF, sid, 'protocol') || '';
		var kind = nf.protocolKind(type, protocol);

		var m = new form.Map(CONF);
		nf.installDependsHandler(m);
		var s = m.section(form.NamedSection, sid, 'nodes', _('Node Config'));
		s.addremove = false;
		s.anonymous = true;

		var o = s.option(form.Value, 'remarks', _('Node Remarks'));
		o.default = _('Remarks');
		o.rmempty = false;

		var groups = {};
		uci.sections(CONF, 'nodes').forEach(function(n) {
			if (n['.name'] != sid && n.group && n.group !== '') groups[n.group] = true;
		});
		var groupKeys = Object.keys(groups);
		o = s.option(form.Value, 'group', _('Group Name'));
		o.default = '';
		o.value('', _('default'));
		groupKeys.forEach(function(g) { o.value(g); });
		o.write = function(section_id, value) {
			var v = trim(value), lower = v.toLowerCase();
			if (lower === '' || lower === 'default')
				return uci.unset(CONF, section_id, 'group');
			for (var i = 0; i < groupKeys.length; i++)
				if (groupKeys[i].toLowerCase() == lower)
					return uci.set(CONF, section_id, 'group', groupKeys[i]);
			uci.set(CONF, section_id, 'group', v);
		};
		o.remove = function(section_id) { uci.unset(CONF, section_id, 'group'); };

		o = s.option(form.ListValue, 'type', _('Type'));
		avail.forEach(function(t) { o.value(t[0], t[1]); });
		if (avail.length) o.default = avail[0][0];
		o.onchange = function(ev, section_id, value) {
			if (value != self.currentType())
				self.rebuild({ type: value, protocol: null });
		};

		dom.content(this.typeNote, []);
		if (!avail.length) {
			this.typeNote.appendChild(pw.card(null, E('p', { 'class': 'pw-text-err' },
				[_('No core is installed (sing-box, Xray, sslocal or ssr-local).')])));
		} else if (uci.get(CONF, sid, 'type') && !typeOk) {
			this.typeNote.appendChild(E('div', { 'class': 'pw-type-note' }, [
				pw.badge(_('Type') + ': ' + uci.get(CONF, sid, 'type'), 'err'), ' ',
				E('span', { 'class': 'pw-text-err' }, [_('The core of this node is not installed; its options cannot be edited.')])
			]));
		}

		this.specs = null;
		this.ctx = null;
		if (typeOk) {
			var ctx = nf.makeCtx(env, sid, kind);
			ctx.type = type;
			this.ctx = ctx;
			this.specs = nf.getSpecs(type, ctx);
			nf.buildForm(s, this.specs, ctx, {
				onKindChange: function(newProtocol, prevProtocol) {
					if (newProtocol == '_json' && self.kind == 'normal')
						return self.convertToJson(prevProtocol);
					self.rebuild({ protocol: newProtocol });
				},
				onShuntGroupChange: function(v) { self.rebuild({ shunt_group: v }); }
			});
		}

		this.map = m;
		this.section = s;
		this.kind = kind;
		this.renderToolbar(kind);
		return m.render().then(function(node) {
			dom.content(self.formBox, node);
			return node;
		});
	},

	formValue: function(name) {
		var o = this.section && this.section.children.filter(function(c) { return c.option == name; })[0];
		return o ? o.formvalue(this.sid) : null;
	},

	/* upstream footer.htm: save {remarks, group, type, protocol:''} and reload with the new form */
	rebuild: function(changes) {
		var sid = this.sid;
		var remarks = this.formValue('remarks'), group = this.formValue('group');
		if (remarks != null && trim(remarks) !== '') uci.set(CONF, sid, 'remarks', remarks);
		if (group != null) {
			var g = trim(group);
			if (g === '' || g.toLowerCase() == 'default') uci.unset(CONF, sid, 'group');
			else uci.set(CONF, sid, 'group', g);
		}
		Object.keys(changes || {}).forEach(function(k) {
			var v = changes[k];
			if (v == null || v === '') uci.unset(CONF, sid, k);
			else uci.set(CONF, sid, k, v);
		});
		return this.renderMap();
	},

	/* Protocol switched from a regular one to Custom JSON: ask the backend for the outbound it
	 * would generate from the current (unsaved) form and open it in the JSON editor. The old
	 * options stay in UCI, so switching back restores the form. */
	convertToJson: function(prevProtocol) {
		var self = this, sid = this.sid;
		var node = nf.collectFormValues(this.section, sid, { protocol: prevProtocol });
		node['.name'] = sid;
		node.type = this.currentType();
		node.protocol = prevProtocol;
		return pw.call('gen_node_json', { node: JSON.stringify(node) }).then(function(res) {
			var changes = { protocol: '_json' };
			if (res && res.code === 1 && res.json)
				changes.custom_json = nf.encodeJsonText(res.json);
			else
				ui.addNotification(null, E('p', {}, [_('Could not convert this node to JSON; starting from an empty editor.') + (res && res.msg ? ' (' + res.msg + ')' : '')]), 'warning');
			return self.rebuild(changes);
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
			return self.rebuild({ protocol: '_json' });
		});
	},

	setStatus: function(text, kind) {
		dom.content(this.statusEl, text ? [E('span', { 'class': kind == 'ok' ? 'pw-text-ok' : 'pw-text-err' }, [text])] : []);
	},

	renderToolbar: function(kind) {
		var self = this;
		var btn = function(label, iconName, fn) {
			return E('button', { 'class': 'btn cbi-button cbi-button-apply pw-btn', 'type': 'button',
				'click': ui.createHandlerFn(self, fn) }, [pw.icon(iconName), ' ', E('span', {}, [label])]);
		};
		var items = [];
		var proto = uci.get(CONF, this.sid, 'protocol') || '';
		if (!proto || proto.charAt(0) != '_') {
			items.push(btn(_('From Share URL'), 'link', this.handleFromUrl));
			items.push(btn(_('Build Share URL'), 'copy', this.handleExportUrl));
			items.push(btn(_('Generate QRCode'), 'globe', this.handleQrcode));
		}
		items.push(btn(_('Export Config File'), 'download', this.handleExportConfig));
		dom.content(this.toolbarEl, items);
		this.qrEl.style.display = 'none';
		this.setStatus('');
	},

	/* ------------------------------------------------------------ share links */

	shareEnv: function() {
		var env = this.env;
		var base = { has_xray: env.has_xray, has_singbox: env.has_singbox, has_ss_rust: env.has_sslocal,
			conf: uci.sections(CONF, 'global_subscribe')[0] || {} };
		return Object.assign(base, sl.coreTypes(base));
	},

	buildUrl: function() {
		var type = this.formValue('type') || this.currentType();
		var remarks = this.formValue('remarks') || '';
		var res = sl.buildUrl(nf.formGetter(this.section, this.sid), type, remarks);
		if (!res.url) {
			ui.addNotification(null, E('p', {}, [_('Not a supported scheme:') + ' ' + type]), 'warning');
			return null;
		}
		return res.url;
	},

	handleExportUrl: function() {
		var url = this.buildUrl(), self = this;
		if (!url) return;
		return copyText(url).then(function(ok) {
			if (ok) self.setStatus(_('Share URL to clipboard successfully.'), 'ok');
			else self.setStatus(_('Share URL to clipboard unable.'), 'err');
		});
	},

	handleQrcode: function() {
		var url = this.buildUrl();
		if (!url) return;
		var svg;
		try { svg = sl.qrSVG(url, 220); } catch (e) { this.setStatus(String(e.message || e), 'err'); return; }
		var holder = E('div');
		holder.innerHTML = svg;
		dom.content(this.qrEl, [holder.firstChild, E('code', {}, [url])]);
		this.qrEl.style.display = '';
	},

	handleFromUrl: function() {
		var self = this;
		var ta = E('textarea', { 'class': 'cbi-input-textarea', 'rows': 4, 'style': 'width:100%;font-family:monospace',
			'placeholder': 'vless:// vmess:// ss:// ssr:// trojan:// hysteria2:// tuic:// anytls:// naive+https:// snell://' });
		ui.showModal(_('Paste Share URL Here'), [
			E('div', { 'class': 'pw-root pw-modal' }, [ta]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', 'click': ui.hideModal }, [_('Cancel')]), ' ',
				E('button', { 'class': 'btn cbi-button-action important', 'click': function() {
					var link = ta.value;
					ui.hideModal();
					if (link && trim(link) !== '')
						self.importLink(link);
				} }, [_('OK')])
			])
		]);
		window.setTimeout(function() { ta.focus(); }, 50);
	},

	importLink: function(link) {
		var self = this;
		this.setStatus('');
		var r = sl.parse(link, this.shareEnv());
		if (!r.ok) {
			this.setStatus(_('Invalid Share URL Format'), 'err');
			return Promise.resolve(false);
		}
		var curType = this.formValue('type') || this.currentType();
		var curProto = this.formValue('protocol') || uci.get(CONF, this.sid, 'protocol') || '';
		var needRebuild = (r.type != curType) || (nf.protocolKind(r.type, r.protocol) != nf.protocolKind(curType, curProto)) || !this.specs;
		var p = needRebuild
			? this.rebuild({ type: r.type, protocol: (r.type == 'Xray' || r.type == 'sing-box') ? r.protocol : uci.get(CONF, this.sid, 'protocol') })
			: Promise.resolve();
		return p.then(function() {
			nf.applyFields(self.section, self.sid, r.fields, sl);
			self.map.checkDepends();
			self.setStatus(_('Import Finished '), 'ok');
			return true;
		});
	},

	handleExportConfig: function() {
		var sid = this.sid;
		return pw.call('gen_client_config', { id: sid }).then(function(res) {
			var text;
			if (res && typeof res.result === 'string') text = res.result;
			else if (res && Object.keys(res).length) text = JSON.stringify(res, null, 2);
			if (!text) {
				ui.addNotification(null, E('p', {}, [_('Error')]), 'danger');
				return;
			}
			pw.downloadBlob(new Blob([text], { type: 'application/json' }), 'config_' + sid + '.json');
		}).catch(function(e) {
			ui.addNotification(null, E('p', {}, [_('Error') + ': ' + (e && e.message || e)]), 'danger');
		});
	},

	/* node_config/header.htm fetchCertSha256() */
	fetchCertSha256: function(el) {
		var self = this;
		if (el && el.getAttribute('data-loading') == '1') return false;
		if (el) { el.setAttribute('data-loading', '1'); el.style.color = 'red'; }
		pw.call('fetch_certsha256', { id: this.sid }).then(function(res) {
			if (res && res.code === 1 && res.data) {
				var o = self.section.children.filter(function(c) { return c.option == 'tls_pinSHA256'; })[0];
				var w = o && o.getUIElement(self.sid);
				if (w) {
					w.setValue(res.data);
					if (w.node) w.node.dispatchEvent(new CustomEvent('widget-change', { bubbles: true }));
				}
			} else {
				ui.addNotification(null, E('p', {}, [(res && res.msg) || _('Fetch Failed') + ' !']), 'warning');
			}
		}).catch(function() {
			ui.addNotification(null, E('p', {}, [_('Error')]), 'danger');
		}).finally(function() {
			if (el) { el.removeAttribute('data-loading'); el.style.color = ''; }
		});
		return false;
	}
});
