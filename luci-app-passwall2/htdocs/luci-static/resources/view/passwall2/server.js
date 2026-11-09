'use strict';
'require view';
'require dom';
'require form';
'require poll';
'require uci';
'require ui';
'require passwall2.pw as pw';

/*
 * Server-Side list page (upstream: model/cbi/passwall2/server/index.lua,
 * view/passwall2/server/{server_list_status,log}.htm, cbi/sortable).
 *
 * Map passwall2_server:
 *   - global.enable
 *   - TypedSection server  "Servers Manager"  (enable, status, remarks, type, port, log; Log/Edit/Delete; drag order)
 *   - TypedSection user    "Users Manager"    (username, password, uuid; delete cascades into server.user/users)
 *   - server log panel (server_get_log polled every 3 s, server_clear_log)
 */

var CONF = 'passwall2_server';
var SERVER_LOG_POLL = 3;

function url(path) {
	return L.url('admin/services/passwall2/' + path);
}

/* api.gen_random_char(): head /dev/urandom | tr -dc A-Za-z0-9 | head -c 8 */
function genRandomChar(n) {
	var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	var out = '';
	n = n || 8;
	var buf = new Uint8Array(n * 2);
	while (out.length < n) {
		if (window.crypto && window.crypto.getRandomValues)
			window.crypto.getRandomValues(buf);
		else
			for (var j = 0; j < buf.length; j++)
				buf[j] = Math.floor(Math.random() * 256);
		for (var i = 0; i < buf.length && out.length < n; i++) {
			/* 248 = 62*4: reject to avoid modulo bias */
			if (buf[i] < 248)
				out += chars.charAt(buf[i] % 62);
		}
	}
	return out;
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

function statusMark(ok) {
	try {
		if (typeof(pw.badge) == 'function') {
			var n = pw.badge(ok ? '✓' : 'X', ok ? 'ok' : 'err');
			if (n instanceof Node)
				return n;
		}
	}
	catch (e) {}
	return E('span', {
		'class': 'pw-badge ' + (ok ? 'pw-badge-ok' : 'pw-badge-err'),
		'style': 'font-weight:bold;color:' + (ok ? 'green' : 'red')
	}, ok ? '✓' : 'X');
}

/* Upstream "type" column of the servers table. */
var PROTO_NAMES = {
	vmess: 'VMess', vless: 'VLESS', shadowsocks: 'SS', shadowsocksr: 'SSR',
	wireguard: 'WG', hysteria: 'HY', hysteria2: 'HY2', anytls: 'AnyTLS'
};

function formatServerType(s) {
	var type = (s && s.type) || '';
	if (type == 'sing-box' || type == 'Xray') {
		var protocol = s.protocol || '';
		if (PROTO_NAMES.hasOwnProperty(protocol)) {
			protocol = PROTO_NAMES[protocol];
		}
		else {
			protocol = protocol.replace(/^[a-z]/, function(c) { return c.toUpperCase(); });
			if ((s.custom || '0') == '1')
				protocol = _('Custom Config');
		}
		if (type == 'sing-box')
			type = 'Sing-Box';
		type = type + ' ' + protocol;
	}
	return type ? _(type) : '';
}

/* Per-instance log (upstream: new tab on server_log?id=; text with <br />, or an alert script).
 * pw.showLog() turns the title into a text node, so remarks are never parsed as HTML. */
function showServerLog(sid, remarks) {
	return pw.showLog(_('Log') + (remarks ? ': ' + remarks : ''), 'server_log', { id: sid });
}

return view.extend({
	load: function() {
		if (typeof(pw.loadCSS) == 'function') {
			try { pw.loadCSS(); } catch (e) {}
		}
		return uci.load(CONF).catch(function() {});
	},

	refreshStatus: function(root) {
		var marks = root.querySelectorAll('._servers_status[data-sid]');
		var tasks = [];
		for (var i = 0; i < marks.length; i++) {
			(function(index, el) {
				var id = el.getAttribute('data-sid');
				tasks.push(Promise.resolve().then(function() {
					return pw.call('server_status', { index: String(index), id: id });
				}).then(function(result) {
					var ok = !!(result && result.status);
					dom.content(el, statusMark(ok));
				}).catch(function() {}));
			})(i, marks[i]);
		}
		return Promise.all(tasks);
	},

	render: function() {
		var self = this;
		var m, s, o;

		/* Upstream default config: `config global 'global' / option enable '0'` */
		if (!uci.get(CONF, 'global'))
			uci.add(CONF, 'global', 'global');

		m = new form.Map(CONF);

		s = m.section(form.NamedSection, 'global', 'global', _('Server-Side'));
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.Flag, 'enable', _('Enable'));
		o.rmempty = false;

		/* -------- Servers -------- */
		s = m.section(form.TableSection, 'server', _('Servers Manager'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = true;
		s.extedit = url('server_config/%s');
		s.handleAdd = function(ev) {
			var uid = genRandomChar(8);
			this.map.data.add(CONF, 'server', uid);
			return this.map.save(null, true).then(function() {
				window.location.href = url('server_config/' + uid);
			});
		};
		s.handleRemove = function(section_id, ev) {
			var o = this.map.data.get(CONF, section_id);
			if (o && o['.type'] == 'server')
				this.map.data.remove(CONF, section_id);
			return this.map.save(null, true);
		};
		s.renderRowActions = function(section_id, more_label) {
			var tdEl = form.TableSection.prototype.renderRowActions.call(this, section_id, more_label);
			var holder = tdEl && tdEl.lastElementChild;
			if (holder) {
				var logBtn = E('button', {
					'class': 'btn cbi-button cbi-button-add',
					'title': _('Log'),
					'click': ui.createHandlerFn(this, function(sid, ev) {
						ev.preventDefault();
						return showServerLog(sid, uci.get(CONF, sid, 'remarks'));
					}, section_id)
				}, _('Log'));
				holder.insertBefore(logBtn, holder.firstChild);
			}
			return tdEl;
		};

		o = s.option(form.Flag, 'enable', _('Enable'));
		o.width = '5%';
		o.rmempty = false;

		o = s.option(form.DummyValue, 'status', _('Status'));
		o.renderWidget = function(section_id) {
			return E('span', { 'class': '_servers_status', 'data-sid': section_id }, _('Collecting data...'));
		};

		o = s.option(form.DummyValue, 'remarks', _('Remarks'));
		o.width = '15%';

		o = s.option(form.DummyValue, 'type', _('Type'));
		o.width = '20%';
		o.renderWidget = function(section_id) {
			return E('span', {}, [ formatServerType(uci.get(CONF, section_id) || {}) ]);
		};

		o = s.option(form.DummyValue, 'port', _('Port'));

		o = s.option(form.Flag, 'log', _('Log'));
		o.default = '1';
		o.rmempty = false;

		/* -------- Users -------- */
		s = m.section(form.TableSection, 'user', _('Users Manager'));
		s.anonymous = true;
		s.addremove = true;
		s.sortable = true;
		s.extedit = url('server_user_config/%s');
		s.handleAdd = function(ev) {
			var uid = genRandomChar(8);
			this.map.data.add(CONF, 'user', uid);
			return this.map.save(null, true).then(function() {
				window.location.href = url('server_user_config/' + uid);
			});
		};
		s.handleRemove = function(section_id, ev) {
			var data = this.map.data;
			var o = data.get(CONF, section_id);
			if (!o || o['.type'] != 'user')
				return this.map.save(null, true);

			data.sections(CONF, 'server').forEach(function(srv) {
				var sid = srv['.name'];
				if (srv.user && srv.user == section_id)
					data.set(CONF, sid, 'user', '');
				var users = L.toArray(srv.users);
				var changed = false;
				for (var i = users.length - 1; i >= 0; i--) {
					if (users[i] == section_id) {
						users.splice(i, 1);
						changed = true;
					}
				}
				if (changed)
					data.set(CONF, sid, 'users', users.length ? users : null);
			});
			data.remove(CONF, section_id);
			return this.map.save(null, true);
		};

		o = s.option(form.DummyValue, 'username', _('Username'));
		o.width = '25%';

		o = s.option(form.DummyValue, 'password', _('Password'));
		o.width = '25%';

		o = s.option(form.DummyValue, 'uuid', 'UUID');
		o.width = '25%';

		/* -------- Log panel -------- */
		var logArea = E('textarea', {
			'id': 'log_textarea',
			'class': 'cbi-input-textarea',
			'style': 'width:100%;margin-top:10px;font-family:monospace;',
			'rows': 20,
			'wrap': 'off',
			'readonly': 'readonly'
		});
		var firstLoadDone = false;
		var logBusy = false;

		function scrollToBottom() {
			logArea.scrollTop = logArea.scrollHeight;
		}

		function fetchLog() {
			if (logBusy)
				return Promise.resolve();
			logBusy = true;
			return Promise.resolve().then(function() {
				return pw.call('server_get_log', {});
			}).then(function(res) {
				var text = (res && typeof(res.result) == 'string') ? res.result : (typeof(res) == 'string' ? res : '');
				var wasBottom = (logArea.scrollTop + logArea.clientHeight >= logArea.scrollHeight - 10);
				if (logArea.value !== text)
					logArea.value = text;
				if (!firstLoadDone) {
					scrollToBottom();
					firstLoadDone = true;
				}
				else if (wasBottom) {
					scrollToBottom();
				}
			}).catch(function() {}).then(function() {
				logBusy = false;
			});
		}

		var logPanel = E('fieldset', { 'class': 'cbi-section pw-card', 'id': '_log_fieldset' }, [
			E('legend', {}, _('Logs')),
			E('div', { 'class': 'pw-toolbar' }, [
				E('button', {
					'class': 'btn cbi-button cbi-button-remove',
					'click': ui.createHandlerFn(this, function() {
						return pw.call('server_clear_log', {}).then(function() {
							logArea.value = '';
							scrollToBottom();
						}).catch(function() {});
					})
				}, _('Clear logs'))
			]),
			logArea
		]);

		return m.render().then(function(mapEl) {
			var root = E('div', { 'class': 'pw-root' }, [
				header(_('Server-Side')),
				mapEl,
				logPanel
			]);

			/* Status marks are re-created whenever the map re-renders (save/add/remove). */
			var observer = new MutationObserver(function() {
				if (mapEl.querySelector('._servers_status[data-sid]:not([data-polled])')) {
					var fresh = mapEl.querySelectorAll('._servers_status[data-sid]:not([data-polled])');
					for (var i = 0; i < fresh.length; i++)
						fresh[i].setAttribute('data-polled', '1');
					self.refreshStatus(mapEl);
				}
			});
			observer.observe(mapEl, { childList: true, subtree: true });

			var marks = mapEl.querySelectorAll('._servers_status[data-sid]');
			for (var i = 0; i < marks.length; i++)
				marks[i].setAttribute('data-polled', '1');
			self.refreshStatus(mapEl);

			fetchLog();
			poll.add(fetchLog, SERVER_LOG_POLL);
			poll.add(function() { return self.refreshStatus(mapEl); }, 5);

			return root;
		});
	}
});
