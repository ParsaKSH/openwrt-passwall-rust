'use strict';
'require view';
'require dom';
'require poll';
'require uci';
'require ui';
'require passwall2.pw as pw';

/*
 * Runtime Logs (upstream: luasrc/view/passwall2/log/log.htm, menu "log", order 999).
 *
 * Default view = the client log (/tmp/log/passwall2.log): `get_log` polled every 5 s,
 * "Clear logs" -> `clear_log`, auto-scroll (first load -> bottom, later only when the
 * user was within 10 px of the bottom).
 *
 * The same page also replaces upstream's "open the raw log endpoint in a new tab" links
 * for the per-instance logs (upstream returns `tail` output with "\n" -> "<br />", or an
 * alert script when the file does not exist). Other pages can link here with:
 *   log?redir=<acl id>      -> get_redir_log {id}     (e.g. acl_default, ACL rule ids)
 *   log?socks=<socks sid>   -> get_socks_log {name}
 *   log?server=<server sid> -> server_log {id}
 *   log?source=server       -> server_get_log / server_clear_log (server-side main log)
 */

var LOG_POLL_CLIENT = 5;
var LOG_POLL_SERVER = 3;

function callText(method, params) {
	return pw.call(method, params || {}).then(function(res) {
		if (res == null)
			return '';
		if (typeof(res) == 'string')
			return res;
		if (typeof(res.result) == 'string')
			return res.result;
		return '';
	});
}

/* Instance logs come back HTML-ish (upstream wrote them straight into a browser tab). */
function instanceLogText(raw) {
	raw = String(raw == null ? '' : raw);
	if (/<script>\s*alert\(/i.test(raw))
		return null;
	return raw.replace(/<br\s*\/?>/gi, '\n');
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

function parseQuery() {
	var q = {};
	var s = (window.location.search || '').replace(/^\?/, '');
	s.split('&').forEach(function(kv) {
		if (!kv)
			return;
		var i = kv.indexOf('=');
		var k = decodeURIComponent((i < 0 ? kv : kv.substring(0, i)).replace(/\+/g, ' '));
		var v = i < 0 ? '' : decodeURIComponent(kv.substring(i + 1).replace(/\+/g, ' '));
		q[k] = v;
	});
	return q;
}

/* Builds the list of log sources shown in the selector. */
function buildSources(q) {
	var list = [];

	list.push({ key: 'client', label: _('Runtime Logs'), method: 'get_log', clear: 'clear_log', interval: LOG_POLL_CLIENT });
	list.push({ key: 'redir:acl_default', label: _('Node Log') + ' (acl_default)', method: 'get_redir_log', params: { id: 'acl_default' }, instance: true, interval: LOG_POLL_CLIENT });

	uci.sections('passwall2', 'acl_rule').forEach(function(s) {
		var sid = s['.name'];
		list.push({
			key: 'redir:' + sid,
			label: _('ACLs') + ': ' + (s.remarks || sid),
			method: 'get_redir_log', params: { id: sid }, instance: true, interval: LOG_POLL_CLIENT
		});
	});

	uci.sections('passwall2', 'socks').forEach(function(s) {
		var sid = s['.name'];
		list.push({
			key: 'socks:' + sid,
			label: _('Socks Config') + ': ' + (s.port ? s.port + ' ' : '') + '(' + sid + ')',
			method: 'get_socks_log', params: { name: sid }, instance: true, interval: LOG_POLL_CLIENT
		});
	});

	list.push({ key: 'server', label: _('Server-Side') + ': ' + _('Logs'), method: 'server_get_log', clear: 'server_clear_log', interval: LOG_POLL_SERVER });

	uci.sections('passwall2_server', 'server').forEach(function(s) {
		var sid = s['.name'];
		list.push({
			key: 'server:' + sid,
			label: _('Server-Side') + ': ' + (s.remarks || sid),
			method: 'server_log', params: { id: sid }, instance: true, interval: LOG_POLL_SERVER
		});
	});

	/* Requested via URL but not in the config (e.g. a socks id typed by hand) -> still allow it. */
	function ensure(key, label, method, params, interval) {
		for (var i = 0; i < list.length; i++)
			if (list[i].key == key)
				return;
		list.push({ key: key, label: label, method: method, params: params, instance: true, interval: interval });
	}

	if (q.redir && /^[A-Za-z0-9_-]+$/.test(q.redir))
		ensure('redir:' + q.redir, _('Node Log') + ' (' + q.redir + ')', 'get_redir_log', { id: q.redir }, LOG_POLL_CLIENT);
	if (q.socks && /^[A-Za-z0-9_-]+$/.test(q.socks))
		ensure('socks:' + q.socks, _('Socks Config') + ' (' + q.socks + ')', 'get_socks_log', { name: q.socks }, LOG_POLL_CLIENT);
	if (q.server && /^[A-Za-z0-9_-]+$/.test(q.server))
		ensure('server:' + q.server, _('Server-Side') + ' (' + q.server + ')', 'server_log', { id: q.server }, LOG_POLL_SERVER);

	return list;
}

function initialKey(q) {
	if (q.redir)
		return 'redir:' + q.redir;
	if (q.socks)
		return 'socks:' + q.socks;
	if (q.server)
		return 'server:' + q.server;
	if (q.source == 'server')
		return 'server';
	return 'client';
}

return view.extend({
	load: function() {
		if (typeof(pw.loadCSS) == 'function') {
			try { pw.loadCSS(); } catch (e) {}
		}
		return Promise.all([
			uci.load('passwall2').catch(function() {}),
			uci.load('passwall2_server').catch(function() {})
		]);
	},

	render: function() {
		var q = parseQuery();
		var sources = buildSources(q);
		var current = null;
		var pollFn = null;
		var firstLoadDone = false;
		var busy = false;
		var autoRefresh = true;

		var textarea = E('textarea', {
			'id': 'log_textarea',
			'class': 'cbi-input-textarea pw-log',
			'style': 'width:100%;margin-top:10px;font-family:monospace;',
			'rows': 40,
			'wrap': 'off',
			'readonly': 'readonly',
			'spellcheck': 'false'
		});

		var status = E('span', { 'class': 'pw-log-status', 'style': 'margin-left:.5em;opacity:.8' });

		var clearBtn = E('button', {
			'class': 'btn cbi-button cbi-button-remove',
			'click': ui.createHandlerFn(this, function() {
				if (!current || !current.clear)
					return;
				return pw.call(current.clear, {}).then(function() {
					textarea.value = '';
					textarea.scrollTop = textarea.scrollHeight;
				}).catch(function(e) {
					ui.addNotification(null, E('p', {}, _('Error') + ': ' + (e && e.message ? e.message : e)), 'danger');
				});
			})
		}, _('Clear logs'));

		var refreshBtn = E('button', {
			'class': 'btn cbi-button cbi-button-neutral',
			'click': ui.createHandlerFn(this, function() { return fetchLog(true); })
		}, _('Refresh'));

		var autoBox = E('input', { 'type': 'checkbox', 'checked': 'checked', 'id': 'pw-log-auto' });
		autoBox.addEventListener('change', function() {
			autoRefresh = autoBox.checked;
			restartPoll();
		});

		var select = E('select', { 'class': 'cbi-input-select', 'id': 'pw-log-source' },
			sources.map(function(s) { return E('option', { 'value': s.key }, s.label); }));

		function setText(text) {
			var wasBottom = (textarea.scrollTop + textarea.clientHeight >= textarea.scrollHeight - 10);
			if (textarea.value !== text)
				textarea.value = text;
			if (!firstLoadDone) {
				textarea.scrollTop = textarea.scrollHeight;
				firstLoadDone = true;
			}
			else if (wasBottom) {
				textarea.scrollTop = textarea.scrollHeight;
			}
		}

		function fetchLog(force) {
			if (!current || (busy && !force))
				return Promise.resolve();
			var src = current;
			busy = true;
			return callText(src.method, src.params).then(function(raw) {
				if (src !== current)
					return;
				if (src.instance) {
					var text = instanceLogText(raw);
					if (text == null) {
						status.textContent = _('Not enabled log');
						setText('');
						return;
					}
					status.textContent = '';
					setText(text);
				}
				else {
					status.textContent = '';
					setText(raw);
				}
			}).catch(function(e) {
				if (src === current)
					status.textContent = _('Error') + (e && e.message ? ': ' + e.message : '');
			}).then(function() {
				busy = false;
			});
		}

		function restartPoll() {
			if (pollFn) {
				poll.remove(pollFn);
				pollFn = null;
			}
			if (!autoRefresh || !current)
				return;
			pollFn = function() { return fetchLog(false); };
			poll.add(pollFn, current.interval || LOG_POLL_CLIENT);
		}

		function selectSource(key) {
			current = null;
			for (var i = 0; i < sources.length; i++)
				if (sources[i].key == key)
					current = sources[i];
			if (!current)
				current = sources[0];
			select.value = current.key;
			clearBtn.style.display = current.clear ? '' : 'none';
			textarea.rows = (current.key == 'server') ? 20 : 40;
			firstLoadDone = false;
			status.textContent = '';
			textarea.value = '';
			fetchLog(true);
			restartPoll();
		}

		select.addEventListener('change', function() {
			selectSource(select.value);
		});

		selectSource(initialKey(q));

		return E('div', { 'class': 'pw-root' }, [
			header(_('Runtime Logs')),
			E('fieldset', { 'class': 'cbi-section pw-card', 'id': '_log_fieldset' }, [
				E('div', { 'class': 'pw-toolbar', 'style': 'display:flex;flex-wrap:wrap;align-items:center;gap:.5em' }, [
					select,
					clearBtn,
					refreshBtn,
					E('label', { 'for': 'pw-log-auto', 'style': 'display:inline-flex;align-items:center;gap:.3em' }, [autoBox, _('Auto refresh')]),
					status
				]),
				textarea
			])
		]);
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
