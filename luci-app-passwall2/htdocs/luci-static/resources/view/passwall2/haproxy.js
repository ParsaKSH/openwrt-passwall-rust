'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require dom';
'require passwall2.pw as pw';

/*
 * Load Balancing page (upstream: model/cbi/passwall2/client/haproxy.lua,
 * view/passwall2/haproxy/status.htm, view/passwall2/haproxy/js.htm). Spec 08 §7, 10 §2.11.
 */

const CFG = 'passwall2';

function purl() {
	return L.url.apply(L, ['admin/services/passwall2'].concat(Array.prototype.slice.call(arguments)));
}

function firstSid(type) {
	const list = uci.sections(CFG, type);
	return list.length ? list[0]['.name'] : uci.add(CFG, type);
}

/* api.is_ipv6addrport: "%[(.-)%]:([0-9]+)$" */
function isIPv6AddrPort(val) {
	const m = String(val).match(/\[(.*?)\]:([0-9]+)$/);
	return !!m && pw.datatype('ip6addr', m[1]) && pw.datatype('port', m[2]);
}

const PROBE_URLS = [
	['https://cp.cloudflare.com/', 'Cloudflare'],
	['https://www.gstatic.com/generate_204', 'Gstatic'],
	['https://www.google.com/generate_204', 'Google'],
	['https://www.youtube.com/generate_204', 'YouTube'],
	['https://connect.rom.miui.com/generate_204', 'MIUI (CN)'],
	['https://connectivitycheck.platform.hicloud.com/generate_204', 'HiCloud (CN)'],
	['https://wifi.vivo.com.cn/generate_204', 'VIVO (CN)']
];

return view.extend({
	load: function () {
		return Promise.all([
			uci.load(CFG),
			L.resolveDefault(uci.load('network'), null),
			L.resolveDefault(pw.loadCSS(), null)
		]);
	},

	render: function (data) {
		const gsid = firstSid('global_haproxy');
		let m, s, o;

		m = new form.Map(CFG);

		/* [[ Haproxy Settings ]] */
		s = m.section(form.NamedSection, gsid, 'global_haproxy', _('Basic Settings'));
		s.addremove = false;

		o = s.option(form.Flag, 'balancing_enable', _('Enable Load Balancing'));
		o.rmempty = false;
		o.default = '0';

		o = s.option(form.Flag, 'console_auth', _('Console Login Auth'));
		o.default = '0';
		o.depends('balancing_enable', '1');

		o = s.option(form.Value, 'console_user', _('Console Username'));
		o.default = '';
		o.depends('console_auth', '1');

		o = s.option(form.Value, 'console_password', _('Console Password'));
		o.password = true;
		o.default = '';
		o.depends('console_auth', '1');

		o = s.option(form.Value, 'console_port', _('Console Port'),
			_('In the browser input routing IP plus port access, such as:192.168.1.1:1188'));
		o.datatype = 'port';
		o.default = '1188';
		o.depends('balancing_enable', '1');

		o = s.option(form.Flag, 'bind_local', _('Haproxy Port') + ' ' + _('Bind Local'),
			_('When selected, it can only be accessed localhost.'));
		o.default = '0';
		o.depends('balancing_enable', '1');

		o = s.option(form.ListValue, 'balancingStrategy', _('Balancing Strategy'));
		o.value('roundrobin', 'roundRobin');
		o.value('random', 'random');
		o.value('leastconn', 'leastConn');
		o.value('source', 'source');
		o.default = 'roundrobin';
		o.depends('balancing_enable', '1');

		o = s.option(form.ListValue, 'health_check_type', _('Health Check Type'));
		o.default = 'script_logic';
		o.value('tcp', 'TCP');
		o.value('script_logic', _('URL Test') + '(passwall2 %s)'.format(_('Inner implement')));
		o.depends('balancing_enable', '1');

		o = s.option(form.Value, 'health_probe_url', _('Probe URL'));
		PROBE_URLS.forEach((p) => o.value(p[0], p[1]));
		o.default = PROBE_URLS[2][0];
		o.description = _('The URL used to detect the connection status.');
		o.depends('health_check_type', 'script_logic');

		o = s.option(form.Value, 'health_check_inter', _('Health Check Inter'));
		o.datatype = 'min(20)';
		o.default = '60';
		o.depends('balancing_enable', '1');
		o.description = _('Units:seconds') + ' ( ≥ 20s )';

		o = s.option(form.DummyValue, 'health_check_tips', ' ');
		o.rawhtml = true;
		o.cfgvalue = function () {
			return '<span style="color: red">%s</span>'.format(_('When the URL test is used, the load balancing node will be converted into a Socks node. when node list set customizing, must be a Socks node, otherwise the health check will be invalid.'));
		};
		o.depends('health_check_type', 'script_logic');

		/* [[ Balancing Settings ]] */
		s = m.section(form.TableSection, 'haproxy_config', _('Node List'));
		s.description = '<font color="red">' +
			_('Add a node, Export Of Multi WAN Only support Multi Wan. Load specific gravity range 1-256. Multiple primary servers can be load balanced, standby will only be enabled when the primary server is offline! Multiple groups can be set, Haproxy port same one for each group.') + '<br>' +
			_('Note that the node configuration parameters for load balancing must be consistent when use TCP health check type, otherwise it cannot be used normally!') + '</font>';
		s.sortable = true;
		s.anonymous = true;
		s.addremove = true;
		/* create "haproxy_XXXXX"; a new entry inherits the listen port of the previous one (haproxy/js.htm) */
		s.handleAdd = function (ev) {
			const prev = this.cfgsections();
			let port = null;
			if (prev.length) {
				const last = prev[prev.length - 1];
				port = this.formvalue(last, 'haproxy_port');
				if (port == null) port = uci.get(CFG, last, 'haproxy_port');
			}
			const uid = uci.add(CFG, 'haproxy_config', 'haproxy_' + pw.randomChars(5));
			if (port != null && port !== '' && port !== '0')
				uci.set(CFG, uid, 'haproxy_port', String(port));
			return this.map.save(null, true);
		};

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		/* Node Address: node picker that also accepts a custom address:port */
		o = pw.addNodeOption(s, 'lbss', _('Node Address'), { custom: true, types: ['normal'] });
		o.rmempty = false;
		o.validate = function (section_id, value) {
			if (value == null || value === '')
				return _('Node address cannot be empty.');
			const t = uci.get(CFG, value);
			if (t && t['.type'] === 'nodes')
				return true;
			if (pw.datatype('hostport', value) || pw.datatype('ip4addrport', value))
				return true;
			if (isIPv6AddrPort(value))
				return true;
			return _('Not valid IP format, please re-enter!') + ' (IP:Port)';
		};

		o = s.option(form.Value, 'haproxy_port', _('Haproxy Port'));
		o.datatype = 'port';
		o.default = '1181';
		o.rmempty = false;
		o.width = '100px';

		o = s.option(form.Value, 'lbweight', _('Node Weight'));
		o.datatype = 'min(1)';
		o.default = '5';
		o.rmempty = false;
		o.width = '100px';

		o = s.option(form.ListValue, 'export', _('Export Of Multi WAN'));
		o.value('0', _('Auto'));
		(uci.sections('network', 'interface') || []).forEach((iface) => {
			if (iface['.name'] !== 'loopback')
				o.value(iface['.name']);
		});
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.ListValue, 'backup', _('Mode'));
		o.value('0', _('Primary'));
		o.value('1', _('Standby'));
		o.rmempty = false;

		pw.redirectAfterApply(purl('log'));

		/* status: haproxy_status poll every 5 s when enabled (haproxy/status.htm) */
		const statusEl = E('span', { 'id': '_status', 'class': 'pw-toolbar', 'style': 'display:inline-flex;gap:.5em;align-items:center' });
		const enabled = (uci.get(CFG, gsid, 'balancing_enable') || '0') === '1';
		const consolePort = uci.get(CFG, gsid, 'console_port') || '';
		if (enabled) {
			const update = () => L.resolveDefault(pw.call('haproxy_status', {}), null).then((r) => {
				if (!r) return;
				if (r.status) {
					dom.content(statusEl, [
						pw.badge(_('RUNNING'), 'ok'),
						E('button', {
							'class': 'btn cbi-button cbi-button-apply',
							'type': 'button',
							'click': () => window.open('http://' + window.location.hostname + ':' + consolePort, 'target', '')
						}, [_('Enter interface')])
					]);
				} else {
					dom.content(statusEl, [pw.badge(_('NOT RUNNING'), 'err')]);
				}
			});
			pw.poll(update, 5);
			update();
		}

		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Load Balancing'), null, [statusEl]),
			mapEl
		]));
	}
});
