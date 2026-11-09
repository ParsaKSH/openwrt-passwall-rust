'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';
'require passwall2.pw as pw';

/*
 * Other Settings page (upstream: model/cbi/passwall2/client/other.lua). Spec 08 §6.
 */

const CFG = 'passwall2';
const DIRECT_IP_FILE = '/usr/share/passwall2/direct_ip';
const DOMAINS_EXCLUDED_FILE = '/usr/share/passwall2/domains_excluded';

function purl() {
	return L.url.apply(L, ['admin/services/passwall2'].concat(Array.prototype.slice.call(arguments)));
}

function trim(s) {
	return (s == null ? '' : String(s)).replace(/^[\x00-\x20]+/, '').replace(/[\x00-\x20]+$/, '');
}

function firstSid(type) {
	const list = uci.sections(CFG, type);
	return list.length ? list[0]['.name'] : uci.add(CFG, type);
}

function cleanText(text) {
	return String(text == null ? '' : text)
		.replace(/\t/g, ' ')
		.replace(/ /g, ' ')
		.replace(/　/g, ' ')
		.replace(/^[ \t\n\r\f\v]+/, '')
		.replace(/[ \t\n\r\f\v]+$/, '\n')
		.replace(/\r\n/g, '\n')
		.replace(/[ \t]*\n[ \t]*/g, '\n');
}

/* port_validate: "-" -> ":" */
function portNormalize(v) {
	return String(v == null ? '' : v).replace(/-/g, ':');
}

function timeChoices(o) {
	const seen = {};
	const add = (v) => { if (!seen[v]) { seen[v] = true; o.value(v); } };
	add('0:00');
	for (let t = 0; t <= 23; t++)
		add(t === 12 ? t + ':30' : (t === 23 ? t + ':59' : t + ':00'));
}

/* TextValue whose content lives in a file instead of UCI */
const FileTextValue = form.TextValue.extend({
	__name__: 'PW.FileTextValue',
	load: function () {
		return this.fileContent != null ? this.fileContent : '';
	},
	write: function (section_id, value) {
		const content = this.transform(value).replace(/\r\n/g, '\n');
		return fs.write(this.filePath, content).then(() => {
			this.fileContent = content;
		}).catch((e) => {
			ui.addNotification(null, E('p', {}, [ _('Unable to save contents: %s').format(e && e.message || e) ]));
		});
	},
	transform: function (v) { return String(v); },
	remove: function () {
		if (this.removeWritesEmpty)
			return fs.write(this.filePath, '').then(() => {
				this.fileContent = '';
			}).catch(() => { });
	}
});

return view.extend({
	load: function () {
		return Promise.all([
			uci.load(CFG),
			pw.findedCom('sing-box'),
			pw.findedCom('xray'),
			pw.getModules(),
			L.resolveDefault(fs.read(DIRECT_IP_FILE), ''),
			L.resolveDefault(fs.read(DOMAINS_EXCLUDED_FILE), ''),
			L.resolveDefault(pw.loadCSS(), null)
		]);
	},

	render: function (data) {
		const has_singbox = !!data[1], has_xray = !!data[2], mods = data[3] || '';
		const directIp = data[4] || '', domainsExcluded = data[5] || '';
		let m, s, o;

		m = new form.Map(CFG);

		/* [[ Delay Settings ]] */
		s = m.section(form.NamedSection, firstSid('global_delay'), 'global_delay', _('Delay Settings'));
		s.addremove = false;

		o = s.option(form.Flag, 'start_daemon', _('Open and close Daemon'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'start_delay', _('Delay Start'), _('Units:seconds'));
		o.default = '1';
		o.rmempty = true;

		const modeTitles = {
			stop: [_('stop automatically mode'), _('stop Time'), _('stop Interval(Hour)')],
			start: [_('start automatically mode'), _('start Time'), _('start Interval(Hour)')],
			restart: [_('restart automatically mode'), _('restart Time'), _('restart Interval(Hour)')]
		};
		['stop', 'start', 'restart'].forEach((value) => {
			o = s.option(form.ListValue, value + '_week_mode', modeTitles[value][0]);
			o.value('', _('Disable'));
			if (value === 'restart')
				o.value('8', _('Loop Mode'));
			o.value('7', _('Every day'));
			o.value('1', _('Every Monday'));
			o.value('2', _('Every Tuesday'));
			o.value('3', _('Every Wednesday'));
			o.value('4', _('Every Thursday'));
			o.value('5', _('Every Friday'));
			o.value('6', _('Every Saturday'));
			o.value('0', _('Every Sunday'));

			o = s.option(form.Value, value + '_time_mode', modeTitles[value][1]);
			timeChoices(o);
			o.default = '0:00';
			o.validate = function (section_id, v) {
				return (v == null || v === '' || pw.isTimeHHMM(v)) ? true : _('valid time (hh:mm)');
			};
			['0', '1', '2', '3', '4', '5', '6', '7'].forEach((w) => o.depends(value + '_week_mode', w));

			o = s.option(form.ListValue, value + '_interval_mode', modeTitles[value][2]);
			for (let t = 1; t <= 24; t++)
				o.value(String(t), t + ' ' + _('Hour'));
			o.default = '2';
			o.depends(value + '_week_mode', '8');
		});

		/* [[ Forwarding Settings ]] */
		s = m.section(form.NamedSection, firstSid('global_forwarding'), 'global_forwarding', _('Forwarding Settings'));
		s.addremove = false;

		const portOption = (name, title, descr, choices, def) => {
			o = s.option(form.Value, name, title, descr);
			choices.forEach((c) => o.value(c[0], c[1]));
			if (def != null) o.default = def;
			o.write = function (section_id, value) {
				uci.set(CFG, section_id, name, portNormalize(value));
			};
			return o;
		};

		portOption('tcp_no_redir_ports', _('TCP No Redir Ports'), null,
			[['', _('No patterns are used')], ['1:65535', _('All')]]);
		portOption('udp_no_redir_ports', _('UDP No Redir Ports'),
			'<font color="red">%s</font>'.format(_("Fill in the ports you don't want to be forwarded by the agent, with the highest priority.")),
			[['', _('No patterns are used')], ['1:65535', _('All')]]);
		portOption('tcp_redir_ports', _('TCP Redir Ports'), null,
			[['1:65535', _('All')],
			['22,25,53,80,143,443,465,587,853,873,993,995,5222,8080,8443,9418', _('Common Use')],
			['80,443', _('Only Web')]], '1:65535');
		portOption('udp_redir_ports', _('UDP Redir Ports'), null, [['1:65535', _('All')]], '1:65535');

		o = s.option(form.DummyValue, 'tips', ' ');
		o.rawhtml = true;
		o.cfgvalue = function () {
			return '<font color="red">%s</font>'.format(
				_('The port settings support single ports and ranges.<br>Separate multiple ports with commas (,).<br>Example: 21,80,443,1000:2000.'));
		};

		o = s.option(form.ListValue, 'prefer_nft', _('Prefer firewall tools'));
		o.default = '1';
		o.value('0', 'Iptables');
		o.value('1', 'Nftables');

		/* transparent-proxy component check (plain substring search like upstream) */
		const has = (k) => mods.indexOf(k) >= 0;
		const tproxy_ok = pw.tproxyOk(mods);
		const ipv6_ok = tproxy_ok && (has('ip6table_mangle') || has('nft_tproxy'));

		if (tproxy_ok) {
			o = s.option(form.ListValue, 'tcp_proxy_way', _('TCP Proxy Way'));
			o.default = 'redirect';
			o.value('redirect', 'REDIRECT');
			o.value('tproxy', 'TPROXY');
			/* upstream depends("ipv6_tproxy", false): a missing field counts as unchecked */
			if (ipv6_ok)
				o.depends('ipv6_tproxy', '0');
			o.remove = function () { /* Do not delete while hidden */ };

			o = s.option(form.ListValue, '_tcp_proxy_way', _('TCP Proxy Way'));
			o.default = 'tproxy';
			o.value('tproxy', 'TPROXY');
			o.depends('ipv6_tproxy', '1');
			o.cfgvalue = function (section_id, set_value) {
				if (arguments.length > 1) return form.ListValue.prototype.cfgvalue.apply(this, arguments);
				return null;
			};
			o.write = function (section_id, value) {
				uci.set(CFG, section_id, 'tcp_proxy_way', value);
			};
			o.remove = function () { };

			if (ipv6_ok) {
				o = s.option(form.Flag, 'ipv6_tproxy', _('IPv6 TProxy'),
					'<font color="red">%s</font>'.format(_('Experimental feature. Make sure that your node supports IPv6.')));
				o.default = '0';
				o.rmempty = false;
			}
		}

		o = s.option(form.Flag, 'accept_icmp', _('Hijacking ICMP (PING)'));
		o.default = '0';

		o = s.option(form.Flag, 'accept_icmpv6', _('Hijacking ICMPv6 (IPv6 PING)'));
		o.depends('ipv6_tproxy', '1');
		o.default = '0';

		o = s.option(FileTextValue, 'direct_ip', _('Direct IP List'),
			'<font color="red">%s</font>'.format(_('These had been joined ip addresses will connect directly (not entering the core).')));
		o.rows = 15;
		o.wrap = 'off';
		o.monospace = true;
		o.filePath = DIRECT_IP_FILE;
		o.fileContent = directIp;
		o.removeWritesEmpty = true;
		o.transform = cleanText;
		o.validate = function (section_id, value) {
			const lines = String(cleanText(value || '')).split(/[\r\n]+/).map(trim);
			for (let i = 0; i < lines.length; i++) {
				const ipmask = lines[i];
				if (ipmask !== '' && ipmask.indexOf('#') !== 0 && ipmask.indexOf('geoip:') !== 0) {
					if (!(pw.datatype('ipmask4', ipmask) || pw.datatype('ipmask6', ipmask)))
						return ipmask + ' ' + _('Not valid IP format, please re-enter!');
				}
			}
			return true;
		};

		if (has_xray) {
			s = m.section(form.NamedSection, firstSid('global_xray'), 'global_xray', 'Xray ' + _('Settings'));
			s.addremove = false;

			o = s.option(form.Flag, 'fragment', _('Fragment'),
				_('TCP fragments, which can deceive the censorship system in some cases, such as bypassing SNI blacklists.'));
			o.default = '0';

			o = s.option(form.ListValue, 'fragment_packets', _('Fragment Packets'),
				_(' "1-3" is for segmentation at TCP layer, applying to the beginning 1 to 3 data writes by the client. "tlshello" is for TLS client hello packet fragmentation.'));
			o.default = 'tlshello';
			['tlshello', '1-1', '1-2', '1-3', '1-5'].forEach((v) => o.value(v, v));
			o.depends('fragment', '1');

			o = s.option(form.Value, 'fragment_lengths', _('Fragment Length'), _('Fragmented packet length (byte)'));
			o.default = '3-5,6-8,10-20';
			o.depends('fragment', '1');

			o = s.option(form.Value, 'fragment_delays', _('Fragment Delay'), _('Fragmentation interval (ms)'));
			o.default = '10-20';
			o.depends('fragment', '1');

			o = s.option(form.Value, 'fragment_maxSplit', _('Max Split'), _('Limit the maximum number of splits.'));
			o.datatype = 'or(uinteger,portrange)';
			o.default = '3-6';
			o.depends('fragment', '1');

			o = s.option(form.Flag, 'noise', _('Noise'),
				_('UDP noise, Under some circumstances it can bypass some UDP based protocol restrictions.'));
			o.default = '0';

			o = s.option(form.Flag, 'sniffing_override_dest', _('Override the connection destination address'));
			o.default = '0';
			o.description = _('Override the connection destination address with the sniffed domain.<br />Otherwise use sniffed domain for routing only.<br />If using shunt nodes, configure the domain shunt rules correctly.');

			/* upstream quirk: depends on a field ("sniffing") that does not exist here -> always hidden, removed on save */
			o = s.option(form.Flag, 'route_only', _('Sniffing Route Only'));
			o.default = '0';
			o.depends('sniffing', '1');

			o = s.option(FileTextValue, 'excluded_domains', _('Excluded Domains'),
				_('If the traffic sniffing result is in this list, the destination address will not be overridden.'));
			o.rows = 15;
			o.wrap = 'off';
			o.monospace = true;
			o.filePath = DOMAINS_EXCLUDED_FILE;
			o.fileContent = domainsExcluded;
			o.removeWritesEmpty = false;
			o.depends({ sniffing_override_dest: '1' });

			o = s.option(form.Value, 'buffer_size', _('Buffer Size'), _('Buffer size for every connection (kB)'));
			o.datatype = 'uinteger';

			/* [[ Xray Noise Packets ]] */
			s = m.section(form.TableSection, 'xray_noise_packets', _('Xray Noise Packets'),
				'<font color="red">%s</font>'.format(_('To send noise packets, select "Noise" in Xray Settings.')));
			s.sortable = true;
			s.anonymous = true;
			s.addremove = true;
			s.handleAdd = function (ev) {
				return form.TableSection.prototype.handleAdd.apply(this, [ev, 'xray_noise_' + pw.randomChars(5)]);
			};

			o = s.option(form.Flag, 'enabled', _('Enable'));
			o.default = '1';
			o.rmempty = false;

			o = s.option(form.ListValue, 'type', _('Type'));
			['rand', 'array', 'str', 'hex', 'base64'].forEach((v) => o.value(v, v));

			o = s.option(form.Value, 'packet', _('Packet | Rand Length'));
			o.datatype = 'minlength(1)';
			o.rmempty = false;

			o = s.option(form.Value, 'delay', _('Delay (ms)'));
			o.datatype = 'or(uinteger,portrange)';
			o.rmempty = false;
		}

		if (has_singbox) {
			s = m.section(form.NamedSection, firstSid('global_singbox'), 'global_singbox', 'Sing-Box ' + _('Settings'));
			s.addremove = false;

			o = s.option(form.Flag, 'record_fragment', 'TLS Record ' + _('Fragment'),
				_('Split handshake data into multiple TLS records for better censorship evasion. Low overhead. Recommended to enable first.'));
			o.default = '0';

			o = s.option(form.Flag, 'fragment', 'TLS TCP ' + _('Fragment'),
				_('Split handshake into multiple TCP segments. Enhances obfuscation. May increase delay. Use only if needed.'));
			o.default = '0';
		}

		pw.redirectAfterApply(purl('log'));

		return m.render().then((mapEl) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader(_('Other Settings'), null, [
				tproxy_ok ? pw.badge('TPROXY', 'ok') : pw.badge(_('Missing components, transparent proxy is unavailable.'), 'err')
			]),
			mapEl
		]));
	}
});
