'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require dom';
'require fs';
'require passwall2.pw as pw';

/*
 * Basic Settings (upstream client/global.lua + global/status.htm, footer.htm, faq.htm,
 * backup.htm, include/node_change.htm, include/shunt_options.*).
 */

const CONF = 'passwall2';

/* global.lua doh_validate: "URL[,IP...]" where every IP is ipmask4/ipmask6; empty is an error. */
function dohValidate(section_id, value) {
	if (value != null && value !== '') {
		const parts = String(value).split(',');
		let ok = true;
		for (let i = 1; i < parts.length; i++) {
			if (parts[i] && !pw.datatype('ipmask4', parts[i]) && !pw.datatype('ipmask6', parts[i]))
				ok = false;
		}
		if (ok)
			return true;
	}
	return _('DoH request address') + ' ' + _('Format must be:') + ' URL,IP';
}

/* Pseudo option rendering arbitrary content; never touches UCI. */
const ContentValue = form.DummyValue.extend({
	__name__: 'CBI.PwContent',
	load() { return null; },
	cfgvalue() { return null; },
	renderWidget(section_id) {
		return (typeof(this.renderContent) === 'function') ? this.renderContent(section_id) : E('div');
	},
	write() {},
	remove() {}
});

return view.extend({
	load() {
		return Promise.all([
			uci.load(CONF),
			pw.findedCom('sing-box'),
			pw.findedCom('xray'),
			pw.getModules(),
			pw.isFinded('geoview'),
			L.resolveDefault(fs.read(pw.TMP_PATH + '/var'), '')
		]).then((r) => ({
			hasSingbox: !!r[1],
			hasXray: !!r[2],
			mods: r[3] || '',
			geoview: !!r[4],
			cacheVars: r[5] || ''
		}));
	},

	/* ------------------------------------------------------------ status dashboard (global/status.htm) */

	renderStatus() {
		const tiles = {};
		const mkTile = (id, ico, title, stateText, kind, clickable) => {
			const state = pw.badge(stateText, kind);
			const tile = E('div', {
				'class': 'pw-tile' + (clickable ? ' pw-tile-click' : ''),
				'role': clickable ? 'button' : null,
				'tabindex': clickable ? '0' : null,
				'title': clickable ? _('Touch Check') : null
			}, [
				E('div', { 'class': 'pw-tile-icon' }, [ pw.icon(ico, 28) ]),
				E('div', { 'class': 'pw-tile-text' }, [
					E('div', { 'class': 'pw-tile-title' }, [ title ]),
					E('div', { 'class': 'pw-tile-state' }, [ state ])
				])
			]);
			tiles[id] = { el: tile, state: state, busy: false };
			return tile;
		};

		const checkConnect = (type, url) => {
			const t = tiles[type];
			if (!t || t.busy)
				return;
			t.busy = true;
			t.el.classList.add('pw-tile-busy');
			pw.setBadge(t.state, _('Check...'), 'info');
			return pw.call('connect_status', { type: type, url: url }).then((rv) => {
				if (rv && rv.ping_type === 'curl') {
					const ms = rv.use_time;
					if (ms === '' || ms == null)
						pw.setBadge(t.state, _('Problem detected!'), 'err');
					else
						pw.setBadge(t.state, ms + ' ms', pw.latencyKind(ms, 1000, 2000));
				}
				else if (rv && rv.status) {
					pw.setBadge(t.state, _('Working...'), 'ok');
				}
				else {
					pw.setBadge(t.state, _('Problem detected!'), 'err');
				}
			}).catch(() => {
				pw.setBadge(t.state, _('Problem detected!'), 'err');
			}).finally(() => {
				t.busy = false;
				t.el.classList.remove('pw-tile-busy');
			});
		};

		const sites = [
			[ 'baidu', _('Baidu Connection'), 'https://www.baidu.com' ],
			[ 'google', _('Google Connection'), 'https://www.google.com/generate_204' ],
			[ 'github', _('GitHub Connection'), 'https://github.com' ]
		];

		const grid = E('div', { 'class': 'pw-status-grid' }, [
			mkTile('core', 'cpu', _('Core'), _('NOT RUNNING'), 'err', false)
		].concat(sites.map((s) => {
			const el = mkTile(s[0], s[0] === 'github' ? 'link' : 'globe', s[1], _('Touch Check'), 'err', true);
			el.addEventListener('click', () => checkConnect(s[0], s[2]));
			el.addEventListener('keydown', (ev) => {
				if (ev.key === 'Enter' || ev.key === ' ') {
					ev.preventDefault();
					checkConnect(s[0], s[2]);
				}
			});
			return el;
		})));

		/* configuration summary (node, DNS, ports) */
		const gsid = this.gsid;
		const nodeId = uci.get(CONF, gsid, 'node');
		const nodeSec = nodeId ? uci.get(CONF, nodeId) : null;
		const proto = uci.get(CONF, gsid, 'remote_dns_protocol') || 'tcp';
		const remote = (proto === 'doh' || proto === 'http3')
			? (uci.get(CONF, gsid, 'remote_dns_doh') || 'https://1.1.1.1/dns-query')
			: (uci.get(CONF, gsid, 'remote_dns') || '1.1.1.1');
		const directProto = uci.get(CONF, gsid, 'direct_dns_protocol') || '';
		const direct = directProto ? (uci.get(CONF, gsid, 'direct_dns') || '223.5.5.5') : _('Auto');
		const socksTotal = (uci.sections(CONF, 'socks') || []).length;
		const socksOn = (uci.sections(CONF, 'socks') || []).filter((s) => s.enabled !== '0').length;
		const enabled = uci.get(CONF, gsid, 'enabled') === '1';

		this.usingEl = E('span', { 'class': 'pw-info-value' }, [ '-' ]);
		const info = (ico, label, value) => E('div', { 'class': 'pw-info' }, [
			pw.icon(ico, 16),
			E('span', { 'class': 'pw-info-label' }, [ label ]),
			(value != null && typeof(value) === 'object' && 'nodeType' in value) ? value : E('span', { 'class': 'pw-info-value', 'title': String(value) }, [ String(value) ])
		]);

		const strip = E('div', { 'class': 'pw-info-strip' }, [
			info('shield', _('Main switch'), pw.badge(enabled ? _('Enable') : _('Disable'), enabled ? 'ok' : 'muted')),
			info('server', _('Node'), nodeSec ? pw.nodeLabel(nodeSec) : _('Close')),
			info('ping', _('Current Node'), this.usingEl),
			info('dns', _('Remote DNS'), proto.toUpperCase() + ' ' + remote),
			info('dns', _('Direct DNS'), direct),
			nodeId ? info('plug', _('Node') + ' Socks ' + _('Listen Port'), uci.get(CONF, gsid, 'node_socks_port') || '1070') : '',
			info('list', _('Socks Config'), '%d / %d'.format(socksOn, socksTotal))
		]);

		let lastRunning = null;
		const refresh = () => pw.call('index_status').then((data) => {
			const running = !!(data && data.global_status);
			pw.setBadge(tiles.core.state, running ? _('RUNNING') : _('NOT RUNNING'), running ? 'ok' : 'err');
			tiles.core.el.classList.toggle('pw-tile-running', running);
			if (running !== lastRunning) {
				lastRunning = running;
				if (!running) {
					this.usingEl.textContent = '-';
				}
				else {
					pw.call('get_now_use_node').then((r) => {
						const id = r && r.global;
						this.usingEl.textContent = id ? (pw.nodeLabel(id) || id) : '-';
						this.usingEl.title = this.usingEl.textContent;
					}).catch(() => {});
				}
			}
		}).catch(() => {});

		pw.poll(refresh, 5);
		refresh();

		return E('div', { 'class': 'pw-card pw-status-card', 'id': '_passwall2_status_fieldset' }, [
			E('div', { 'class': 'pw-card-body' }, [ grid, strip ])
		]);
	},

	/* ------------------------------------------------------------ FAQ tab (global/faq.htm) */

	renderFaq() {
		/* upstream faq.htm: "Browser access" shows the controller's hide/show URLs (menu.d: passwall2/{hide,show}) */
		const hideUrl = window.location.origin + pw.url('hide');
		const showUrl = window.location.origin + pw.url('show');
		const doHide = (ev) => {
			ev.preventDefault();
			return pw.confirm(_('Hide in main menu:'), _('Are you sure to hide?')).then((ok) => {
				if (!ok)
					return;
				return pw.call('hide').catch(() => {}).then(() => {
					window.setTimeout(() => { window.location.href = L.url('admin/status/overview'); }, 1500);
				});
			});
		};
		const doShow = (ev) => {
			ev.preventDefault();
			return pw.call('show').catch(() => {}).then(() => {
				window.setTimeout(() => { window.location.href = pw.url(); }, 1500);
			});
		};

		return E('div', { 'class': 'pw-faq' }, [
			E('div', { 'id': 'faq_dns' }, [
				E('b', { 'class': 'pw-faq-title' }, [ _('DNS related issues:') ]),
				E('ul', {}, [
					E('li', { 'class': 'pw-faq-item' }, [ '1. ', E('span', {}, [ _("Certain browsers such as Chrome have built-in DNS service, which may affect DNS resolution settings. You can go to 'Settings -> Privacy and security -> Use secure DNS' menu to turn it off.") ]) ]),
					E('li', { 'class': 'pw-faq-item' }, [ '2. ', E('span', {}, [ _('If you are unable to access the internet after reboot, please try clearing the cache of your terminal devices (make sure to close all open browser application windows first, this step is especially important):') ]),
						E('ul', {}, [
							E('li', { 'class': 'pw-faq-sub' }, [ ' ◦ ', E('span', {}, [ _("For Windows systems, open Command Prompt and run the command 'ipconfig /flushdns'.") ]) ]),
							E('li', { 'class': 'pw-faq-sub' }, [ ' ◦ ', E('span', {}, [ _("For Mac systems, open Terminal and run the command 'sudo killall -HUP mDNSResponder'.") ]) ]),
							E('li', { 'class': 'pw-faq-sub' }, [ ' ◦ ', E('span', {}, [ _('For mobile devices, you can clear it by reconnecting to the network, such as toggling Airplane Mode and reconnecting to WiFi.') ]) ])
						])
					]),
					E('li', { 'class': 'pw-faq-item' }, [ '3. ', E('span', {}, [ _("Please make sure your device's network settings point both the DNS server and default gateway to this router, to ensure DNS queries are properly routed.") ]) ])
				])
			]),
			E('div', { 'id': 'faq_reset' }, [
				E('a', { 'href': '#', 'class': 'pw-faq-reset', 'click': doHide }, [ _('Hide in main menu:') ]), E('br'),
				' ' + _('Browser access:') + ' ', E('a', { 'href': '#', 'click': doHide }, [ hideUrl ]), E('br'),
				E('a', { 'href': '#', 'class': 'pw-faq-reset', 'click': doShow }, [ _('Show in main menu:') ]), E('br'),
				' ' + _('Browser access:') + ' ', E('a', { 'href': showUrl }, [ showUrl ]), E('br')
			])
		]);
	},

	/* ------------------------------------------------------------ Maintain tab (global/backup.htm) */

	dlBackup(ev) {
		return pw.call('create_backup').then((res) => {
			const filename = res && (res.filename || res.file_name);
			if (!filename)
				return;
			if (res.result == null || res.result === '')
				throw new Error(_('Backup failed!'));
			pw.downloadBlob(new Blob([ pw.b64ToBytes(res.result) ], { type: 'application/octet-stream' }), filename);
		}).catch((e) => {
			pw.alert(_('Backup and Restore'), (e && e.message) ? e.message : _('Backup failed!'));
		});
	},

	doReset(ev) {
		return pw.confirm(_('Restore to default configuration'), _('Do you want to restore the client to default settings?')).then((ok) => {
			if (!ok)
				return;
			return new Promise((resolve) => window.setTimeout(resolve, 1000)).then(() =>
				pw.confirm(_('Restore to default configuration'), _('Are you sure you want to restore the client to default settings?'))
			).then((ok2) => {
				if (!ok2)
					return;
				return pw.call('reset_config').catch(() => {}).then(() => {
					window.location.href = pw.url('log');
				});
			});
		});
	},

	showUpload(ev) {
		const fileInput = E('input', { 'class': 'cbi-input-file', 'type': 'file', 'id': 'ulfile', 'accept': '.tar.gz' });
		const uploadBtn = E('button', { 'class': 'btn cbi-button cbi-button-apply', 'id': 'upload-btn' }, [ _('UL Restore') ]);
		const closeBtn = E('button', { 'class': 'btn cbi-button cbi-button-remove' }, [ _('CLOSE WIN') ]);
		const progress = E('div', { 'class': 'pw-progress', 'style': 'display:none' }, [ E('div', { 'class': 'pw-progress-bar' }) ]);
		let busy = false;

		const resetBtn = () => {
			busy = false;
			uploadBtn.textContent = _('UL Restore');
			uploadBtn.disabled = false;
			progress.style.display = 'none';
		};

		closeBtn.addEventListener('click', () => {
			if (busy)
				return;
			fileInput.value = '';
			ui.hideModal();
		});

		uploadBtn.addEventListener('click', () => {
			if (busy)
				return;
			const file = fileInput.files && fileInput.files[0];
			if (!file) {
				pw.notify(_('Please select a file first.'), 'warn');
				return;
			}
			if (!/\.tar\.gz$/.test(file.name)) {
				pw.notify(_('Invalid file type. Please upload a .tar.gz file.'), 'err');
				fileInput.value = '';
				return;
			}
			if (file.size > 10 * 1024 * 1024) {
				pw.notify(_('File size exceeds 10MB limit.'), 'err');
				fileInput.value = '';
				return;
			}

			busy = true;
			uploadBtn.disabled = true;
			const reader = new FileReader();
			reader.onerror = () => { resetBtn(); pw.notify(_('Upload failed!'), 'err'); };
			reader.onload = (e) => {
				const base64Data = pw.bytesToB64(new Uint8Array(e.target.result));
				const targetByteSize = 64 * 1024;
				let chunkSize = Math.floor(targetByteSize * 4 / 3);
				chunkSize = chunkSize + (4 - (chunkSize % 4)) % 4;
				const totalChunks = Math.ceil(base64Data.length / chunkSize);
				let current = 0;
				progress.style.display = '';

				const sendNext = () => {
					if (current >= totalChunks) {
						resetBtn();
						window.location.href = pw.url('log');
						return;
					}
					const chunk = base64Data.substring(current * chunkSize, (current + 1) * chunkSize);
					return pw.call('restore_backup', {
						filename: file.name,
						chunk: chunk,
						chunk_index: String(current),
						total_chunks: String(totalChunks)
					}).then((resp) => {
						if (resp && resp.status === 'success') {
							current++;
							const pct = Math.floor((current / totalChunks) * 100);
							uploadBtn.textContent = _('Uploading...') + ' ' + pct + '%';
							progress.firstChild.style.width = pct + '%';
							return sendNext();
						}
						resetBtn();
						pw.alert(_('Restore Backup File'), _('Upload error:') + ' ' + ((resp && resp.message) || ''));
					}).catch((err) => {
						resetBtn();
						pw.alert(_('Restore Backup File'), _('Upload failed with status') + ' ' + ((err && err.message) || err));
					});
				};
				sendNext();
			};
			reader.readAsArrayBuffer(file);
		});

		ui.showModal(_('Restore Backup File'), [
			E('div', { 'class': 'pw-root pw-modal pw-upload' }, [
				E('div', { 'class': 'pw-upload-field' }, [ fileInput ]),
				progress
			]),
			E('div', { 'class': 'right' }, [ closeBtn, ' ', uploadBtn ])
		]);
		fileInput.focus();
	},

	renderBackup() {
		const row = (title, btn) => E('div', { 'class': 'pw-backup-row' }, [
			E('div', { 'class': 'pw-backup-title' }, [ title ]),
			E('div', { 'class': 'pw-backup-action' }, [ btn ])
		]);
		return E('div', { 'class': 'pw-backup' }, [
			E('h3', {}, [ _('Backup and Restore') ]),
			E('div', { 'class': 'cbi-section-descr' }, [
				_('Backup or Restore Client and Server Configurations.'), E('br'),
				E('span', { 'class': 'pw-text-err' }, [ _('Note: Restoring configurations across different versions may cause compatibility issues.') ])
			]),
			row(_('Create Backup File'), pw.button(_('DL Backup'), { kind: 'save', icon: 'download', click: (ev) => this.dlBackup(ev) })),
			row(_('Restore Backup File'), pw.button(_('RST Backup'), { kind: 'apply', icon: 'upload', click: (ev) => this.showUpload(ev) })),
			row(_('Restore to default configuration'), pw.button(_('Do Reset'), { kind: 'reset', icon: 'refresh', click: (ev) => this.doReset(ev) }))
		]);
	},

	/* ------------------------------------------------------------ page */

	render(data) {
		pw.loadCSS();
		const gsid = pw.globalSid('global');
		this.gsid = gsid;

		if (!gsid) {
			return pw.wrap(
				pw.pageHeader('PassWall 2', _('Basic Settings')),
				pw.card(null, E('p', {}, [ _('Configuration section %s is missing.').format('@global[0]') ]))
			);
		}

		const hasCore = data.hasSingbox || data.hasXray;
		const tproxy = pw.tproxyOk(data.mods);

		const nodes = pw.getNodesSync(false);
		const normalList = nodes.filter((n) => n.node_type === 'normal');
		const balancingList = nodes.filter((n) => n.protocol === '_balancing');
		const shuntList = nodes.filter((n) => n.protocol === '_shunt');
		const ifaceList = nodes.filter((n) => n.protocol === '_iface');
		/* global.lua: node choices are only populated when a normal or interface node exists */
		const populate = normalList.length > 0 || ifaceList.length > 0;
		const choiceNodes = populate ? nodes : [];

		let m, s, s2, o;

		m = new form.Map(CONF);
		m.tabbed = false;

		s = m.section(form.NamedSection, gsid, 'global');
		s.anonymous = true;
		s.addremove = false;

		s.tab('Main', _('Main'));

		o = s.taboption('Main', form.Flag, 'enabled', _('Main switch'));
		o.rmempty = false;

		/* ---- Node */
		const nodeOpt = pw.addNodeOption(s, 'node', '<a style="color: red">' + _('Node') + '</a>', {
			tab: 'Main',
			values: [ [ '', _('Close') ] ],
			nodes: choiceNodes,
			edit: true,
			log: () => pw.showLog(_('Log'), 'get_redir_log', { id: 'acl_default' })
		});

		o = s.taboption('Main', pw.HideValue, '_node');
		o.depends({ node: '', '!reverse': true });

		const isSingbox = s.taboption('Main', pw.HideValue, '_is_singbox');
		isSingbox.depends('_hide', '1');

		/* ---- Shunt (include/shunt_options.lua for every shunt node; visible while selected) */
		if (hasCore && nodes.length > 0) {
			if (normalList.length > 0 || ifaceList.length > 0) {
				pw.addShuntOptions(s, {
					tab: 'Shunt',
					tabTitle: _('Shunt Rule'),
					sectionId: gsid,
					nodeOption: 'node',
					nodes: nodes,
					geoview: data.geoview,
					globalSid: gsid
				});
			}
			else {
				o = s.taboption('Main', form.DummyValue, 'tips', '　');
				o.rawhtml = true;
				o.cfgvalue = function() {
					return '<a style="color: red">%s</a>'.format(_('There are no available nodes, please add or subscribe nodes first.'));
				};
				o.depends('_node', '1');
				shuntList.forEach((v) => o.depends('node', v.id));
				balancingList.forEach((v) => o.depends('node', v.id));
			}
		}

		/* ---- Transparent proxy component check */
		if (tproxy) {
			o = s.taboption('Main', form.Flag, 'localhost_proxy', _('Localhost Proxy'), _('When selected, localhost can transparent proxy.'));
			o.default = '1';
			o.rmempty = false;

			o = s.taboption('Main', form.Flag, 'client_proxy', _('Client Proxy'), _('When selected, devices in LAN can transparent proxy. Otherwise, it will not be proxy. But you can still use access control to allow the designated device to proxy.'));
			o.default = '1';
			o.rmempty = false;
		}
		else {
			const missing = '<div class="cbi-checkbox"><input class="cbi-input-checkbox" type="checkbox" disabled></div><div class="cbi-value-description"><font color="red">%s</font></div>'
				.format(_('Missing components, transparent proxy is unavailable.'));
			o = s.taboption('Main', form.DummyValue, 'localhost_proxy', _('Localhost Proxy'));
			o.rawhtml = true;
			o.cfgvalue = function() { return missing; };

			o = s.taboption('Main', form.DummyValue, 'client_proxy', _('Client Proxy'));
			o.rawhtml = true;
			o.cfgvalue = function() { return missing; };
		}

		o = s.taboption('Main', form.Value, 'node_socks_port', _('Node') + ' Socks ' + _('Listen Port'));
		o.default = '1070';
		o.datatype = 'port';
		o.depends('_node', '1');

		o = s.taboption('Main', form.Flag, 'node_socks_bind_local', _('Node') + ' Socks ' + _('Bind Local'), _('When selected, it can only be accessed localhost.'));
		o.default = '1';
		o.depends('_node', '1');

		/* ---- DNS */
		s.tab('DNS', _('DNS'));

		o = s.taboption('DNS', form.ListValue, 'direct_dns_protocol', _('Direct DNS Protocol'));
		o.value('', _('Auto'));
		o.value('udp', 'UDP');

		o = s.taboption('DNS', form.Value, 'direct_dns', _('Direct DNS'));
		o.datatype = 'or(ipaddr,ipaddrport(1))';
		o.default = '223.5.5.5';
		[ '223.5.5.5', '223.6.6.6', '114.114.114.114', '119.29.29.29', '180.76.76.76' ].forEach((v) => o.value(v));
		o.depends('direct_dns_protocol', 'tcp');
		o.depends('direct_dns_protocol', 'udp');

		o = s.taboption('DNS', form.ListValue, 'direct_dns_query_strategy', _('Direct Query Strategy'));
		o.default = 'UseIP';
		o.value('UseIP');
		o.value('UseIPv4');
		o.value('UseIPv6');

		o = s.taboption('DNS', form.ListValue, 'remote_dns_protocol', _('Remote DNS Protocol'));
		/* JS LuCI branch of global.lua: TLS/QUIC/HTTP3 only offered when the saved node is sing-box */
		o.load = function(section_id) {
			const cur = uci.get(CONF, gsid, 'node');
			const t = cur ? uci.get(CONF, cur, 'type') : null;
			this.keylist = [];
			this.vallist = [];
			this.value('tcp', 'TCP');
			this.value('doh', 'DoH');
			this.value('udp', 'UDP');
			if (t === 'sing-box') {
				this.value('tls', 'TLS(DoT)');
				this.value('quic', 'QUIC(DoQ)');
				this.value('http3', 'HTTP3(DoH3)');
			}
			return form.ListValue.prototype.load.call(this, section_id);
		};

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
		o.depends('remote_dns_protocol', 'tcp');
		o.depends('remote_dns_protocol', 'udp');
		o.depends('remote_dns_protocol', 'quic');
		o.depends('remote_dns_protocol', 'tls');

		o = s.taboption('DNS', form.Value, 'remote_dns_doh', _('Remote DNS DoH'));
		o.default = 'https://1.1.1.1/dns-query';
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
		o.validate = dohValidate;
		o.rmempty = false;
		o.depends('remote_dns_protocol', 'doh');
		o.depends('remote_dns_protocol', 'http3');

		o = s.taboption('DNS', form.Value, 'remote_dns_client_ip', _('Remote DNS EDNS Client Subnet'));
		o.description = _('Notify the DNS server when the DNS query is notified, the location of the client (cannot be a private IP address).') + '<br />' +
			_('This feature requires the DNS server to support the Edns Client Subnet (RFC7871).');
		o.datatype = 'ipaddr';

		o = s.taboption('DNS', form.ListValue, 'remote_dns_detour', _('Remote DNS Outbound'));
		o.default = 'remote';
		o.value('remote', _('Remote'));
		o.value('direct', _('Direct'));

		const fakedns = s.taboption('DNS', form.Flag, 'remote_fakedns', 'FakeDNS', _('Use FakeDNS work in the domain that proxy.'));
		fakedns.default = '0';
		fakedns.rmempty = false;

		o = s.taboption('DNS', form.ListValue, 'remote_dns_query_strategy', _('Remote Query Strategy'));
		o.default = 'UseIPv4';
		o.value('UseIP');
		o.value('UseIPv4');
		o.value('UseIPv6');

		o = s.taboption('DNS', form.Value, 'remote_rewrite_ttl', _('Remote DNS') + ' TTL');
		o.datatype = 'min(1)';
		o.default = '30';
		o.depends('_is_singbox', '1');

		o = s.taboption('DNS', form.TextValue, 'dns_hosts', _('Domain Override'));
		o.rows = 5;
		o.wrap = 'off';
		o.remove = function(section_id) {
			/* only delete when the submitted node is an Xray / sing-box node */
			const nv = nodeOpt.formvalue(section_id);
			if (nv) {
				const t = uci.get(CONF, nv, 'type');
				if (t === 'Xray' || t === 'sing-box')
					return form.TextValue.prototype.remove.call(this, section_id);
			}
		};

		o = s.taboption('DNS', form.Flag, 'dns_redirect', _('DNS Redirect'), _('Force special DNS server to need proxy devices.'));
		o.default = '1';
		o.rmempty = false;

		const preferNft = uci.get_first(CONF, 'global_forwarding', 'prefer_nft') === '1';
		const setTitle = preferNft ? _('Clear NFTSET') : _('Clear IPSET');
		o = s.taboption('DNS', ContentValue, 'clear_ipset', setTitle, _('Try this feature if the rule modification does not take effect.'));
		o.renderContent = function() {
			return E('button', {
				'type': 'button',
				'class': 'btn cbi-button cbi-button-remove',
				'click': ui.createHandlerFn(this, () => pw.call('flush_set', { redirect: '1', reload: '1' }).then(() => {
					window.location.href = pw.url('log');
				}).catch((e) => pw.notify((e && e.message) || String(e), 'err')))
			}, [ setTitle ]);
		};

		/* ---- Log */
		s.tab('log', _('Log'));

		o = s.taboption('log', form.Flag, 'log_node', _('Enable Node Log'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('log', form.ListValue, 'loglevel', _('Log Level'));
		o.default = 'warn';
		o.value('debug');
		o.value('info');
		o.value('warn');
		o.value('error');

		o = s.taboption('log', ContentValue, '_log', _('Log File'));
		o.renderContent = function() {
			return E('div', { 'class': 'pw-inline' }, [
				E('code', {}, [ pw.TMP_PATH + '/acl/acl_default.log' ]),
				' ',
				E('button', {
					'type': 'button',
					'class': 'btn cbi-button cbi-button-apply',
					'click': () => pw.showLog(_('View Log'), 'get_redir_log', { id: 'acl_default' })
				}, [ _('View Log') ])
			]);
		};
		o.depends('log_node', '1');

		/* ---- FAQ / Maintain */
		s.tab('faq', 'FAQ');
		o = s.taboption('faq', ContentValue, '_faq');
		o.renderContent = () => this.renderFaq();

		s.tab('maintain', _('Maintain'));
		o = s.taboption('maintain', ContentValue, '_backup');
		o.renderContent = () => this.renderBackup();

		/* ---- Socks Server */
		o = s.taboption('Main', form.Flag, 'socks_enabled', 'Socks ' + _('Main switch'));
		o.rmempty = false;

		s2 = m.section(form.TableSection, 'socks', _('Socks Config'));
		s2.sortable = true;
		s2.anonymous = true;
		s2.addremove = true;
		s2.extedit = pw.url('socks_config', '%s');
		s2.handleAdd = function(ev) {
			const uid = 'socks_' + pw.randomChars(5);
			this.map.data.add(CONF, 'socks', uid);
			return this.map.save(null, true).then(() => {
				window.location.href = pw.url('socks_config', uid);
			});
		};

		o = s2.option(ContentValue, 'status', _('Status'));
		o.renderContent = function(section_id) {
			const el = E('div', { 'class': '_status pw-socks-status', 'socks_id': section_id }, [ E('span', { 'class': 'pw-spinner' }) ]);
			const idx = (uci.sections(CONF, 'socks') || []).map((x) => x['.name']).indexOf(section_id);
			pw.call('socks_status', { index: String(idx), id: section_id }).then((r) => {
				const mark = (ok) => E('span', { 'class': ok ? 'pw-mark pw-mark-ok' : 'pw-mark pw-mark-err' }, [ ok ? '✓' : 'X' ]);
				const parts = [ mark(!!r.socks_status) ];
				if (r.use_http && r.use_http != '0')
					parts.push(mark(!!r.http_status));
				dom.content(el, parts);
			}).catch(() => {
				dom.content(el, E('span', { 'class': 'pw-mark pw-mark-err' }, [ 'X' ]));
			});
			return el;
		};

		o = s2.option(form.Flag, 'enabled', _('Enable'));
		o.default = '1';
		o.rmempty = false;

		pw.addNodeOption(s2, 'node', _('Socks Node'), {
			nodes: choiceNodes,
			edit: true,
			log: (sid) => pw.showLog(_('Log'), 'get_socks_log', { name: sid })
		});

		o = s2.option(form.DummyValue, 'now_node', _('Current Node'));
		o.rawhtml = true;
		o.cfgvalue = function(section_id) {
			const cur = pw.parseCacheVar(data.cacheVars, section_id);
			if (cur) {
				const n = uci.get(CONF, cur);
				if (n)
					return pw.escapeHTML(pw.nodeRemarks(n)).replace(/(：)\[/g, '$1<br>[');
			}
			return '';
		};

		o = s2.option(form.Value, 'port', 'Socks ' + _('Listen Port'));
		o.datatype = 'port';
		o.rmempty = false;
		o.load = function(section_id) {
			/* global.lua: default = n + 1080, n = 1 + number of socks sections */
			this.default = String((uci.sections(CONF, 'socks') || []).length + 1081);
			return form.Value.prototype.load.call(this, section_id);
		};

		/* ---- node-dependent visibility (end of global.lua) */
		if (populate) {
			nodes.forEach((v) => {
				if (v.type === 'sing-box')
					isSingbox.depends({ node: v.id });
				if (v.node_type === 'normal' || v.protocol === '_balancing' || v.protocol === '_urltest')
					fakedns.depends({ node: v.id });
			});
		}

		/* footer.htm: show the Socks main switch at the top of the Socks table */
		const origRender = m.renderContents.bind(m);
		m.renderContents = function() {
			return origRender().then((mapEl) => {
				const flag = mapEl.querySelector('[id="cbi-%s-%s-socks_enabled"]'.format(CONF, gsid));
				const socksSec = mapEl.querySelector('#cbi-%s-socks'.format(CONF));
				if (flag && socksSec) {
					flag.classList.add('pw-socks-switch');
					const anchor = socksSec.querySelector('.cbi-section-descr') || socksSec.querySelector('table');
					if (anchor)
						anchor.parentNode.insertBefore(flag, anchor);
					else
						socksSec.appendChild(flag);
				}
				return mapEl;
			});
		};

		return m.render().then((mapEl) => pw.wrap(
			pw.pageHeader('PassWall 2', _('Basic Settings'), [
				pw.button(_('Runtime Logs'), { icon: 'log', click: () => { window.location.href = pw.url('log'); } })
			]),
			this.renderStatus(),
			E('div', { 'class': 'pw-global-map' }, [ mapEl ])
		));
	},

	/* Register the "land on Runtime Logs" redirect only once the save succeeded: a rejected
	 * save (validation error) must not leave the listener behind for a later, unrelated apply. */
	handleSaveApply(ev, mode) {
		return this.handleSave(ev).then(() => {
			pw.redirectAfterApply(pw.url('log'));
			return ui.changes.apply(mode == '0');
		});
	}
});
