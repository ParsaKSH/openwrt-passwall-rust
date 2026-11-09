'use strict';
'require view';
'require dom';
'require form';
'require uci';
'require ui';
'require passwall2.pw as pw';

/*
 * App Update (upstream: client/app_update.lua + view/passwall2/app_update/app_version.htm).
 *
 * Version rows: PassWall2 itself + every component of `com.order` (geoview, xray, sing-box).
 * Endpoint mapping (rpcd, see docs/ARCHITECTURE.md):
 *   version_<k>      -> com_version {com:k}                   -> {code:1, data:"<ver>"}
 *   check_<k>        -> com_check   {com:k, arch:''}          -> upstream to_check / to_check_self JSON
 *   update_<k> ...   -> com_update  {com:k, task?, ...}       -> upstream to_download / progress / extract / move / install JSON
 * The self-install result is read from the static file
 * /luci-static/resources/passwall2-update/<id>.json (rpcd may restart during install).
 */

var APPNAME = 'passwall2';

/* luci.passwall2.com: order + display names + default paths */
var COM_ORDER = [ 'geoview', 'xray', 'sing-box' ];
var COM = {
	'geoview': { name: 'Geoview', default_path: '/usr/bin/geoview' },
	'xray': { name: 'Xray', default_path: '/usr/bin/xray' },
	'sing-box': { name: 'Sing-Box', default_path: '/usr/bin/sing-box' }
};

/* Release links come from the remote release API (possibly via a GitHub proxy): only plain
 * http(s) URLs may become an href, anything else (javascript:, data:, ...) is dropped. */
function safeHttpUrl(u) {
	u = (u == null) ? '' : String(u).trim();
	return /^https?:\/\/[^\s"'<>]+$/i.test(u) ? u : null;
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

/* Promise wrapper resolving to the JSON object, or null on transport error (like XHR json==null). */
function rpc(method, params) {
	return Promise.resolve().then(function() {
		return pw.call(method, params || {});
	}).then(function(res) {
		return (res != null && typeof(res) == 'object') ? res : null;
	}).catch(function() {
		return null;
	});
}

function createUpdater() {
	var T = {
		checkUpdate: _('Check update'),
		forceUpdate: _('Force update'),
		retry: _('Retry'),
		noUpdate: _('It is the latest version'),
		updateSuccess: _('Update successful'),
		clickToUpdate: _('Click to update'),
		inProgress: _('Updating...'),
		updateInProgressNotice: _('Updating, are you sure to close?'),
		downloading: _('Downloading...'),
		unpacking: _('Unpacking...'),
		moving: _('Moving...'),
		installing: _('Installing...'),
		installingNotice: _('Do not refresh or switch pages during installation.'),
		updateFailed: _('Update failed'),
		unknownError: _('Unknown error')
	};

	var st = {
		appInfoList: {},
		inProgressCount: 0,
		componentUpdates: 0,
		luciUpdating: false,
		buttons: [],		/* every check/force button */
		checkBtn: {},		/* app -> check button */
		forceBtn: {},		/* app -> force button */
		detail: {}		/* app -> detail span */
	};

	function beforeUnload(e) {
		e.returnValue = T.updateInProgressNotice;
		return T.updateInProgressNotice;
	}

	function syncUpdateButtons() {
		for (var i = 0; i < st.buttons.length; i++) {
			var btn = st.buttons[i];
			btn.disabled = !!btn.updateDisabled || st.luciUpdating ||
				(btn.getAttribute('data-update-app') === APPNAME && st.componentUpdates > 0);
		}
	}

	function setButtonDisabled(btn, disabled) {
		btn.updateDisabled = disabled;
		syncUpdateButtons();
	}

	function setText(btn, text) {
		btn.textContent = text;
		btn.setAttribute('title', text);
	}

	function addPageNotice() {
		if (st.inProgressCount === 0)
			window.addEventListener('beforeunload', beforeUnload);
		st.inProgressCount++;
	}

	function removePageNotice(app) {
		if (app === APPNAME)
			st.luciUpdating = false;
		else if (app)
			st.componentUpdates--;
		st.inProgressCount--;
		syncUpdateButtons();
		if (st.inProgressCount === 0)
			window.removeEventListener('beforeunload', beforeUnload);
	}

	function onUpdateSuccess(btn) {
		if (btn) {
			setText(btn, T.updateSuccess);
			setButtonDisabled(btn, true);
		}
		if (st.inProgressCount === 0) {
			window.setTimeout(function() {
				if (st.inProgressCount === 0 && !st.luciUpdating)
					window.location.reload();
			}, 1000);
		}
	}

	function onRequestError(btn, errorMessage, checking) {
		setButtonDisabled(btn, false);
		setText(btn, T.retry);
		var app = btn.getAttribute('data-update-app');
		var detailEl = st.detail[app];
		if (app === APPNAME && !checking && !errorMessage)
			errorMessage = T.unknownError;
		if (errorMessage && detailEl)
			detailEl.textContent = errorMessage;
	}

	function onBtnClick(btn, app) {
		if (st.appInfoList[app] === undefined)
			checkUpdate(btn, app);
		else
			doUpdate(btn, app);
	}

	function checkUpdate(btn, app) {
		setButtonDisabled(btn, true);
		setText(btn, T.inProgress);
		addPageNotice();

		var detailEl = st.detail[app];
		if (detailEl)
			detailEl.textContent = '';

		rpc('com_check', { com: app, arch: '' }).then(function(json) {
			removePageNotice();
			if (!json || json.code) {
				st.appInfoList[app] = undefined;
				onRequestError(btn, json && json.error, true);
				return;
			}
			st.appInfoList[app] = json;
			if (json.has_update) {
				setButtonDisabled(btn, false);
				setText(btn, T.clickToUpdate);
				if (detailEl) {
					dom.content(detailEl, '');
					if (json.remote_version) {
						/* both values come from the remote release API: text node only, http(s) links only */
						var em = E('em', { 'style': 'color:red;' }, [ String(json.remote_version) ]);
						var link = safeHttpUrl(json.html_url);
						if (link)
							em = E('a', { 'href': link, 'target': '_blank', 'rel': 'noreferrer noopener' }, [ em ]);
						detailEl.appendChild(em);
					}
				}
			}
			else {
				setButtonDisabled(btn, true);
				setText(btn, T.noUpdate);
				var forceBtn = st.forceBtn[app];
				if (forceBtn)
					forceBtn.style.display = 'inline';
			}
		});
	}

	function doUpdate(btn, app) {
		if (st.luciUpdating || (app === APPNAME && st.componentUpdates > 0))
			return;
		var appInfo = st.appInfoList[app];
		if (!appInfo || !appInfo.data) {
			onRequestError(btn, T.updateFailed);
			return;
		}
		var downloadList = [ appInfo.data ];
		if (app === APPNAME && Array.isArray(appInfo.i18n))
			downloadList = downloadList.concat(appInfo.i18n);
		for (var i = 0; i < downloadList.length; i++) {
			if (!downloadList[i] || !downloadList[i].browser_download_url) {
				onRequestError(btn, T.updateFailed);
				return;
			}
		}

		if (app === APPNAME)
			st.luciUpdating = true;
		else
			st.componentUpdates++;
		setButtonDisabled(btn, true);
		setText(btn, T.downloading);
		addPageNotice();

		var downloadId = Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
		var totalSize = 0;
		for (var j = 0; j < downloadList.length; j++)
			totalSize += Number(downloadList[j].size) || 0;
		if (!isFinite(totalSize) || totalSize <= 0)
			totalSize = 0;

		var progressActive = true;
		var progressPending = false;
		var progressTimer = null;

		function stopDownloadProgress() {
			progressActive = false;
			if (progressTimer) {
				window.clearInterval(progressTimer);
				progressTimer = null;
			}
		}

		function updateDownloadProgress() {
			if (!progressActive || progressPending || totalSize <= 0)
				return;
			progressPending = true;
			rpc('com_update', {
				com: app,
				task: 'progress',
				id: downloadId,
				total_size: String(totalSize)
			}).then(function(json) {
				progressPending = false;
				if (progressActive && json && !json.code && typeof(json.percent) === 'number')
					setText(btn, T.downloading + ' ' + json.percent + '%');
			});
		}

		if (totalSize > 0) {
			updateDownloadProgress();
			progressTimer = window.setInterval(updateDownloadProgress, 1000);
		}

		function download(part) {
			var asset = downloadList[part - 1];
			rpc('com_update', {
				com: app,
				url: asset.browser_download_url,
				size: String((app === APPNAME && part === 1 ? totalSize : asset.size) / 1024),
				id: downloadId,
				part: String(part)
			}).then(function(json) {
				if (json && !json.code && app === APPNAME && part < downloadList.length) {
					download(part + 1);
					return;
				}
				stopDownloadProgress();
				if (!json || json.code) {
					removePageNotice(app);
					onRequestError(btn, json && (json.error || T.updateFailed));
				}
				else if (app === APPNAME) {
					installLuci(btn, downloadId);
				}
				else if (json.zip) {
					setText(btn, T.unpacking);
					rpc('com_update', {
						com: app,
						task: 'extract',
						file: json.file,
						subfix: appInfo.type || ''
					}).then(function(json2) {
						if (!json2 || json2.code) {
							removePageNotice(app);
							onRequestError(btn, json2 && json2.error);
						}
						else {
							move(btn, app, json2.file);
						}
					});
				}
				else {
					move(btn, app, json.file);
				}
			});
		}

		download(1);
	}

	function move(btn, app, file) {
		setText(btn, T.moving);
		rpc('com_update', { com: app, task: 'move', file: file }).then(function(json) {
			removePageNotice(app);
			if (!json || json.code)
				onRequestError(btn, json && json.error);
			else
				onUpdateSuccess(btn);
		});
	}

	function installLuci(btn, id) {
		setText(btn, T.installing);
		var detailEl = st.detail[APPNAME];
		if (detailEl)
			detailEl.textContent = T.installingNotice;

		var pending = false, finished = false, timer = null;

		function finishInstall(code) {
			if (finished)
				return;
			finished = true;
			window.clearInterval(timer);
			removePageNotice(APPNAME);
			if (code) {
				onRequestError(btn, T.updateFailed);
			}
			else {
				window.removeEventListener('beforeunload', beforeUnload);
				window.location.reload();
			}
		}

		/* Read the tiny result file even if an rpcd restart invalidates the session. */
		timer = window.setInterval(function() {
			if (pending)
				return;
			pending = true;
			var xhr = new XMLHttpRequest();
			xhr.open('GET', L.resource(APPNAME + '-update/' + id + '.json') + '?_=' + Date.now(), true);
			xhr.timeout = 5000;
			xhr.onerror = xhr.ontimeout = function() { pending = false; };
			xhr.onload = function() {
				pending = false;
				if (finished)
					return;
				var json;
				try { json = JSON.parse(xhr.responseText); } catch (e) { return; }
				if (!json || typeof(json.code) !== 'number')
					return;
				finishInstall(json.code);
			};
			xhr.send();
		}, 1000);

		var info = st.appInfoList[APPNAME] || {};
		Promise.resolve().then(function() {
			return pw.call('com_update', {
				com: APPNAME,
				task: 'install',
				id: id,
				force: info.has_update ? '0' : '1',
				languages: info.languages || ''
			});
		}).then(function(json) {
			if (finished)
				return;
			if (!json || typeof(json.code) !== 'number' || json.code)
				finishInstall(1);
		}).catch(function() {
			finishInstall(1);
		});
	}

	function makeRow(app, title, versionEl) {
		var checkBtn = E('button', {
			'class': 'btn cbi-button cbi-button-apply',
			'type': 'button',
			'data-update-app': app,
			'id': (app === APPNAME ? APPNAME : '_' + app) + '-check_btn'
		}, T.checkUpdate);
		var forceBtn = E('button', {
			'class': 'btn cbi-button cbi-button-apply',
			'type': 'button',
			'data-update-app': app,
			'id': '_' + app + '-force_btn',
			'style': 'display:none'
		}, T.forceUpdate);
		var detail = E('span', { 'class': 'app-update-detail', 'id': checkBtn.id + '-detail' });

		checkBtn.addEventListener('click', function(ev) { ev.preventDefault(); onBtnClick(checkBtn, app); });
		forceBtn.addEventListener('click', function(ev) { ev.preventDefault(); doUpdate(forceBtn, app); });

		st.buttons.push(checkBtn, forceBtn);
		st.checkBtn[app] = checkBtn;
		st.forceBtn[app] = forceBtn;
		st.detail[app] = detail;

		return E('div', { 'class': 'cbi-value pw-app-row' }, [
			E('label', { 'class': 'cbi-value-title' }, [
				title,
				E('span', { 'class': 'app-version-sub' }, versionEl)
			]),
			E('div', { 'class': 'cbi-value-field' }, [
				E('div', { 'class': 'app-update-actions' }, [ checkBtn, forceBtn, detail ])
			])
		]);
	}

	function fillVersion(el, com) {
		el.textContent = _('Collecting data...');
		rpc('com_version', { com: com }).then(function(result) {
			if (result && result.code == 1) {
				var data = result.data;
				el.textContent = (data != null && data !== '') ? String(data) : _('Null');
			}
			else {
				el.textContent = _('Null');
			}
		});
	}

	return {
		render: function() {
			var rows = [];
			var selfVer = E('span', { 'class': 'com_version', 'key': APPNAME });
			rows.push(makeRow(APPNAME, 'Passwall2 ' + _('Version'), selfVer));
			fillVersion(selfVer, APPNAME);

			COM_ORDER.forEach(function(k) {
				var verEl = E('span', { 'class': 'com_version', 'key': k }, _('Null'));
				rows.push(makeRow(k, COM[k].name + ' ' + _('Version'), verEl));
				fillVersion(verEl, k);
			});

			return E('div', { 'id': 'app_version', 'class': 'pw-app-versions' }, [
				E('style', {}, [
					'#app_version > .cbi-value{display:flex;flex-wrap:wrap;align-items:center;margin-top:0;margin-bottom:0;padding-top:.25rem;padding-bottom:.25rem}',
					'#app_version > .cbi-value > .cbi-value-title{padding-top:0;padding-bottom:0;line-height:1.2}',
					'#app_version .app-version-sub{display:block;font-size:.85em;font-weight:normal;opacity:.7}',
					'#app_version .app-update-actions{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem}',
					'#app_version .app-update-actions > span{min-width:0;overflow-wrap:anywhere}'
				].join('\n'))
			].concat(rows));
		}
	};
}

return view.extend({
	load: function() {
		if (typeof(pw.loadCSS) == 'function') {
			try { pw.loadCSS(); } catch (e) {}
		}
		return uci.load('passwall2');
	},

	render: function() {
		var sections = uci.sections('passwall2', 'global_app');
		var sid = sections.length ? sections[0]['.name'] : uci.add('passwall2', 'global_app');

		var m, s, o;

		m = new form.Map('passwall2');

		/* upstream section title "App Update" is shown as the page header */
		s = m.section(form.NamedSection, sid, 'global_app');
		s.anonymous = true;
		s.addremove = false;

		var updater = createUpdater();
		var versionBlock = null;
		o = s.option(form.DummyValue, '_app_version');
		o.render = function(option_index, section_id) {
			/*
			 * Full-width block, like the upstream template appended inside the section.
			 * Built once and re-used when the map re-renders (save), so a running
			 * update keeps its state and buttons.
			 */
			if (!versionBlock)
				versionBlock = E('div', { 'class': 'cbi-value pw-app-version-block', 'style': 'display:block' }, updater.render());
			return Promise.resolve(versionBlock);
		};
		o.write = function() {};
		o.remove = function() {};

		o = s.option(form.ListValue, 'gh_proxy_url', _('GitHub Proxy'), _('Use GitHub instead of proxy nodes for component updates.'));
		o.default = '';
		o.value('', _('Close(Not use)'));
		o.value('https://gh-proxy.org/', 'gh-proxy.org');
		o.value('https://ghproxy.cc/', 'ghproxy.cc');
		o.value('https://mirror.ghproxy.com/', 'ghproxy.com');
		o.value('https://ghfast.top/', 'ghfast.top');

		COM_ORDER.forEach(function(k) {
			var v = COM[k];
			o = s.option(form.Value, k.replace(/-/g, '_') + '_file', _('%s App Path').format(v.name));
			o.default = v.default_path || ('/usr/bin/' + k);
			o.placeholder = o.default;
			/* upstream: remove() writes the default -> the path can never be empty in UCI */
			o.remove = function(section_id) {
				return this.map.data.set('passwall2', section_id, this.option, this.default);
			};
		});

		o = s.option(form.DummyValue, 'tips', ' ');
		o.renderWidget = function() {
			return E('font', { 'color': 'red' }, _('if you want to run from memory, change the path, /tmp beginning then save the application and update it manually.'));
		};
		o.write = function() {};
		o.remove = function() {};

		return m.render().then(function(mapEl) {
			return E('div', { 'class': 'pw-root' }, [
				header(_('App Update')),
				mapEl
			]);
		});
	}
});
