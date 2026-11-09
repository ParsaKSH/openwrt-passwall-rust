'use strict';
'require view';
'require uci';
'require fs';
'require ui';
'require passwall2.pw as pw';

/*
 * Geo View page (upstream: model/cbi/passwall2/client/geoview.lua + view/passwall2/rule/geoview.htm).
 * Spec 08 §10, 10 §2.15, 07 geo_view.
 */

const CFG = 'passwall2';

/* (v2ray_location_asset or "/usr/share/v2ray/"):match("^(.*)/") -> everything before the last "/" */
function geoDir() {
	const v = uci.get_first(CFG, 'global_rules', 'v2ray_location_asset');
	const asset = (v != null) ? String(v) : '/usr/share/v2ray/';
	const idx = asset.lastIndexOf('/');
	return idx >= 0 ? asset.substring(0, idx) : null;
}

function fileExists(path) {
	return L.resolveDefault(fs.stat(path), null).then((st) => !!st);
}

return view.extend({
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function () {
		return uci.load(CFG).then(() => {
			const dir = geoDir();
			if (dir == null)
				return [false, false];
			return Promise.all([
				fileExists(dir + '/geosite.dat'),
				fileExists(dir + '/geoip.dat'),
				L.resolveDefault(pw.loadCSS(), null)
			]);
		});
	},

	render: function (data) {
		const header = pw.pageHeader(_('Geo View'), null, []);

		if (!(data[0] && data[1]))
			return E('div', { 'class': 'pw-root' }, [header]);

		const textarea = E('textarea', {
			'id': 'geoview_textarea',
			'class': 'cbi-input-textarea',
			'style': 'width:100%;margin-top:10px;font-family:monospace',
			'rows': 25,
			'wrap': 'off',
			'readonly': 'readonly'
		});

		const lookupInput = E('input', {
			'type': 'text', 'class': 'cbi-input-text', 'id': 'geoview.lookup',
			'inputmode': 'search', 'enterkeyhint': 'search', 'style': 'flex:1;min-width:0'
		});
		const extractInput = E('input', {
			'type': 'text', 'class': 'cbi-input-text', 'id': 'geoview.extract',
			'inputmode': 'search', 'enterkeyhint': 'search', 'placeholder': 'geoip:cn / geosite:gfw', 'style': 'flex:1;min-width:0'
		});

		let lookupBtn, extractBtn;
		const doGeoview = (btn, action, value) => {
			value = String(value || '').trim();
			if (!value) {
				pw.notify(_('Please enter query content!'), 'warn');
				return;
			}
			lookupBtn.disabled = true;
			extractBtn.disabled = true;
			btn.textContent = _('Querying');
			textarea.value = '';
			return pw.call('geo_view', { action: action, value: value }).then((r) => {
				textarea.value = (r && r.result != null) ? String(r.result) : '';
			}, (e) => {
				textarea.value = e && e.message ? e.message : _('Error');
			}).then(() => {
				lookupBtn.disabled = false;
				extractBtn.disabled = false;
				btn.textContent = _('Query');
			});
		};

		lookupBtn = E('button', {
			'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'id': 'lookup-view_btn',
			'click': () => doGeoview(lookupBtn, 'lookup', lookupInput.value)
		}, [_('Query')]);
		extractBtn = E('button', {
			'class': 'btn cbi-button cbi-button-apply', 'type': 'button', 'id': 'extract-view_btn',
			'click': () => doGeoview(extractBtn, 'extract', extractInput.value)
		}, [_('Query')]);

		[[lookupInput, lookupBtn], [extractInput, extractBtn]].forEach((p) => {
			p[0].addEventListener('keydown', (e) => {
				if (e.key === 'Enter' || e.keyCode === 13) {
					e.stopPropagation();
					e.preventDefault();
					p[0].blur();
					p[1].click();
				}
			});
		});

		const row = (id, title, input, btn, descr) => E('div', { 'class': 'cbi-value', 'id': id }, [
			E('label', { 'class': 'cbi-value-title', 'for': input.id }, [title]),
			E('div', { 'class': 'cbi-value-field' }, [
				E('div', { 'class': 'geoview-search', 'style': 'display:flex;gap:.4em;align-items:center' }, [input, btn]),
				E('div', { 'class': 'cbi-value-description' }, [descr])
			])
		]);

		return E('div', { 'class': 'pw-root' }, [
			header,
			pw.card(_('Tips:'),
				E('ul', { 'style': 'margin:0' }, [
					E('li', { 'class': 'faq-item' }, ['1. ', _('By entering a domain or IP, you can query the Geo rule list they belong to.')]),
					E('li', { 'class': 'faq-item' }, ['2. ', _('By entering a GeoIP or Geosite, you can extract the domains/IPs they contain.')]),
					E('li', { 'class': 'faq-item' }, ['3. ', _('Use the GeoIP/Geosite query function to verify if the entered Geo rules are correct.')])
				])),
			pw.card(_('Geo View'),
				row('cbi-passwall2-geoview-lookup', _('Domain/IP Query'), lookupInput, lookupBtn,
					_('Enter a domain or IP to query the Geo rule list they belong to.')),
				row('cbi-passwall2-geoview-extract', _('GeoIP/Geosite Query'), extractInput, extractBtn,
					_('Enter a GeoIP or Geosite to extract the domains/IPs they contain. Format: geoip:cn or geosite:gfw')),
				E('div', { 'class': 'cbi-value' }, [textarea]))
		]);
	}
});
