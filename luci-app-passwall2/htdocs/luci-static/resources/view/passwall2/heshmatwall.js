'use strict';
'require view';
'require form';
'require uci';
'require ui';
'require dom';
'require passwall2.pw as pw';
'require passwall2.sharelink as sl';

/*
 * HeshmatWall: settings of the phone web app (PWA) at /heshmatwall/ (backend:
 * passwall2/src/heshmat.rs). The app has its own login, separate from LuCI: a username, a
 * password (stored only as a PBKDF2 hash, set through the heshmatwall_set_password rpc) and
 * a link key that is part of the link shown here.
 */

const CONF = 'passwall2';
const SEC = 'heshmatwall';

function appLink(key) {
	return '%s//%s/heshmatwall/#k=%s'.format(window.location.protocol, window.location.host, key);
}

function copyText(text) {
	if (navigator.clipboard && window.isSecureContext)
		return navigator.clipboard.writeText(text).then(() => true, () => false);
	const ta = E('textarea', { 'style': 'position:fixed;top:0;left:0;opacity:0' }, [ text ]);
	document.body.appendChild(ta);
	ta.select();
	let ok = false;
	try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
	document.body.removeChild(ta);
	return Promise.resolve(ok);
}

return view.extend({
	load() {
		return Promise.all([ uci.load(CONF), pw.call('heshmatwall_info') ]);
	},

	passwordDialog(info) {
		const user = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'value': info.username || 'admin', 'autocomplete': 'username', 'style': 'width:100%' });
		const pw1 = E('input', { 'type': 'password', 'class': 'cbi-input-password', 'autocomplete': 'new-password', 'style': 'width:100%' });
		const pw2 = E('input', { 'type': 'password', 'class': 'cbi-input-password', 'autocomplete': 'new-password', 'style': 'width:100%' });
		const msg = E('div', { 'class': 'pw-text-err', 'style': 'min-height:1.2em;margin-top:.5em' });
		const row = (label, input) => E('div', { 'style': 'margin-bottom:.6em' }, [ E('label', { 'style': 'display:block;margin-bottom:.2em' }, [ label ]), input ]);
		ui.showModal(_('Set HeshmatWall password'), [
			E('div', { 'class': 'pw-root pw-modal' }, [
				row(_('Username'), user),
				row(_('Password'), pw1),
				row(_('Confirm Password'), pw2),
				E('p', { 'class': 'cbi-value-description' }, [ _('At least 8 characters. Changing the password signs out every device.') ]),
				msg
			]),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn cbi-button', 'click': ui.hideModal }, [ _('Cancel') ]), ' ',
				E('button', { 'class': 'btn cbi-button-action important', 'click': () => {
					if (pw1.value !== pw2.value) { msg.textContent = _('The passwords do not match.'); return; }
					if (pw1.value.length < 8) { msg.textContent = _('At least 8 characters.'); return; }
					return pw.call('heshmatwall_set_password', { username: user.value.trim(), password: pw1.value }).then((r) => {
						if (!r || r.code !== 1) { msg.textContent = (r && r.msg) || _('Error'); return; }
						ui.hideModal();
						window.location.reload();
					});
				} }, [ _('Save') ])
			])
		]);
		window.setTimeout(() => pw1.focus(), 50);
	},

	renderAccess(info) {
		const enabled = uci.get(CONF, SEC, 'enabled') === '1';
		const status = E('div', { 'class': 'pw-info-strip', 'style': 'margin-top:0' }, [
			E('span', {}, [ _('Password') + ': ', pw.badge(info.has_password ? _('Set') : _('Not set'), info.has_password ? 'ok' : 'err') ]),
			E('span', {}, [ _('Signed-in devices') + ': ', E('b', {}, [ String(info.sessions || 0) ]) ])
		]);
		const actions = E('div', { 'style': 'display:flex;flex-wrap:wrap;gap:.5em;margin-top:.8em' }, [
			E('button', { 'class': 'btn cbi-button cbi-button-apply', 'click': () => this.passwordDialog(info) }, [ info.has_password ? _('Change password') : _('Set password') ]),
			E('button', { 'class': 'btn cbi-button', 'disabled': info.has_password ? null : '', 'click': () =>
				pw.confirm(_('New link'), _('The current link stops working and every device is signed out. Continue?')).then((ok) => {
					if (ok) return pw.call('heshmatwall_regen_link').then(() => window.location.reload());
				}) }, [ _('New link') ]),
			E('button', { 'class': 'btn cbi-button cbi-button-remove', 'disabled': info.sessions ? null : '', 'click': () =>
				pw.call('heshmatwall_logout_all').then(() => window.location.reload()) }, [ _('Sign out all devices') ])
		]);

		const linkBox = E('div', { 'style': 'margin-top:1em' });
		if (!info.has_password || !info.link_key) {
			linkBox.appendChild(E('p', { 'class': 'pw-text-err' }, [ _('Set a password first; the link is created with it.') ]));
		}
		else {
			const link = appLink(info.link_key);
			const status2 = E('span', { 'class': 'pw-text-ok', 'style': 'margin-left:.5em' });
			const qr = E('div', { 'style': 'margin-top:.8em' });
			try { qr.innerHTML = sl.qrSVG(link, 200); } catch (e) {}
			linkBox.appendChild(E('div', {}, [
				E('label', { 'style': 'display:block;font-weight:600;margin-bottom:.3em' }, [ _('App link') ]),
				E('div', { 'style': 'display:flex;flex-wrap:wrap;gap:.5em;align-items:center' }, [
					E('code', { 'style': 'word-break:break-all;flex:1 1 20em' }, [ link ]),
					E('button', { 'class': 'btn cbi-button', 'click': () => copyText(link).then((ok) => { status2.textContent = ok ? _('Copied') : _('Copy failed'); }) }, [ _('Copy') ]),
					E('a', { 'class': 'btn cbi-button', 'href': link, 'target': '_blank', 'rel': 'noopener' }, [ _('Open') ]),
					status2
				]),
				enabled ? '' : E('p', { 'class': 'pw-text-err' }, [ _('The app is disabled: enable it below and Save & Apply.') ]),
				qr,
				E('p', { 'class': 'cbi-value-description' }, [
					_('Open the link on your phone (same network as the router), sign in with the username and password, then use "Add to Home screen" / "Install app". The link contains a secret key: share it only with people who should manage the router.')
				])
			]));
		}
		return pw.card(_('Access'), status, actions, linkBox);
	},

	render(data) {
		pw.loadCSS();
		const info = data[1] || {};
		if (!uci.get(CONF, SEC))
			uci.add(CONF, SEC, SEC);

		const m = new form.Map(CONF);
		const s = m.section(form.NamedSection, SEC, SEC, _('Settings'));
		s.anonymous = true;
		s.addremove = false;

		let o = s.option(form.Flag, 'enabled', _('Enable'), _('Serve the HeshmatWall app at /heshmatwall/ on this router.'));
		o.rmempty = false;

		o = s.option(form.ListValue, 'session_hours', _('Stay signed in for'));
		[ [ '1', _('1 hour') ], [ '24', _('1 day') ], [ '168', _('7 days') ], [ '720', _('30 days') ] ].forEach((v) => o.value(v[0], v[1]));
		o.default = '168';

		return m.render().then((form_) => E('div', { 'class': 'pw-root' }, [
			pw.pageHeader('HeshmatWall', _('A phone app for PassWall 2 with its own sign-in, separate from LuCI.')),
			this.renderAccess(info),
			form_
		]));
	}
});
