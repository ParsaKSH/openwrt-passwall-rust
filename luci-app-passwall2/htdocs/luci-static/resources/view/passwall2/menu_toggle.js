'use strict';
'require view';
'require passwall2.pw as pw';

/*
 * Upstream controller endpoints admin/services/passwall2/{show,hide} (show_menu / hide_menu):
 * the FAQ on the Basic Settings page advertises them as "Browser access" URLs, so a user who
 * hid the menu entry can bring it back by opening .../passwall2/show.
 * show: delete @global[0].hide_from_luci, then go to the PassWall 2 main page.
 * hide: set hide_from_luci=1, then go to Status -> Overview (asks first, since this is a GET URL).
 */
return view.extend({
	load() {
		const p = L.env.requestpath || [];
		return p[p.length - 1] === 'hide' ? 'hide' : 'show';
	},

	run(act) {
		return pw.call(act, {}).catch(() => null).then(() => {
			window.location.href = (act === 'hide') ? L.url('admin/status/overview') : pw.url();
		});
	},

	render(act) {
		if (act === 'hide') {
			pw.confirm(_('Hide in main menu:'), _('Are you sure to hide?')).then((ok) => {
				if (ok)
					return this.run(act);
				window.location.href = pw.url();
			});
		}
		else {
			this.run(act);
		}
		return E('div', { 'class': 'spinning' }, [ _('Loading view…') ]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
