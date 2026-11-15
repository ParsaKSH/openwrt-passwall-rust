/*
 * HeshmatWall: PassWall 2 from your phone. A small single-page app in the style of the
 * v2rayNG Android client; it talks to the router through /cgi-bin/heshmatwall
 * (passwall2/src/heshmat.rs) with its own sign-in, separate from LuCI.
 */
'use strict';
(() => {

const API = '/cgi-bin/heshmatwall';
const REPO = 'https://github.com/ParsaKSH/openwrt-passwall-rust';
const LUCI_NODE = '/cgi-bin/luci/admin/services/passwall2/node_config/';

/* ------------------------------------------------------------------ storage */

const LS = {
	get(k) { try { return localStorage.getItem('hw_' + k); } catch (e) { return null; } },
	set(k, v) { try { if (v == null) localStorage.removeItem('hw_' + k); else localStorage.setItem('hw_' + k, v); } catch (e) {} }
};

/* ------------------------------------------------------------------ i18n */

const STR = {
	en: {
		app: 'HeshmatWall', config: 'Config',
		not_connected: 'Not connected', connected: 'Connected. Tap to check connection.',
		testing: 'Testing…', testing_count: 'Testing %1 configs…', conn_ok: 'Connection succeeded in %1 ms',
		conn_fail: 'Internet unavailable', starting: 'Starting…', stopping: 'Stopping…', restarting: 'Restarting…',
		start: 'Start service', stop: 'Stop service',
		subscriptions: 'Subscriptions', settings: 'Settings', logcat: 'Logcat', check_update: 'Check for update',
		about: 'About', open_luci: 'Open LuCI', sign_out: 'Sign out', menu: 'Menu', back: 'Back',
		search: 'Search', add: 'Add', more: 'More options',
		import_clipboard: 'Import from Clipboard', import_file: 'Import from a local file',
		paste_hint: 'Paste share links (vless://, vmess://, ss://, trojan://, hysteria2://, …), one per line, or a subscription content.',
		restart: 'Restart service', delete_configs: 'Delete configs', sort: 'Sort by test results',
		tcping: 'Test TCP delays (TCPing)', real: 'Test real delays', update_sub: 'Update subscription',
		details: 'Details', edit: 'Edit', delete: 'Delete',
		no_configs: 'No configs yet. Tap + to import share links.',
		delete_confirm: 'Delete %1 config(s)?', delete_one: 'Delete "%1"?',
		cancel: 'Cancel', ok: 'OK', save: 'Save', close: 'Close',
		imported: 'Imported %1 config(s)', import_none: 'No valid share links found',
		selected: 'Selected: %1', need_node: 'Select a config first', deleted: 'Deleted',
		sign_in: 'Sign in', username: 'Username', password: 'Password', login_sub: 'Sign in to manage PassWall 2',
		bad_credentials: 'Wrong username or password',
		bad_link: 'This link is no longer valid. Get the current one from LuCI → Services → PassWall 2 → HeshmatWall.',
		no_link: 'Open the app with the link from LuCI → Services → PassWall 2 → HeshmatWall.',
		locked: 'Too many attempts. Try again in %1 min.', disabled: 'HeshmatWall is disabled in LuCI.',
		no_password: 'Set a password in LuCI → Services → PassWall 2 → HeshmatWall first.',
		network_error: 'Cannot reach the router', session_expired: 'Signed out. Please sign in again.',
		cat_proxy: 'Proxy', cat_dns: 'DNS', cat_app: 'App',
		proxy_mode: 'Proxy mode', mode_tproxy: 'Transparent proxy (all LAN traffic)', mode_socks: 'SOCKS/HTTP proxy only',
		socks_port: 'SOCKS port', listen: 'Listen on', listen_all: 'All interfaces (LAN devices)', listen_local: 'Router only',
		http_port: 'HTTP port', off: 'Off', localhost_proxy: 'Proxy the router itself', client_proxy: 'Proxy LAN devices',
		remote_dns_proto: 'Remote DNS protocol', remote_dns: 'Remote DNS server', doh: 'DoH URL',
		language: 'Language', system: 'System', theme: 'Theme', light: 'Light', dark: 'Dark',
		saved_restart: 'Saved. Restarting the service…', saved: 'Saved',
		add_sub: 'Add subscription', remark: 'Remarks', url: 'URL', update_all: 'Update all',
		updating: 'Updating in the background…', no_subs: 'No subscriptions',
		duplicate: 'A subscription with this name or URL exists', bad_url: 'Invalid URL', bad_remark: 'Invalid remarks',
		clear: 'Clear', refresh: 'Refresh', log_empty: '(empty)',
		version: 'Version %1', source: 'Source code', about_text: 'Phone app for PassWall 2 (Rust) on OpenWrt.',
		type: 'Type', core: 'Core', address: 'Address', port: 'Port', group: 'Group', default_group: 'Default',
		real_delay: 'Real delay', delay: 'Delay', edit_luci: 'Editing opens the node in LuCI (LuCI sign-in may be needed).',
		error: 'Error: %1', bad_value: 'Invalid value', install: 'Install app'
	},
	fa: {
		app: 'HeshmatWall', config: 'کانفیگ',
		not_connected: 'متصل نیست', connected: 'متصل است. برای بررسی اتصال ضربه بزنید.',
		testing: 'در حال بررسی…', testing_count: 'در حال تست %1 کانفیگ…', conn_ok: 'اتصال موفق در %1 میلی‌ثانیه',
		conn_fail: 'اینترنت در دسترس نیست', starting: 'در حال روشن شدن…', stopping: 'در حال خاموش شدن…', restarting: 'در حال راه‌اندازی مجدد…',
		start: 'روشن کردن سرویس', stop: 'خاموش کردن سرویس',
		subscriptions: 'اشتراک‌ها', settings: 'تنظیمات', logcat: 'لاگ', check_update: 'بررسی به‌روزرسانی',
		about: 'درباره', open_luci: 'باز کردن LuCI', sign_out: 'خروج', menu: 'منو', back: 'بازگشت',
		search: 'جستجو', add: 'افزودن', more: 'گزینه‌های بیشتر',
		import_clipboard: 'وارد کردن از کلیپ‌بورد', import_file: 'وارد کردن از فایل',
		paste_hint: 'لینک‌های اشتراک‌گذاری (vless://، vmess://، ss://، trojan://، hysteria2:// و …) را هر کدام در یک خط، یا محتوای یک اشتراک را بچسبانید.',
		restart: 'راه‌اندازی مجدد سرویس', delete_configs: 'حذف کانفیگ‌ها', sort: 'مرتب‌سازی بر اساس نتیجه تست',
		tcping: 'تست تأخیر TCP (TCPing)', real: 'تست تأخیر واقعی', update_sub: 'به‌روزرسانی اشتراک',
		details: 'جزئیات', edit: 'ویرایش', delete: 'حذف',
		no_configs: 'هنوز کانفیگی نیست. برای وارد کردن لینک‌ها روی + بزنید.',
		delete_confirm: '%1 کانفیگ حذف شود؟', delete_one: '«%1» حذف شود؟',
		cancel: 'لغو', ok: 'تأیید', save: 'ذخیره', close: 'بستن',
		imported: '%1 کانفیگ وارد شد', import_none: 'لینک معتبری پیدا نشد',
		selected: 'انتخاب شد: %1', need_node: 'اول یک کانفیگ انتخاب کنید', deleted: 'حذف شد',
		sign_in: 'ورود', username: 'نام کاربری', password: 'رمز عبور', login_sub: 'برای مدیریت PassWall 2 وارد شوید',
		bad_credentials: 'نام کاربری یا رمز عبور اشتباه است',
		bad_link: 'این لینک دیگر معتبر نیست. لینک فعلی را از LuCI ← Services ← PassWall 2 ← HeshmatWall بگیرید.',
		no_link: 'برنامه را با لینکی که در LuCI ← Services ← PassWall 2 ← HeshmatWall هست باز کنید.',
		locked: 'تلاش‌های زیادی انجام شد. %1 دقیقه دیگر دوباره امتحان کنید.', disabled: 'HeshmatWall در LuCI غیرفعال است.',
		no_password: 'اول در LuCI ← Services ← PassWall 2 ← HeshmatWall رمز عبور بگذارید.',
		network_error: 'دسترسی به روتر ممکن نیست', session_expired: 'از حساب خارج شدید. دوباره وارد شوید.',
		cat_proxy: 'پروکسی', cat_dns: 'DNS', cat_app: 'برنامه',
		proxy_mode: 'حالت پروکسی', mode_tproxy: 'پروکسی شفاف (کل ترافیک شبکه)', mode_socks: 'فقط پروکسی SOCKS/HTTP',
		socks_port: 'پورت SOCKS', listen: 'گوش دادن روی', listen_all: 'همه‌ی رابط‌ها (دستگاه‌های شبکه)', listen_local: 'فقط خود روتر',
		http_port: 'پورت HTTP', off: 'خاموش', localhost_proxy: 'پروکسی برای خود روتر', client_proxy: 'پروکسی برای دستگاه‌های شبکه',
		remote_dns_proto: 'پروتکل DNS راه دور', remote_dns: 'سرور DNS راه دور', doh: 'آدرس DoH',
		language: 'زبان', system: 'پیش‌فرض سیستم', theme: 'پوسته', light: 'روشن', dark: 'تیره',
		saved_restart: 'ذخیره شد. سرویس در حال راه‌اندازی مجدد است…', saved: 'ذخیره شد',
		add_sub: 'افزودن اشتراک', remark: 'نام', url: 'آدرس', update_all: 'به‌روزرسانی همه',
		updating: 'به‌روزرسانی در پس‌زمینه انجام می‌شود…', no_subs: 'اشتراکی نیست',
		duplicate: 'اشتراکی با همین نام یا آدرس وجود دارد', bad_url: 'آدرس نامعتبر', bad_remark: 'نام نامعتبر',
		clear: 'پاک کردن', refresh: 'تازه‌سازی', log_empty: '(خالی)',
		version: 'نسخه %1', source: 'کد منبع', about_text: 'برنامه‌ی موبایل برای PassWall 2 (Rust) روی OpenWrt.',
		type: 'نوع', core: 'هسته', address: 'آدرس', port: 'پورت', group: 'گروه', default_group: 'پیش‌فرض',
		real_delay: 'تأخیر واقعی', delay: 'تأخیر', edit_luci: 'ویرایش، نود را در LuCI باز می‌کند (ممکن است ورود به LuCI لازم باشد).',
		error: 'خطا: %1', bad_value: 'مقدار نامعتبر', install: 'نصب برنامه'
	}
};

let lang = 'en';
function t(k, ...a) {
	let s = (STR[lang] && STR[lang][k]) || STR.en[k] || k;
	a.forEach((v, i) => { s = s.split('%' + (i + 1)).join(String(v)); });
	return s;
}

function applyLang() {
	const pref = LS.get('lang') || 'system';
	lang = pref === 'system' ? ((navigator.language || '').toLowerCase().startsWith('fa') ? 'fa' : 'en') : pref;
	document.documentElement.lang = lang;
	document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
}

const darkQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
function applyTheme() {
	const pref = LS.get('theme') || 'system';
	const dark = pref === 'dark' || (pref === 'system' && darkQuery && darkQuery.matches);
	document.documentElement.dataset.theme = dark ? 'dark' : 'light';
	document.querySelectorAll('meta[name="theme-color"]').forEach((m) => { m.content = dark ? '#1C1B1F' : '#FFFFFF'; m.removeAttribute('media'); });
}

/* ------------------------------------------------------------------ DOM helpers */

function h(tag, attrs, ...kids) {
	const el = document.createElement(tag);
	for (const [k, v] of Object.entries(attrs || {})) {
		if (v == null || v === false) continue;
		if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
		else if (k === 'class') el.className = v;
		else if (k === 'style') el.style.cssText = v;   /* CSSOM: allowed by the page's CSP */
		else if (k === 'value') el.value = v;
		else el.setAttribute(k, v === true ? '' : v);
	}
	const add = (c) => {
		if (c == null || c === false) return;
		if (Array.isArray(c)) c.forEach(add);
		else el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
	};
	kids.forEach(add);
	return el;
}

/* Material icon paths (24px) */
const ICONS = {
	menu: 'M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z',
	search: 'M15.5 14h-.79l-.28-.27A6.47 6.47 0 0 0 16 9.5 6.5 6.5 0 1 0 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z',
	add: 'M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z',
	more: 'M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z',
	back: 'M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z',
	close: 'M19 6.41 17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.59 17.59 19 19 17.59 13.59 12z',
	share: 'M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11A2.99 2.99 0 0 0 21 5c0-1.66-1.34-3-3-3s-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81A2.99 2.99 0 0 0 3 12a2.99 2.99 0 0 0 5.04 2.19l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92s2.92-1.31 2.92-2.92-1.31-2.92-2.92-2.92z',
	edit: 'M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04a1 1 0 0 0 0-1.41l-2.34-2.34a1 1 0 0 0-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z',
	delete: 'M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z',
	play: 'M8 5v14l11-7z',
	stop: 'M6 6h12v12H6z',
	subs: 'M20 8H4V6h16v2zm-2-6H6v2h12V2zm4 10v8c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2v-8c0-1.1.9-2 2-2h16c1.1 0 2 .9 2 2zm-6 4-6-3.27v6.53L16 16z',
	settings: 'M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.49.49 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.48.48 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96a.49.49 0 0 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1 1 12 8.4a3.6 3.6 0 0 1 0 7.2z',
	log: 'M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z',
	update: 'M17.65 6.35A7.96 7.96 0 0 0 12 4a8 8 0 1 0 7.73 10h-2.08A6 6 0 1 1 12 6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z',
	info: 'M11 7h2v2h-2zm0 4h2v6h-2zm1-9C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z',
	logout: 'M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z',
	open: 'M19 19H5V5h7V3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z',
	tune: 'M3 17v2h6v-2H3zM3 5v2h10V5H3zm10 16v-2h8v-2h-8v-2h-2v6h2zM7 9v2H3v2h4v2h2V9H7zm14 4v-2H11v2h10zm-6-4h2V7h4V5h-4V3h-2v6z',
	dns: 'M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM20 3H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z',
	lang: 'm12.87 15.07-2.54-2.51.03-.03A17.52 17.52 0 0 0 14.07 6H17V4h-7V2H8v2H1v1.99h11.17C11.5 7.92 10.44 9.75 9 11.35 8.07 10.32 7.3 9.19 6.69 8h-2c.73 1.63 1.73 3.17 2.98 4.56l-5.09 5.02L4 19l5-5 3.11 3.11.76-2.04zM18.5 10h-2L12 22h2l1.12-3h4.75L21 22h2l-4.5-12zm-2.62 7 1.62-4.33L19.12 17h-3.24z',
	palette: 'M12 3a9 9 0 0 0 0 18c.83 0 1.5-.67 1.5-1.5 0-.39-.15-.74-.39-1.01-.23-.26-.38-.61-.38-.99 0-.83.67-1.5 1.5-1.5H16c2.76 0 5-2.24 5-5 0-4.42-4.03-8-9-8zm-5.5 9a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm3-4a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm5 0a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3zm3 4a1.5 1.5 0 1 1 0-3 1.5 1.5 0 0 1 0 3z',
	code: 'M9.4 16.6 4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0 4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z',
	inbox: 'M19 3H4.99C3.88 3 3 3.9 3 5l-.01 14c0 1.1.89 2 2 2H19c1.1 0 2-.9 2-2V5a2 2 0 0 0-2-2zm0 12h-4c0 1.66-1.35 3-3 3s-3-1.34-3-3H4.99V5H19v10z',
	port: 'M7.77 6.76 6.23 5.48.82 12l5.41 6.52 1.54-1.28L3.42 12l4.35-5.24zM7 13h2v-2H7v2zm10-2h-2v2h2v-2zm-6 2h2v-2h-2v2zm6.77-7.52-1.54 1.28L20.58 12l-4.35 5.24 1.54 1.28L23.18 12l-5.41-6.52z'
};

function icon(name) {
	const ns = 'http://www.w3.org/2000/svg';
	const svg = document.createElementNS(ns, 'svg');
	svg.setAttribute('viewBox', '0 0 24 24');
	svg.setAttribute('class', 'svg');
	svg.setAttribute('aria-hidden', 'true');
	const p = document.createElementNS(ns, 'path');
	p.setAttribute('d', ICONS[name] || '');
	svg.appendChild(p);
	return svg;
}

function iconBtn(name, label, onclick, cls) {
	return h('button', { 'class': 'icon-btn' + (cls ? ' ' + cls : ''), 'type': 'button', 'title': label, 'aria-label': label, 'onclick': onclick }, icon(name));
}

function toast(msg, kind) {
	document.querySelectorAll('.toast').forEach((x) => x.remove());
	const el = h('div', { 'class': 'toast' + (kind ? ' ' + kind : ''), 'role': 'status' }, msg);
	document.body.appendChild(el);
	setTimeout(() => el.remove(), 2600);
}

/* ------------------------------------------------------------------ dialogs and menus */

function dialog(title, body, actions) {
	return new Promise((resolve) => {
		let wrap;
		const close = (v) => { wrap.remove(); document.removeEventListener('keydown', onKey); resolve(v); };
		const onKey = (e) => { if (e.key === 'Escape') close(null); };
		const btns = (actions || [ { label: t('close'), value: null } ]).map((a) => h('button', {
			'class': 'tbtn' + (a.cls ? ' ' + a.cls : ''), 'type': a.submit ? 'submit' : 'button',
			'onclick': (e) => {
				if (a.submit) return;
				e.preventDefault();
				const v = a.value instanceof Function ? a.value() : a.value;
				if (v !== undefined) close(v);
			}
		}, a.label));
		const submit = (actions || []).find((a) => a.submit);
		const box = h('form', { 'class': 'dialog', 'role': 'dialog', 'aria-modal': 'true', 'onsubmit': (e) => {
			e.preventDefault();
			if (!submit) return;
			const v = submit.value instanceof Function ? submit.value() : submit.value;
			if (v !== undefined) close(v);
		} }, title ? h('h2', {}, title) : null, body, h('div', { 'class': 'actions' }, btns));
		wrap = h('div', { 'class': 'dialog-wrap', 'onclick': (e) => { if (e.target === wrap) close(null); } }, box);
		document.body.appendChild(wrap);
		document.addEventListener('keydown', onKey);
		const first = box.querySelector('input, textarea');
		if (first) setTimeout(() => first.focus(), 30);
	});
}

function confirmDialog(text, okLabel, danger) {
	return dialog(null, h('div', { 'class': 'text' }, text), [
		{ label: t('cancel'), value: false },
		{ label: okLabel || t('ok'), value: true, cls: danger ? 'danger' : '' }
	]).then((v) => v === true);
}

function field(label, attrs) {
	const input = h(attrs && attrs.multiline ? 'textarea' : 'input', Object.assign({}, attrs, { multiline: null }));
	return { el: h('label', { 'class': 'field' }, h('span', {}, label), input), input };
}

function choiceDialog(title, options, current) {
	const name = 'c' + Math.random().toString(36).slice(2);
	let wrapResolve;
	const list = h('div', {}, options.map(([v, label]) => h('label', { 'class': 'radio' },
		h('input', { 'type': 'radio', 'name': name, 'value': v, 'checked': v === current, 'onchange': () => wrapResolve(v) }), label)));
	const p = dialog(title, list, [ { label: t('cancel'), value: null } ]);
	return new Promise((resolve) => {
		wrapResolve = (v) => { document.querySelector('.dialog-wrap')?.remove(); resolve(v); };
		p.then(resolve);
	});
}

function inputDialog(title, label, value, attrs) {
	const f = field(label, Object.assign({ 'value': value || '' }, attrs));
	return dialog(title, f.el, [
		{ label: t('cancel'), value: null },
		{ label: t('ok'), value: () => f.input.value, submit: true }
	]);
}

function openMenu(anchor, items) {
	closeMenus();
	const r = anchor.getBoundingClientRect();
	const menu = h('div', { 'class': 'menu', 'role': 'menu' }, items.filter(Boolean).map(([label, fn]) =>
		h('button', { 'type': 'button', 'role': 'menuitem', 'onclick': () => { closeMenus(); fn(); } }, label)));
	const rtl = document.documentElement.dir === 'rtl';
	menu.style.top = (r.bottom + 4) + 'px';
	if (rtl) menu.style.left = Math.max(8, r.left) + 'px';
	else menu.style.right = Math.max(8, window.innerWidth - r.right) + 'px';
	const shield = h('div', { 'class': 'menu-shield', 'style': 'position:fixed;inset:0;z-index:29', 'onclick': closeMenus });
	document.body.append(shield, menu);
	menu.querySelector('button')?.focus();
}

function closeMenus() {
	document.querySelectorAll('.menu, .menu-shield').forEach((x) => x.remove());
}

/* ------------------------------------------------------------------ API */

const state = {
	token: LS.get('token'),
	link: LS.get('link'),
	data: null,
	group: LS.get('group') || null,
	delays: {},
	sorted: false,
	search: null,
	status: null,
	busy: false,
	testing: 0
};

class AuthError extends Error {}

async function api(action, params) {
	let res;
	try {
		res = await fetch(API, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			cache: 'no-store',
			credentials: 'omit',
			body: JSON.stringify(Object.assign({ action: action, token: state.token || '' }, params || {}))
		});
	}
	catch (e) {
		throw new Error(t('network_error'));
	}
	let j = null;
	try { j = await res.json(); } catch (e) { j = null; }
	if (!j) throw new Error(t('network_error') + ' (HTTP ' + res.status + ')');
	if (action !== 'login' && (j.error === 'auth' || j.error === 'disabled')) {
		signOut(j.error === 'disabled' ? t('disabled') : t('session_expired'), true);
		throw new AuthError(j.error);
	}
	return j;
}

function errText(j) {
	return t(j && j.error) !== (j && j.error) ? t(j.error) : t('error', (j && j.error) || '?');
}

/* ------------------------------------------------------------------ app root */

const root = document.getElementById('app');
let pollTimer = null;

function signOut(message, keepServer) {
	if (!keepServer && state.token) api('logout').catch(() => {});
	state.token = null;
	LS.set('token', null);
	state.data = null;
	clearInterval(pollTimer);
	if (sub) { sub.remove(); sub = null; }
	main = null;
	closeMenus();
	document.querySelectorAll('.dialog-wrap').forEach((x) => x.remove());
	renderLogin(message);
}

/* ------------------------------------------------------------------ login */

function renderLogin(message) {
	closeMenus();
	const user = field(t('username'), { 'autocomplete': 'username', 'autocapitalize': 'off', 'spellcheck': 'false', 'class': 'ltr', 'value': LS.get('user') || 'admin' });
	const pass = field(t('password'), { 'type': 'password', 'autocomplete': 'current-password', 'class': 'ltr' });
	const err = h('div', { 'class': 'err', 'role': 'alert' }, message || (state.link ? '' : t('no_link')));
	const btn = h('button', { 'class': 'tbtn filled', 'type': 'submit', 'disabled': !state.link }, t('sign_in'));
	const form = h('form', { 'onsubmit': async (e) => {
		e.preventDefault();
		btn.disabled = true;
		err.textContent = '';
		try {
			const j = await api('login', { link: state.link || '', username: user.input.value.trim(), password: pass.input.value });
			if (j.ok && j.token) {
				state.token = j.token;
				LS.set('token', j.token);
				LS.set('user', user.input.value.trim());
				startMain();
				return;
			}
			err.textContent = j.error === 'locked' ? t('locked', Math.max(1, Math.ceil((j.retry_after || 60) / 60))) : errText(j);
		}
		catch (ex) { err.textContent = ex.message; }
		btn.disabled = !state.link;
	} },
		h('img', { 'src': 'icon.svg', 'alt': '' }),
		h('h1', {}, t('app')),
		h('p', {}, t('login_sub')),
		user.el, pass.el, btn, err);
	root.replaceChildren(h('div', { 'class': 'login' }, form));
	if (state.link) setTimeout(() => (user.input.value ? pass.input : user.input).focus(), 50);
}

/* ------------------------------------------------------------------ main screen */

let main = null;   /* refs of the main screen */

function startMain() {
	history.replaceState({ screen: 'main' }, '');
	renderMain();
	refresh();
	clearInterval(pollTimer);
	pollTimer = setInterval(() => { if (!document.hidden && main && main.visible) refresh(); }, 8000);
}

async function refresh() {
	try {
		const j = await api('overview');
		if (!j.ok) return;
		state.data = j;
		if (main) { updateList(); updateBar(); }
	}
	catch (e) {
		if (!(e instanceof AuthError) && main && !state.data) setStatus(e.message);
	}
}

function groupsOf(d) {
	const g = (d && d.groups) || [];
	return g.length ? g : [ '' ];
}

function visibleNodes() {
	const d = state.data;
	if (!d) return [];
	const groups = groupsOf(d);
	if (state.group == null || !groups.includes(state.group)) state.group = groups[0];
	let list = d.nodes.filter((n) => groups.length < 2 || n.group === state.group);
	if (state.search) {
		const q = state.search.toLowerCase();
		list = list.filter((n) => (n.remarks + ' ' + n.address + ' ' + n.type).toLowerCase().includes(q));
	}
	if (state.sorted) {
		const key = (n) => { const v = state.delays[n.id]; return v == null ? 1e9 : (v < 0 ? 1e8 : v); };
		list = list.slice().sort((a, b) => key(a) - key(b));
	}
	return list;
}

function renderMain() {
	closeMenus();
	const title = h('div', { 'class': 'title' }, t('app'));
	const search = h('input', { 'class': 'search', 'type': 'search', 'placeholder': t('search'), 'hidden': true, 'oninput': () => { state.search = search.value; updateList(); } });
	const navBtn = iconBtn('menu', t('menu'), () => {
		if (state.search != null) { state.search = null; search.value = ''; search.hidden = true; title.hidden = false; navBtn.replaceChildren(icon('menu')); navBtn.classList.remove('flip'); updateList(); }
		else openDrawer();
	});
	const searchBtn = iconBtn('search', t('search'), () => {
		state.search = '';
		title.hidden = true;
		search.hidden = false;
		navBtn.replaceChildren(icon('back'));
		navBtn.classList.add('flip');
		search.focus();
	});
	const addBtn = iconBtn('add', t('add'), () => openMenu(addBtn, [
		[ t('import_clipboard'), importClipboard ],
		[ t('import_file'), importFile ]
	]));
	const moreBtn = iconBtn('more', t('more'), () => openMenu(moreBtn, [
		[ t('restart'), restartService ],
		[ t('delete_configs'), deleteVisible ],
		[ t('sort'), () => { state.sorted = !state.sorted; updateList(); } ],
		[ t('tcping'), () => testAll('tcp') ],
		[ t('real'), () => testAll('real') ],
		[ t('update_sub'), () => updateSubs('') ]
	]));
	const bar = h('header', { 'class': 'topbar' }, navBtn, title, search, searchBtn, addBtn, moreBtn);
	const tabs = h('nav', { 'class': 'tabs', 'hidden': true });
	const progress = h('div', { 'class': 'progress', 'hidden': true }, h('i'));
	const list = h('main', { 'class': 'content', 'onscroll': () => bar.classList.toggle('scrolled', list.scrollTop > 0) });
	const status = h('div', { 'class': 'status', 'aria-live': 'polite' }, '');
	const knob = h('button', { 'class': 'knob', 'type': 'button', 'aria-label': t('start'), 'onclick': (e) => { e.stopPropagation(); toggleService(); } }, icon('play'));
	const track = h('div', { 'class': 'track', 'role': 'button', 'tabindex': '0', 'onclick': checkConnection,
		'onkeydown': (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); checkConnection(); } } }, status, knob);
	const scrim = h('div', { 'class': 'scrim', 'onclick': closeDrawer });
	const drawer = renderDrawer();
	const screen = h('div', { 'class': 'screen' }, bar, tabs, progress, list, h('div', { 'class': 'bottombar' }, track));
	root.replaceChildren(screen, scrim, drawer);
	main = { visible: true, screen, list, tabs, progress, status, knob, scrim, drawer };
	updateList();
	updateBar();
}

function updateList() {
	if (!main) return;
	const d = state.data;
	const groups = groupsOf(d);
	main.tabs.hidden = groups.length < 2;
	if (groups.length > 1) {
		main.tabs.replaceChildren(...groups.map((g) => h('button', {
			'class': 'tab' + (g === state.group ? ' active' : ''), 'type': 'button',
			'onclick': () => { state.group = g; LS.set('group', g); updateList(); }
		}, g || t('default_group'))));
	}
	if (!d) { main.list.replaceChildren(); return; }
	const nodes = visibleNodes();
	if (!nodes.length) {
		main.list.replaceChildren(h('div', { 'class': 'empty' }, icon('inbox'), d.nodes.length ? '' : t('no_configs')));
		return;
	}
	main.list.classList.add('grid');
	main.list.replaceChildren(...nodes.map(renderRow));
}

function renderRow(n) {
	const selected = state.data && state.data.node === n.id;
	const delay = state.delays[n.id];
	const stats = n.address ? (n.address + (n.port ? ' : ' + n.port : '')) : n.core;
	return h('div', { 'class': 'row', 'role': 'button', 'tabindex': '0', 'aria-current': selected ? 'true' : null,
		'onclick': () => selectNode(n), 'onkeydown': (e) => { if (e.key === 'Enter') selectNode(n); } },
		h('div', { 'class': 'ind' }, selected ? h('i') : null),
		h('div', { 'class': 'body' },
			h('div', { 'class': 'l1' },
				h('div', { 'class': 'remarks' }, n.remarks || n.id),
				h('div', { 'class': 'acts', 'onclick': (e) => e.stopPropagation() },
					iconBtn('share', t('details'), () => nodeDetails(n), 'small'),
					iconBtn('edit', t('edit'), () => window.open(LUCI_NODE + encodeURIComponent(n.id), '_blank', 'noopener'), 'small'),
					iconBtn('delete', t('delete'), () => deleteNodes([ n ], t('delete_one', n.remarks)), 'small'))),
			h('div', { 'class': 'l2' },
				n.group ? h('span', { 'class': 'badge' }, n.group.slice(0, 1)) : null,
				h('span', { 'class': 'stats' }, stats)),
			h('div', { 'class': 'l3' },
				h('span', { 'class': 'type' }, n.type),
				delay != null && delay !== 0 ? h('span', { 'class': 'delay' + (delay < 0 ? ' bad' : '') }, delay === 'wait' ? '…' : delay + ' ms') : null)));
}

function setStatus(text) {
	state.status = text;
	if (main) main.status.textContent = text;
}

function updateBar() {
	if (!main) return;
	const d = state.data;
	const on = !!(d && d.running);
	main.knob.classList.toggle('on', on);
	main.knob.replaceChildren(icon(on ? 'stop' : 'play'));
	main.knob.setAttribute('aria-label', on ? t('stop') : t('start'));
	main.knob.disabled = state.busy;
	main.progress.hidden = !state.testing;
	if (state.busy || state.testing) return;
	setStatus(on ? t('connected') : t('not_connected'));
}

/* wait until the service reaches the wanted state (or 40 s pass) */
async function waitRunning(want) {
	for (let i = 0; i < 20; i++) {
		await new Promise((r) => setTimeout(r, 2000));
		await refresh();
		if (state.data && !!state.data.running === want) return true;
	}
	return false;
}

async function toggleService() {
	if (state.busy || !state.data) return;
	const on = !state.data.running;
	if (on && !state.data.node) { toast(t('need_node')); return; }
	state.busy = true;
	main.knob.disabled = true;
	if (on) { main.knob.classList.add('spin'); setTimeout(() => main && main.knob.classList.remove('spin'), 3000); }
	setStatus(on ? t('starting') : t('stopping'));
	try {
		const j = await api('toggle', { on: on });
		if (!j.ok) toast(errText(j), 'err');
		else await waitRunning(on);
	}
	catch (e) { if (!(e instanceof AuthError)) toast(e.message, 'err'); }
	state.busy = false;
	updateBar();
}

async function restartService() {
	state.busy = true;
	setStatus(t('restarting'));
	try { await api('restart'); await new Promise((r) => setTimeout(r, 3000)); await waitRunning(true); }
	catch (e) { if (!(e instanceof AuthError)) toast(e.message, 'err'); }
	state.busy = false;
	updateBar();
}

async function selectNode(n) {
	if (!state.data || state.data.node === n.id) return;
	const prev = state.data.node;
	state.data.node = n.id;
	updateList();
	try {
		const j = await api('select', { id: n.id });
		if (!j.ok) { state.data.node = prev; updateList(); toast(errText(j), 'err'); return; }
		toast(t('selected', n.remarks || n.id));
		if (state.data.running) {
			state.busy = true;
			setStatus(t('restarting'));
			await new Promise((r) => setTimeout(r, 3000));
			await waitRunning(true);
			state.busy = false;
			updateBar();
		}
	}
	catch (e) { if (!(e instanceof AuthError)) toast(e.message, 'err'); }
}

async function checkConnection() {
	if (state.busy || !state.data) return;
	if (!state.data.running) { setStatus(t('not_connected')); return; }
	state.busy = true;
	setStatus(t('testing'));
	try {
		const j = await api('check');
		setStatus(j.ok && j.ms >= 0 ? t('conn_ok', j.ms) : t('conn_fail'));
	}
	catch (e) { if (!(e instanceof AuthError)) setStatus(e.message); }
	state.busy = false;
	main.knob.disabled = false;
}

async function testAll(kind) {
	const nodes = visibleNodes().filter((n) => kind !== 'tcp' || n.address);
	if (!nodes.length || state.testing) return;
	nodes.forEach((n) => { state.delays[n.id] = 'wait'; });
	state.testing = nodes.length;
	updateList();
	updateBar();
	setStatus(t('testing_count', state.testing));
	const queue = nodes.slice();
	const worker = async () => {
		while (queue.length) {
			const n = queue.shift();
			try {
				const j = await api('test', { id: n.id, kind: kind });
				state.delays[n.id] = j.ok ? j.ms : -1;
			}
			catch (e) { state.delays[n.id] = -1; if (e instanceof AuthError) { queue.length = 0; } }
			state.testing--;
			if (state.testing) setStatus(t('testing_count', state.testing));
			updateList();
		}
	};
	await Promise.all(Array.from({ length: kind === 'tcp' ? 6 : 2 }, worker));
	state.testing = 0;
	updateBar();
}

async function testOne(n, kind, out) {
	out.textContent = '…';
	try {
		const j = await api('test', { id: n.id, kind: kind });
		state.delays[n.id] = j.ok ? j.ms : -1;
	}
	catch (e) { state.delays[n.id] = -1; }
	out.textContent = state.delays[n.id] + ' ms';
	updateList();
}

function nodeDetails(n) {
	const out = h('dd', {}, state.delays[n.id] != null && state.delays[n.id] !== 'wait' ? state.delays[n.id] + ' ms' : '—');
	const rows = [ [ t('type'), n.type ], [ t('core'), n.core ], [ t('address'), n.address ], [ t('port'), n.port ], [ t('group'), n.group || t('default_group') ] ]
		.filter((r) => r[1]);
	const body = h('div', {},
		h('dl', {}, rows.map(([k, v]) => [ h('dt', {}, k), h('dd', {}, v) ]), h('dt', {}, t('delay')), out),
		h('p', { 'class': 'text' }, t('edit_luci')));
	dialog(n.remarks || n.id, body, [
		n.address ? { label: 'TCPing', value: () => { testOne(n, 'tcp', out); return undefined; } } : null,
		{ label: t('real_delay'), value: () => { testOne(n, 'real', out); return undefined; } },
		{ label: t('close'), value: null }
	].filter(Boolean));
}

async function deleteNodes(nodes, question) {
	if (!nodes.length) return;
	if (!await confirmDialog(question || t('delete_confirm', nodes.length), t('delete'), true)) return;
	try {
		const j = await api('delete', { ids: nodes.map((n) => n.id) });
		toast(j.ok ? t('deleted') : errText(j), j.ok ? '' : 'err');
		await refresh();
	}
	catch (e) { if (!(e instanceof AuthError)) toast(e.message, 'err'); }
}

function deleteVisible() {
	deleteNodes(visibleNodes());
}

async function importText(text) {
	if (!text || !text.trim()) return;
	try {
		const j = await api('import', { text: text });
		if (!j.ok) toast(errText(j), 'err');
		else toast(j.added ? t('imported', j.added) : t('import_none'), j.added ? 'ok' : 'err');
		await refresh();
	}
	catch (e) { if (!(e instanceof AuthError)) toast(e.message, 'err'); }
}

async function importClipboard() {
	let text = '';
	try { if (navigator.clipboard && window.isSecureContext) text = await navigator.clipboard.readText(); } catch (e) { text = ''; }
	if (text && /:\/\//.test(text)) return importText(text);
	const f = field(t('paste_hint'), { 'multiline': true, 'spellcheck': 'false', 'autocapitalize': 'off' });
	const v = await dialog(t('import_clipboard'), f.el, [
		{ label: t('cancel'), value: null },
		{ label: t('ok'), value: () => f.input.value }
	]);
	if (v) importText(v);
}

function importFile() {
	const input = h('input', { 'type': 'file', 'accept': '.txt,.conf,text/plain', 'onchange': () => {
		const file = input.files && input.files[0];
		if (!file || file.size > 200000) return;
		file.text().then(importText);
	} });
	input.click();
}

async function updateSubs(id) {
	try {
		const j = await api('sub_update', { id: id || '' });
		toast(j.ok ? t('updating') : errText(j), j.ok ? '' : 'err');
		if (j.ok) [ 15000, 40000, 90000 ].forEach((ms) => setTimeout(refresh, ms));
	}
	catch (e) { if (!(e instanceof AuthError)) toast(e.message, 'err'); }
}

/* ------------------------------------------------------------------ drawer */

function renderDrawer() {
	const item = (ico, label, fn, href) => href
		? h('a', { 'class': 'navitem', 'href': href, 'target': '_blank', 'rel': 'noopener', 'onclick': closeDrawer }, icon(ico), label)
		: h('button', { 'class': 'navitem', 'type': 'button', 'onclick': () => { closeDrawer(); fn(); } }, icon(ico), label);
	return h('aside', { 'class': 'drawer', 'aria-label': t('menu') },
		h('div', { 'class': 'head' }, h('img', { 'src': 'icon.svg', 'alt': '' }), h('div', { 'class': 'name' }, t('app')),
			h('div', { 'class': 'ver' }, state.data ? 'v' + state.data.version : '')),
		item('subs', t('subscriptions'), () => openScreen('subs')),
		item('settings', t('settings'), () => openScreen('settings')),
		h('div', { 'class': 'hr' }),
		item('log', t('logcat'), () => openScreen('log')),
		item('update', t('check_update'), null, REPO + '/releases'),
		item('open', t('open_luci'), null, '/cgi-bin/luci/admin/services/passwall2'),
		item('info', t('about'), () => openScreen('about')),
		item('logout', t('sign_out'), () => signOut()));
}

function openDrawer() {
	main.drawer.replaceWith(main.drawer = renderDrawer());
	requestAnimationFrame(() => { main.drawer.classList.add('open'); main.scrim.classList.add('open'); });
}

function closeDrawer() {
	if (!main) return;
	main.drawer.classList.remove('open');
	main.scrim.classList.remove('open');
}

/* ------------------------------------------------------------------ sub screens */

function subScreen(title, actions, content) {
	const bar = h('header', { 'class': 'topbar' }, iconBtn('back', t('back'), () => history.back(), 'flip'), h('div', { 'class': 'title' }, title), actions);
	const scr = h('div', { 'class': 'screen', 'style': 'z-index:25' }, bar, content);
	document.body.appendChild(scr);
	return scr;
}

let sub = null;
function openScreen(name) {
	closeSub();
	history.pushState({ screen: name }, '');
	main.visible = false;
	sub = ({ subs: screenSubs, settings: screenSettings, log: screenLog, about: screenAbout })[name]();
}

function closeSub() {
	if (sub) { sub.remove(); sub = null; }
	if (main) main.visible = true;
}

window.addEventListener('popstate', () => {
	closeMenus();
	document.querySelectorAll('.dialog-wrap').forEach((x) => x.remove());
	if (sub) { closeSub(); refresh(); }
	else closeDrawer();
});

function screenSubs() {
	const list = h('main', { 'class': 'content' });
	const draw = () => {
		const subs = (state.data && state.data.subscriptions) || [];
		list.replaceChildren(...(subs.length ? subs.map((s) => h('div', { 'class': 'subrow' },
			h('div', { 'class': 'pt' }, h('b', {}, s.remark), h('small', {}, s.url)),
			iconBtn('update', t('update_sub'), () => updateSubs(s.id), 'small'),
			iconBtn('delete', t('delete'), async () => {
				if (!await confirmDialog(t('delete_one', s.remark), t('delete'), true)) return;
				const j = await api('sub_delete', { id: s.id });
				if (!j.ok) toast(errText(j), 'err');
				await refresh(); draw();
			}, 'small'))) : [ h('div', { 'class': 'empty' }, icon('subs'), t('no_subs')) ]));
	};
	const add = async () => {
		const r = field(t('remark'), {});
		const u = field(t('url'), { 'type': 'url', 'class': 'ltr', 'autocapitalize': 'off', 'spellcheck': 'false', 'placeholder': 'https://' });
		const v = await dialog(t('add_sub'), h('div', {}, r.el, u.el), [
			{ label: t('cancel'), value: null },
			{ label: t('save'), value: () => ({ remark: r.input.value, url: u.input.value }), submit: true }
		]);
		if (!v) return;
		const j = await api('sub_add', v);
		if (!j.ok) { toast(errText(j), 'err'); return; }
		await refresh(); draw();
		updateSubs(j.id);
	};
	draw();
	return subScreen(t('subscriptions'), [ iconBtn('update', t('update_all'), () => updateSubs('')), iconBtn('add', t('add_sub'), add) ], list);
}

function screenSettings() {
	const list = h('main', { 'class': 'content' });
	const draw = () => {
		const s = (state.data && state.data.settings) || {};
		const socks = s.proxy_mode === 'socks';
		const save = async (patch) => {
			try {
				const j = await api('settings', { settings: patch });
				if (!j.ok) { toast(j.error === 'bad_value' ? t('bad_value') : errText(j), 'err'); return; }
				toast(state.data.enabled ? t('saved_restart') : t('saved'), 'ok');
				Object.assign(state.data.settings, patch);
				draw();
				setTimeout(refresh, 4000);
			}
			catch (e) { if (!(e instanceof AuthError)) toast(e.message, 'err'); }
		};
		const pref = (ico, title, summary, onclick, extra, disabled) => h('div', { 'class': 'pref' + (disabled ? ' disabled' : ''), 'role': 'button', 'tabindex': '0', 'onclick': onclick },
			h('div', { 'class': 'pi' }, ico ? icon(ico) : null), h('div', { 'class': 'pt' }, h('b', {}, title), summary ? h('small', {}, summary) : null), extra);
		const sw = (ico, title, key, disabled) => {
			const inp = h('input', { 'type': 'checkbox', 'checked': s[key] === '1', 'tabindex': '-1' });
			return pref(ico, title, null, (e) => { e.preventDefault(); save({ [key]: s[key] === '1' ? '0' : '1' }); }, h('span', { 'class': 'switch' }, inp, h('i')), disabled);
		};
		const choose = (title, key, options) => async () => {
			const v = await choiceDialog(title, options, s[key]);
			if (v != null && v !== s[key]) save({ [key]: v });
		};
		const input = (title, key, attrs) => async () => {
			const v = await inputDialog(title, title, s[key], Object.assign({ 'class': 'ltr', 'autocapitalize': 'off', 'spellcheck': 'false' }, attrs));
			if (v != null && v.trim() !== s[key]) save({ [key]: v.trim() });
		};
		const modeOpts = [ [ 'tproxy', t('mode_tproxy') ], [ 'socks', t('mode_socks') ] ];
		const listenOpts = [ [ '0.0.0.0', t('listen_all') ], [ '127.0.0.1', t('listen_local') ] ];
		const dnsOpts = [ [ 'tcp', 'TCP' ], [ 'udp', 'UDP' ], [ 'doh', 'DoH' ] ];
		const label = (opts, v) => (opts.find((o) => o[0] === v) || [ v, v ])[1];
		const langOpts = [ [ 'system', t('system') ], [ 'en', 'English' ], [ 'fa', 'فارسی' ] ];
		const themeOpts = [ [ 'system', t('system') ], [ 'light', t('light') ], [ 'dark', t('dark') ] ];
		list.replaceChildren(...[
			h('div', { 'class': 'pref-cat' }, t('cat_proxy')),
			pref('tune', t('proxy_mode'), label(modeOpts, s.proxy_mode), choose(t('proxy_mode'), 'proxy_mode', modeOpts)),
			pref('port', t('socks_port'), s.node_socks_port, input(t('socks_port'), 'node_socks_port', { 'inputmode': 'numeric' })),
			socks ? pref(null, t('listen'), label(listenOpts, s.socks_mode_listen), choose(t('listen'), 'socks_mode_listen', listenOpts)) : null,
			socks ? pref(null, t('http_port'), s.socks_mode_http_port || t('off'), input(t('http_port'), 'socks_mode_http_port', { 'inputmode': 'numeric', 'placeholder': t('off') })) : null,
			socks ? null : sw(null, t('localhost_proxy'), 'localhost_proxy'),
			socks ? null : sw(null, t('client_proxy'), 'client_proxy'),
			h('div', { 'class': 'pref-cat' }, t('cat_dns')),
			pref('dns', t('remote_dns_proto'), label(dnsOpts, s.remote_dns_protocol), choose(t('remote_dns_proto'), 'remote_dns_protocol', dnsOpts)),
			s.remote_dns_protocol === 'doh'
				? pref(null, t('doh'), s.remote_dns_doh, input(t('doh'), 'remote_dns_doh', { 'type': 'url' }))
				: pref(null, t('remote_dns'), s.remote_dns, input(t('remote_dns'), 'remote_dns')),
			h('div', { 'class': 'pref-cat' }, t('cat_app')),
			pref('lang', t('language'), label(langOpts, LS.get('lang') || 'system'), async () => {
				const v = await choiceDialog(t('language'), langOpts, LS.get('lang') || 'system');
				if (v) { LS.set('lang', v); applyLang(); history.back(); setTimeout(() => { renderMain(); openScreen('settings'); }, 50); }
			}),
			pref('palette', t('theme'), label(themeOpts, LS.get('theme') || 'system'), async () => {
				const v = await choiceDialog(t('theme'), themeOpts, LS.get('theme') || 'system');
				if (v) { LS.set('theme', v); applyTheme(); draw(); }
			}),
			pref('logout', t('sign_out'), LS.get('user') || '', () => signOut())
		].filter(Boolean));
	};
	draw();
	return subScreen(t('settings'), null, list);
}

function screenLog() {
	const pre = h('pre', { 'class': 'log' }, '…');
	const box = h('main', { 'class': 'content', 'style': 'padding-bottom:16px' }, pre);
	const load = async () => {
		try {
			const j = await api('log');
			pre.textContent = (j.ok && j.log) ? j.log : t('log_empty');
			box.scrollTop = box.scrollHeight;
		}
		catch (e) { if (!(e instanceof AuthError)) pre.textContent = e.message; }
	};
	load();
	return subScreen(t('logcat'), [
		iconBtn('update', t('refresh'), load),
		iconBtn('delete', t('clear'), async () => { await api('clear_log'); load(); })
	], box);
}

function screenAbout() {
	const d = state.data || {};
	return subScreen(t('about'), null, h('main', { 'class': 'content' },
		h('div', { 'class': 'about' },
			h('img', { 'src': 'icon.svg', 'alt': '' }),
			h('h1', {}, t('app')),
			h('div', { 'class': 'ver' }, t('version', d.version || '?')),
			h('p', { 'class': 'ver' }, t('about_text'))),
		h('a', { 'class': 'pref', 'href': REPO, 'target': '_blank', 'rel': 'noopener', 'style': 'color:inherit;text-decoration:none' },
			h('div', { 'class': 'pi' }, icon('code')), h('div', { 'class': 'pt' }, h('b', {}, t('source')), h('small', {}, REPO))),
		h('a', { 'class': 'pref', 'href': REPO + '/releases', 'target': '_blank', 'rel': 'noopener', 'style': 'color:inherit;text-decoration:none' },
			h('div', { 'class': 'pi' }, icon('update')), h('div', { 'class': 'pt' }, h('b', {}, t('check_update')), h('small', {}, REPO + '/releases')))));
}

/* ------------------------------------------------------------------ boot */

function boot() {
	applyLang();
	applyTheme();
	if (darkQuery && darkQuery.addEventListener) darkQuery.addEventListener('change', applyTheme);
	const m = /[#&]k=([0-9a-f]{8,64})/i.exec(location.hash || '');
	if (m) {
		if (state.link && state.link !== m[1]) { state.token = null; LS.set('token', null); }
		state.link = m[1];
		LS.set('link', m[1]);
		history.replaceState(null, '', location.pathname + location.search);
	}
	if ('serviceWorker' in navigator && window.isSecureContext)
		navigator.serviceWorker.register('sw.js').catch(() => {});
	document.addEventListener('visibilitychange', () => { if (!document.hidden && state.token && main) refresh(); });
	if (state.token) startMain();
	else renderLogin();
}

boot();
})();
