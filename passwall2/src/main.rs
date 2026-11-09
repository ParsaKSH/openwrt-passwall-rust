//! passwall2 — multicall binary replacing every script of upstream luci-app-passwall2.
//!
//! Usage: passwall2 <command> [args...]   (see `passwall2 help`)

pub mod uci;
pub mod util;
pub mod api;
pub mod xray;
pub mod singbox;
pub mod firewall;
pub mod app;
pub mod dns;
pub mod haproxy;
pub mod socks_switch;
pub mod server;
pub mod subscribe;
pub mod rules;
pub mod rpc;
pub mod migrate;

const HELP: &str = "passwall2 (Rust) — commands:
  start | stop | restart | boot          service control (used by /etc/init.d/passwall2)
  app <sub> [k=v...]                     internal runtime entry points (run_socks, socks_node_switch, ...)
  xray <gen_config|gen_proto_config|gen_config_server> '<json>'
  sing-box <gen_config|gen_proto_config|gen_config_server|geo_convert_srs> '<json>'
  nft <start|stop|...> | ipt <start|stop|...>   firewall
  server <start|stop|restart>            server side (/etc/init.d/passwall2_server)
  subscribe <start|truncate|...>         node subscription
  rule-update [log] [geoip,geosite,...]  geo data update
  socks-auto-switch <socks_id>           SOCKS auto switch daemon
  haproxy-check <laddr> <lport> <saddr> <sport>
  dns-helper <...>                       dnsmasq helper (helper_dnsmasq)
  monitor | tasks | lease2hosts          daemons
  rpc <list|call> [method]               rpcd exec plugin (luci.passwall2)
  migrate [--dry-run]                    bring a legacy (26.4-era) config to the current schema
  version";

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let cmd = argv.get(1).map(|s| s.as_str()).unwrap_or("help");
    let rest: Vec<String> = argv.iter().skip(2).cloned().collect();
    let code = match cmd {
        "start" | "stop" | "restart" | "boot" | "app" | "monitor" | "tasks" | "lease2hosts" | "test" => app::cli(cmd, &rest),
        "xray" => xray::cli(&rest),
        "sing-box" | "singbox" => singbox::cli(&rest),
        "nft" | "ipt" | "firewall" => firewall::cli(cmd, &rest),
        "server" => server::cli(&rest),
        "subscribe" => subscribe::cli(&rest),
        "rule-update" | "rule_update" => rules::cli(&rest),
        "socks-auto-switch" => socks_switch::cli(&rest),
        "haproxy" | "haproxy-check" => haproxy::cli(cmd, &rest),
        "dns-helper" => dns::cli(&rest),
        "rpc" => rpc::cli(&rest),
        "api" => api::cli(&rest),
        "migrate" => migrate::cli(&rest),
        "version" | "-v" | "--version" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            0
        }
        _ => {
            println!("{}", HELP);
            if cmd == "help" { 0 } else { 1 }
        }
    };
    std::process::exit(code);
}
