//! Asynchronous calls (`async: "1"`): run a method detached via `passwall2 rpc job <id>` so
//! long operations are not cut by the LuCI (20 s) / uhttpd (60 s) request timeouts.
//!
//! Files in `JOB_DIR`: `<id>.req` (method+params), `<id>.pid` (while running),
//! `<id>.json` (result). `job_status` returns the result once and removes the files.

use super::params::Params;
use crate::util;
use serde_json::{json, Value};

pub const JOB_DIR: &str = "/tmp/etc/passwall2_tmp/rpc_jobs";
const MAX_AGE_SECS: u64 = 3600;

pub fn valid_job_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

fn file(id: &str, ext: &str) -> String {
    format!("{}/{}.{}", JOB_DIR, id, ext)
}

fn cleanup_old() {
    let Ok(rd) = std::fs::read_dir(JOB_DIR) else { return };
    let now = std::time::SystemTime::now();
    for e in rd.flatten() {
        let old = e.metadata().ok().and_then(|m| m.modified().ok()).and_then(|t| now.duration_since(t).ok()).is_some_and(|d| d.as_secs() > MAX_AGE_SECS);
        if old {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// Queue `method` and start it in the background → `{"job": id}`.
pub fn spawn(method: &str, params: &Params) -> Value {
    util::mkdir(JOB_DIR);
    cleanup_old();
    let id = params.get("job").filter(|j| valid_job_id(j)).unwrap_or_else(|| crate::api::gen_random_char(16));
    let mut p = params.clone();
    p.remove("async");
    p.remove("job");
    for ext in ["json", "pid"] {
        let _ = std::fs::remove_file(file(&id, ext));
    }
    let req = json!({"method": method, "params": p.to_value()});
    if !util::write(&file(&id, "req"), &req.to_string()) {
        return json!({"code": 0, "error": "Unable to queue job"});
    }
    super::spawn_self(&["rpc", "job", &id]);
    json!({"job": id})
}

fn write_atomic(path: &str, data: &str) {
    let tmp = format!("{}.tmp", path);
    if std::fs::write(&tmp, data).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// `passwall2 rpc job <id>`: run the queued call and store its result.
pub fn run(id: &str) -> i32 {
    if !valid_job_id(id) {
        return 1;
    }
    let req: Value = serde_json::from_str(&util::read(&file(id, "req"))).unwrap_or(Value::Null);
    let Some(method) = req["method"].as_str().map(|s| s.to_string()) else { return 1 };
    let params = Params::from_json(&req["params"].to_string());
    let _ = std::fs::write(file(id, "pid"), std::process::id().to_string());
    let result = super::call_sync(&method, &params).unwrap_or_else(|| json!({"error": "Method not found"}));
    write_atomic(&file(id, "json"), &result.to_string());
    let _ = std::fs::remove_file(file(id, "pid"));
    0
}

fn pid_alive(pid_file: &str) -> bool {
    util::read(pid_file).trim().parse::<u32>().is_ok_and(|pid| util::exists(&format!("/proc/{}", pid)))
}

/// `job_status {job}` → `{"done": false}` | `{"done": true, "result": ...}`.
pub fn status(p: &Params) -> Value {
    let id = p.s("job");
    if !valid_job_id(&id) {
        return json!({"done": true, "error": "Invalid job"});
    }
    let res = file(&id, "json");
    if util::exists(&res) {
        let v: Value = serde_json::from_str(&util::read(&res)).unwrap_or_else(|_| json!({}));
        for ext in ["json", "req", "pid"] {
            let _ = std::fs::remove_file(file(&id, ext));
        }
        return json!({"done": true, "result": v});
    }
    if pid_alive(&file(&id, "pid")) {
        return json!({"done": false});
    }
    // queued but the runner has not written its pid yet
    let req = file(&id, "req");
    let fresh = std::fs::metadata(&req).ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()).is_some_and(|d| d.as_secs() < 10);
    if fresh && !util::exists(&file(&id, "pid")) {
        return json!({"done": false});
    }
    let _ = std::fs::remove_file(&req);
    let _ = std::fs::remove_file(file(&id, "pid"));
    json!({"done": true, "error": "Job not found"})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_job_id("abc-DEF_123"));
        assert!(!valid_job_id(""));
        assert!(!valid_job_id("../x"));
        assert!(!valid_job_id(&"a".repeat(65)));
    }

    #[test]
    fn unknown_job() {
        let v = status(&Params::from_json(r#"{"job":"nonexistentjob123"}"#));
        assert_eq!(v["done"], json!(true));
        assert_eq!(v["error"], json!("Job not found"));
    }
}
