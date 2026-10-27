//! Tauri backend for kblocker.
//!
//! Everything the app shows is read directly: the module's sysfs attributes,
//! the domain list, the schedule and the registered PGP keys are all world
//! readable. Everything it changes goes through `pkexec kblockerctl …`, so
//! the CLI stays the single place that knows how to drive the module.

use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SYSFS: &str = "/sys/kernel/kblocker";
const DOMAINS_FILE: &str = "/etc/kblocker/domains.conf";
const SCHEDULE_FILE: &str = "/etc/kblocker/schedule.json";
const DEFAULT_CTL: &str = "/usr/local/bin/kblockerctl";
const SCHEDULER_UNIT: &str = "kblocker-scheduler.service";

fn ctl_path() -> String {
    std::env::var("KBLOCKERCTL").unwrap_or_else(|_| DEFAULT_CTL.to_string())
}

fn key_dir() -> String {
    std::env::var("KBLOCKER_PGP_KEY_DIR").unwrap_or_else(|_| "/etc/kblocker/keys".to_string())
}

fn enc_dir() -> String {
    std::env::var("KBLOCKER_PGP_ENC_DIR").unwrap_or_else(|_| "/var/lib/kblocker/unlock-pgp".to_string())
}

fn read_lines(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

// ---- Status ----

#[derive(Serialize)]
struct Status {
    module_loaded: bool,
    ctl_installed: bool,
    enabled: bool,
    remaining: u64,
    pgp_active: bool,
    state_restored: bool,
    protected_files: u32,
    blocked_ips: u32,
    domains: Vec<String>,
    scheduler_active: bool,
    /// Base URL of the key holder pages the scheduler hosts, if running
    web_url: Option<String>,
    /// Where the scheduler hosts those pages: "off", "local", "lan" or "custom"
    web_mode: &'static str,
    /// The address it listens on, kept while the pages are off
    web_host: String,
    web_port: u16,
}

/// Where the scheduler serves the key holder pages, from its KBLOCKER_WEB
/// setting. A wildcard bind is shown with this machine's LAN address so the
/// link works from other devices.
fn scheduler_web_addr() -> String {
    Command::new("systemctl")
        .args(["show", "--property=Environment", "--value", SCHEDULER_UNIT])
        .output()
        .ok()
        .and_then(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .find_map(|kv| kv.strip_prefix("KBLOCKER_WEB="))
                .map(String::from)
        })
        .unwrap_or_else(|| "127.0.0.1:8737".into())
}

/// Host and port of a KBLOCKER_WEB value, or the default when it's "off"
fn split_web_addr(addr: &str) -> (String, u16) {
    addr.rsplit_once(':')
        .and_then(|(h, p)| Some((h.trim_matches(['[', ']']).to_string(), p.parse().ok()?)))
        .unwrap_or_else(|| ("127.0.0.1".into(), 8737))
}

fn web_mode(addr: &str) -> &'static str {
    if addr == "off" {
        return "off";
    }
    match split_web_addr(addr).0.as_str() {
        "127.0.0.1" | "localhost" | "::1" => "local",
        "" | "0.0.0.0" | "::" => "lan",
        _ => "custom",
    }
}

fn scheduler_web_url(addr: &str) -> Option<String> {
    if addr == "off" {
        return None;
    }
    let (host, port) = addr.rsplit_once(':')?;
    let host = match host {
        "" | "0.0.0.0" | "[::]" => std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect("192.0.2.1:9").map(|_| s))
            .and_then(|s| s.local_addr())
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|_| "127.0.0.1".into()),
        h => h.to_string(),
    };
    Some(format!("http://{host}:{port}"))
}

#[tauri::command]
fn status() -> Status {
    let raw = fs::read_to_string(format!("{SYSFS}/status")).ok();
    let fields: HashMap<String, String> = raw
        .as_deref()
        .unwrap_or("")
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let num = |k: &str| fields.get(k).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);

    // The config file is what enable writes to the kernel; prefer it, and
    // fall back to the kernel's list when there is no config yet.
    let mut domains = read_lines(DOMAINS_FILE);
    if domains.is_empty() {
        domains = read_lines(&format!("{SYSFS}/blocked_domains"));
    }

    let scheduler_active = Command::new("systemctl")
        .args(["is-active", "--quiet", SCHEDULER_UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let web_addr = scheduler_web_addr();
    let (web_host, web_port) = split_web_addr(&web_addr);

    Status {
        module_loaded: raw.is_some(),
        ctl_installed: Path::new(&ctl_path()).exists(),
        enabled: num("enabled") == 1,
        remaining: num("remaining"),
        pgp_active: num("pgp_active") == 1,
        state_restored: num("state_restored") == 1,
        protected_files: num("protected_files") as u32,
        blocked_ips: (num("blocked_ips_v4") + num("blocked_ips_v6")) as u32,
        domains,
        web_url: if scheduler_active { scheduler_web_url(&web_addr) } else { None },
        web_mode: web_mode(&web_addr),
        web_host,
        web_port,
        scheduler_active,
    }
}

// ---- Key holders ----

#[derive(Serialize)]
struct KeyHolder {
    fingerprint: String,
    name: String,
    user: String,
    /// An encrypted copy of the current unload key exists for this holder
    has_cipher: bool,
}

fn gpg_show(path: &Path) -> Option<(String, String)> {
    let out = Command::new("gpg")
        .args(["--batch", "--with-colons", "--show-keys"])
        .arg(path)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut fp = String::new();
    let mut user = String::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() >= 10 {
            if f[0] == "fpr" && fp.is_empty() {
                fp = f[9].to_string();
            }
            if f[0] == "uid" && user.is_empty() {
                user = f[9].to_string();
            }
        }
    }
    if fp.is_empty() {
        None
    } else {
        Some((fp, user))
    }
}

#[tauri::command]
fn key_holders() -> Vec<KeyHolder> {
    let dir = key_dir();
    let enc = enc_dir();
    let Ok(entries) = fs::read_dir(&dir) else {
        return vec![];
    };
    let mut out = vec![];
    for e in entries.flatten() {
        let path = e.path();
        let Some(file) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(stem) = [".asc", ".gpg", ".pub"].iter().find_map(|ext| file.strip_suffix(ext)) else {
            continue;
        };
        // kblockerctl names key files after the fingerprint; gpg is only
        // needed for the user id, so a missing gpg still lists the key
        let fp = stem.to_uppercase();
        if fp.len() != 40 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let user = gpg_show(&path).map(|(_, u)| u).unwrap_or_default();
        let name = fs::read_to_string(format!("{dir}/{fp}.name"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let has_cipher = Path::new(&format!("{enc}/unlock-{fp}.asc")).exists();
        out.push(KeyHolder { fingerprint: fp, name, user, has_cipher });
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

/// The encrypted unload key for one holder, to send to them
#[tauri::command]
fn cipher_for(fingerprint: String) -> Result<String, String> {
    if fingerprint.len() != 40 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Not a valid fingerprint.".into());
    }
    let path = format!("{}/unlock-{}.asc", enc_dir(), fingerprint.to_uppercase());
    fs::read_to_string(&path).map_err(|_| "There's no encrypted key for this holder.".to_string())
}

/// All encrypted unload keys, keyed by fingerprint
#[tauri::command]
fn ciphers() -> HashMap<String, String> {
    let mut out = HashMap::new();
    if let Ok(entries) = fs::read_dir(enc_dir()) {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(fp) = name.strip_prefix("unlock-").and_then(|n| n.strip_suffix(".asc")) {
                if let Ok(text) = fs::read_to_string(e.path()) {
                    out.insert(fp.to_uppercase(), text);
                }
            }
        }
    }
    out
}

// ---- Schedule ----

#[tauri::command]
fn schedule() -> Result<serde_json::Value, String> {
    match fs::read_to_string(SCHEDULE_FILE) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("{SCHEDULE_FILE} is not valid JSON: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::json!({ "blocks": [] })),
        Err(e) => Err(format!("Couldn't read {SCHEDULE_FILE}: {e}")),
    }
}

// ---- History ----

const HISTORY_FILE: &str = "/var/lib/kblocker/history.jsonl";
const HISTORY_OPEN_FILE: &str = "/var/lib/kblocker/history-open.json";

/// Past blocks recorded by the scheduler daemon, oldest first. The block in
/// progress, if any, comes last with outcome "open".
#[tauri::command]
fn history() -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = fs::read_to_string(HISTORY_FILE)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if let Some(open) = fs::read_to_string(HISTORY_OPEN_FILE).ok().and_then(|s| serde_json::from_str(&s).ok()) {
        out.push(open);
    }
    out
}

// ---- Privileged actions ----

#[derive(Serialize)]
struct CtlOutput {
    stdout: String,
}

/// Runs kblockerctl as root through polkit and returns its stdout, or its
/// stderr as the error.
fn ctl(args: &[&str], stdin: Option<&str>) -> Result<CtlOutput, String> {
    let ctl = ctl_path();
    if !Path::new(&ctl).exists() {
        return Err(format!("kblockerctl isn't installed at {ctl}. Run sudo make install first."));
    }
    let mut child = Command::new("pkexec")
        .arg(&ctl)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Couldn't run pkexec: {e}"))?;
    if let (Some(input), Some(mut pipe)) = (stdin, child.stdin.take()) {
        pipe.write_all(input.as_bytes()).map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    match out.status.code() {
        Some(0) => Ok(CtlOutput { stdout }),
        Some(126) => Err("Authentication was cancelled.".into()),
        Some(127) if stderr.contains("Not authorized") || stderr.is_empty() => {
            Err("You aren't authorized to change kblocker settings.".into())
        }
        _ => Err(if stderr.is_empty() { stdout } else { stderr }),
    }
}

async fn ctl_async(args: Vec<String>, stdin: Option<String>) -> Result<CtlOutput, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        ctl(&refs, stdin.as_deref())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[derive(Serialize)]
struct EnableResult {
    /// Set for an unlocked (--insecure) block: the only copy of the key
    key: Option<String>,
}

#[tauri::command]
async fn enable(minutes: u32, insecure: bool) -> Result<EnableResult, String> {
    let mut args = vec!["enable".to_string(), minutes.to_string()];
    if insecure {
        args.push("--insecure".into());
    }
    let out = ctl_async(args, None).await?;
    let key = out
        .stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("Unload key:"))
        .map(|k| k.trim().to_string());
    Ok(EnableResult { key })
}

/// Stops the current block. With a key it authorizes a locked block; the key
/// travels over stdin so it never shows in the process list.
#[tauri::command]
async fn unblock(key: Option<String>) -> Result<(), String> {
    match key {
        Some(k) => ctl_async(vec!["unblock".into(), "--key".into(), "-".into()], Some(k)).await,
        None => ctl_async(vec!["disable".into()], None).await,
    }
    .map(|_| ())
}

#[tauri::command]
async fn unload(key: String) -> Result<(), String> {
    ctl_async(vec!["unload".into(), "--key".into(), "-".into()], Some(key)).await.map(|_| ())
}

#[tauri::command]
async fn set_domains(domains: Vec<String>, removed: Option<String>) -> Result<(), String> {
    if domains.is_empty() {
        // block needs at least one domain; clearing the last one is a remove
        let Some(last) = removed else { return Ok(()) };
        return ctl_async(vec!["remove".into(), last], None).await.map(|_| ());
    }
    let mut args = vec!["block".to_string()];
    args.extend(domains);
    ctl_async(args, None).await.map(|_| ())
}

/// Where the scheduler hosts the key holder pages: "off", "local", "lan" or
/// "custom" (which needs `bind`). The port is kept when `port` is None.
#[tauri::command]
async fn set_web_pages(mode: String, bind: Option<String>, port: Option<u16>) -> Result<(), String> {
    if !matches!(mode.as_str(), "off" | "local" | "lan" | "custom") {
        return Err(format!("Unknown setting: {mode}"));
    }
    let mut args = vec!["web-pages".to_string(), mode.clone()];
    if mode == "custom" {
        let ip: std::net::IpAddr = bind
            .as_deref()
            .unwrap_or("")
            .trim()
            .parse()
            .map_err(|_| "Enter an IP address, like 192.168.1.20.".to_string())?;
        args.extend(["--bind".into(), ip.to_string()]);
    }
    if let Some(p) = port {
        if p == 0 {
            return Err("The port must be between 1 and 65535.".into());
        }
        args.extend(["--port".into(), p.to_string()]);
    }
    ctl_async(args, None).await.map(|_| ())
}

#[tauri::command]
async fn reload() -> Result<(), String> {
    ctl_async(vec!["reload".into()], None).await.map(|_| ())
}

#[tauri::command]
async fn save_schedule(schedule: serde_json::Value) -> Result<(), String> {
    let json = serde_json::to_string(&schedule).map_err(|e| e.to_string())?;
    ctl_async(vec!["schedule".into(), "set".into(), "-".into()], Some(json)).await.map(|_| ())
}

fn temp_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}.asc", std::process::id()))
}

#[tauri::command]
async fn add_key_holder(public_key: String, name: String) -> Result<(), String> {
    let path = temp_path("kblocker-pub");
    fs::write(&path, &public_key).map_err(|e| format!("Couldn't stage the key: {e}"))?;
    let mut args = vec!["add-pgp".to_string(), path.to_string_lossy().to_string()];
    if !name.trim().is_empty() {
        args.push(name.trim().to_string());
    }
    let result = ctl_async(args, None).await;
    let _ = fs::remove_file(&path);
    result.map(|_| ())
}

#[tauri::command]
async fn remove_key_holder(fingerprint: String) -> Result<(), String> {
    ctl_async(vec!["remove-pgp".into(), fingerprint], None).await.map(|_| ())
}

// ---- Local files the user picks through the dialog plugin ----

#[tauri::command]
fn read_text_file(path: String) -> Result<String, String> {
    let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
    if meta.len() > 1 << 20 {
        return Err("That file is too large to be a PGP key.".into());
    }
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

/// Writes a file only the current user can read (used for private keys)
#[tauri::command]
fn write_private_file(path: String, contents: String) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| e.to_string())?;
    f.write_all(contents.as_bytes()).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            status,
            key_holders,
            cipher_for,
            ciphers,
            schedule,
            history,
            enable,
            unblock,
            unload,
            set_domains,
            reload,
            set_web_pages,
            save_schedule,
            add_key_holder,
            remove_key_holder,
            read_text_file,
            write_private_file,
        ])
        .run(tauri::generate_context!())
        .expect("error while running kblocker");
}
