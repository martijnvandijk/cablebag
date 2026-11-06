//! RDP tabs. On Windows each tab runs one `cablebag-rdp` helper process that hosts the Windows
//! Remote Desktop control as a child window of the Cablebag window; this module starts it and
//! passes commands. On other platforms the IronRDP engine runs in this process and draws into the
//! tab's canvas, with the same binary frame messages as [`crate::vnc`].

use crate::prompt::{button, field, PromptRequest};
use crate::ssh::{self, Hop};
use crate::store::Session;
use crate::term::{Sink, TermOut};
use crate::tunnel;
use crate::AppState;
use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use serde::Serialize;
use serde_json::{json, Value};
use std::any::Any;
use std::collections::HashMap;
#[cfg(windows)]
use std::io::Write;
#[cfg(windows)]
use std::io::{BufRead, BufReader};
#[cfg(windows)]
use std::path::PathBuf;
#[cfg(windows)]
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

#[cfg(windows)]
pub struct RdpProc {
    stdin: Mutex<ChildStdin>,
    child: Mutex<Child>,
    /// The SSH gateway or WireGuard port the control connects through, kept open as long as the session.
    _tunnel: Option<Box<dyn std::any::Any + Send + Sync>>,
}

#[cfg(windows)]
impl RdpProc {
    pub fn send(&self, v: &Value) {
        let mut w = self.stdin.lock();
        let _ = writeln!(w, "{v}");
        let _ = w.flush();
    }
}

#[cfg(windows)]
impl Drop for RdpProc {
    fn drop(&mut self) {
        self.send(&json!({"cmd": "quit"}));
        let mut c = self.child.lock();
        std::thread::sleep(Duration::from_millis(150));
        let _ = c.kill();
    }
}

/// A live tab: the helper process (Windows) or the engine task (elsewhere).
enum Backend {
    #[cfg(windows)]
    Helper(Arc<RdpProc>),
    #[cfg(not(windows))]
    Engine(tokio::sync::mpsc::UnboundedSender<Value>),
}

impl Backend {
    fn send(&self, v: &Value) {
        match self {
            #[cfg(windows)]
            Backend::Helper(p) => p.send(v),
            #[cfg(not(windows))]
            Backend::Engine(tx) => {
                let _ = tx.send(v.clone());
            }
        }
    }
}

#[cfg(not(windows))]
impl Drop for Backend {
    /// Asks the engine to end the session politely; like the helper, give it a moment to flush.
    fn drop(&mut self) {
        self.send(&json!({"cmd": "quit"}));
        std::thread::sleep(Duration::from_millis(150));
    }
}

#[derive(Default)]
pub struct Rdps {
    map: Mutex<HashMap<String, Backend>>,
    /// Requests from the assistant (a picture, a click, keys), by id, waiting for the helper's reply.
    pending: Mutex<HashMap<String, tokio::sync::oneshot::Sender<Value>>>,
}

impl Rdps {
    pub fn send(&self, id: &str, v: Value) {
        if let Some(p) = self.map.lock().get(id) {
            p.send(&v);
        }
    }
    pub fn remove(&self, id: &str) {
        self.map.lock().remove(id);
    }
    /// Sends a request from the assistant to the helper and waits for its reply.
    pub async fn request(&self, id: &str, mut cmd: Value) -> Result<Value> {
        let req = uuid::Uuid::new_v4().to_string();
        cmd["req"] = json!(req);
        let (tx, rx) = tokio::sync::oneshot::channel();
        {
            let map = self.map.lock();
            let p = map.get(id).ok_or_else(|| anyhow!("This Remote Desktop tab is not open."))?;
            self.pending.lock().insert(req.clone(), tx);
            p.send(&cmd);
        }
        let got = tokio::time::timeout(Duration::from_secs(15), rx).await;
        self.pending.lock().remove(&req);
        let v = got
            .map_err(|_| anyhow!("The remote screen did not answer in time."))?
            .map_err(|_| anyhow!("The Remote Desktop tab closed."))?;
        if let Some(e) = v["error"].as_str() {
            return Err(anyhow!(e.to_string()));
        }
        Ok(v)
    }

    /// A picture of the remote screen as it shows now (a JPEG data URL), for the assistant.
    pub async fn snapshot(&self, id: &str) -> Result<String> {
        let v = self.request(id, json!({"cmd": "snapshot"})).await?;
        Ok(format!("data:image/jpeg;base64,{}", s(&v, "image")))
    }

    fn replied(&self, v: Value) {
        if let Some(tx) = self.pending.lock().remove(&s(&v, "req")) {
            let _ = tx.send(v);
        }
    }

    /// Ends every helper (each one quits and is stopped as it is dropped), before an update replaces its file.
    pub fn close_all(&self) {
        self.map.lock().clear();
    }
}

#[derive(Clone, Serialize)]
struct RdpEvent {
    id: String,
    event: String,
    text: String,
    data: Value,
}

struct Log<'a> {
    app: &'a AppHandle,
    id: &'a str,
}

impl Sink for Log<'_> {
    fn info(&self, text: &str) {
        emit(self.app, self.id, "log", text, Value::Null);
    }
    fn error(&self, text: &str) {
        emit(self.app, self.id, "log", text, Value::Null);
    }
}

fn emit(app: &AppHandle, id: &str, event: &str, text: &str, data: Value) {
    let _ = app.emit("rdp-event", RdpEvent { id: id.into(), event: event.into(), text: text.into(), data });
}

fn status(app: &AppHandle, id: &str, state: &str, message: &str) {
    let _ = app.emit("term-status", json!({"id": id, "state": state, "message": message}));
}

#[cfg(windows)]
fn helper_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("CABLEBAG_RDP_HELPER") {
        return Ok(PathBuf::from(p));
    }
    let exe_dir = std::env::current_exe()?.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rdp-helper/publish/cablebag-rdp.exe");
    // Development builds use the freshly published helper, not the copy the bundler left next to the exe.
    let order = if cfg!(debug_assertions) {
        vec![dev, exe_dir.join("cablebag-rdp.exe")]
    } else {
        vec![exe_dir.join("cablebag-rdp.exe"), exe_dir.join("rdp").join("cablebag-rdp.exe"), dev]
    };
    for p in order {
        if p.exists() {
            return Ok(p);
        }
    }
    Err(anyhow!("The RDP helper (cablebag-rdp.exe) was not found next to Cablebag."))
}

/// The web view does not clip its siblings, so it would paint over the RDP window placed on top of it.
/// Turn on clipping for the main window and every direct child.
#[cfg(windows)]
fn clip_children(hwnd: i64) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindow, GetWindowLongPtrW, SetWindowLongPtrW, SetWindowPos, GWL_STYLE, GW_CHILD, GW_HWNDNEXT,
        SWP_FRAMECHANGED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, WS_CLIPCHILDREN, WS_CLIPSIBLINGS,
    };
    unsafe {
        let main = HWND(hwnd as isize as *mut core::ffi::c_void);
        let style = GetWindowLongPtrW(main, GWL_STYLE);
        SetWindowLongPtrW(main, GWL_STYLE, style | WS_CLIPCHILDREN.0 as isize);
        let mut child = GetWindow(main, GW_CHILD).ok();
        while let Some(c) = child {
            let s = GetWindowLongPtrW(c, GWL_STYLE);
            if s & WS_CLIPSIBLINGS.0 as isize == 0 {
                SetWindowLongPtrW(c, GWL_STYLE, s | WS_CLIPSIBLINGS.0 as isize);
                let _ = SetWindowPos(
                    c,
                    None,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED | SWP_NOACTIVATE,
                );
            }
            child = GetWindow(c, GW_HWNDNEXT).ok();
        }
    }
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

/// On Windows the helper places its window with x, y and scale; the engine only sizes the desktop.
#[allow(dead_code)]
pub struct Geometry {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
    pub scale: u32,
}

/// Everything before "start the session": PSM, the optional SSH gateway or WireGuard forward, and
/// the credential lookup with its prompt. The forward is returned so the caller keeps it open as
/// long as the connection.
struct Resolved {
    host: String,
    port: u16,
    /// The address as the session names it (the gateway or tunnel forwards replace host and port).
    target: String,
    target_port: u16,
    user: String,
    domain: String,
    password: String,
    /// Log in on the remote screen (no NLA): the server shows its own prompt.
    login_remote: bool,
    options: Value,
    _tunnel: Option<Box<dyn Any + Send + Sync>>,
}

/// Returned in place of an error when the person (or the flow) ended the attempt by cancelling.
#[derive(Debug)]
struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("cancelled")
    }
}

impl std::error::Error for Cancelled {}

async fn resolve(app: &AppHandle, id: &str, session: &Session) -> Result<Resolved> {
    let state = app.state::<AppState>();
    let mut host = session.host.trim().to_string();
    let mut port = if session.port > 0 { session.port as u16 } else { 3389 };
    let mut user = session.username.clone();
    let mut domain = s(&session.data, "domain");
    let mut options = session.data.clone();
    status(app, id, "connecting", "");

    // Through CyberArk PSM: the connection goes to the PSM server, which logs in to the target itself.
    let mut psm_password = None;
    // "none": directly, even when a folder above goes through PSM.
    let psm = Some(s(&session.data, "psm")).filter(|p| p != "none").unwrap_or_default();
    if !psm.is_empty() {
        let (cfg, b) = state.creds.cyberark(app, &psm)?;
        let crate::sources::Backend::CyberArk(ca) = &*b else { anyhow::bail!("The PSM source is not a CyberArk source.") };
        // The linked CyberArk account, when it is one of this source's.
        let item = s(&session.data, "vault_item");
        let account = match crate::sources::parse_ref(&item) {
            (Some(src), a) if src == cfg.id && !a.is_empty() => Some(a.to_string()),
            _ => None,
        };
        let mut target_user = user.clone();
        if target_user.is_empty() && account.is_some() {
            if let Some(i) = state.creds.items(app).into_iter().find(|i| i.id == item) {
                target_user = i.username;
            }
        }
        let p = match crate::sources::cyberark::psm_rdp(ca, app, &cfg, account.as_deref(), &target_user, &host).await {
            Ok(p) => p,
            Err(e) => {
                status(app, id, "failed", &e.to_string());
                return Err(anyhow!("CyberArk PSM: {e}"));
            }
        };
        emit(app, id, "log", &format!("Through CyberArk PSM ({}).", p.host), Value::Null);
        host = p.host;
        port = if p.port > 0 { p.port } else { 3389 };
        user = p.user;
        domain = p.domain;
        psm_password = Some(p.password);
        if let Some(o) = options.as_object_mut() {
            o.insert("remote_program".into(), Value::String(p.remote_program));
            o.insert("load_balance_info".into(), Value::String(p.load_balance_info));
        }
    }
    let (target, target_port) = (host.clone(), port);

    // Optional SSH gateway: forward a local port to the RDP server through SSH first.
    let mut fwd = None;
    if let Some(gw) = session.data.get("ssh_gateway").filter(|g| !s(g, "host").is_empty()) {
        let hop = Hop {
            via_wg: crate::wg::of(session).unwrap_or_default(),
            agent_forward: false,
            host: s(gw, "host"),
            port: gw.get("port").and_then(|p| p.as_u64()).unwrap_or(22) as u16,
            user: s(gw, "user"),
            key_path: s(gw, "key_path"),
            vault_item: s(gw, "vault_item"),
            session_id: String::new(),
            name: String::new(),
            ..Default::default()
        };
        let log = Log { app, id };
        log.info(&format!("Opening SSH gateway {}...", hop.host));
        let conn = Arc::new(ssh::connect_chain(app, &[hop], true, &log).await?);
        let f = tunnel::local_forward(conn, 0, host.clone(), port).await?;
        host = "127.0.0.1".into();
        port = f.port;
        fwd = Some(Box::new(f) as Box<dyn std::any::Any + Send + Sync>);
    } else if let Some(wg) = crate::wg::of(session) {
        let log = Log { app, id };
        log.info("Opening the WireGuard tunnel...");
        let f = crate::wg::local_forward(app, &wg, &host, port).await?;
        host = "127.0.0.1".into();
        port = f.port;
        fwd = Some(Box::new(f));
    }

    // Password: from a linked credential source login, saved in Cablebag, or asked once. Through PSM it is
    // whatever PSM gave (often nothing: PSM asks, or logs in by itself).
    let vault_host = session.host.trim().to_string();
    let mut from_vw = None;
    let item = if psm.is_empty() { s(&session.data, "vault_item") } else { String::new() };
    if let Some(pw) = psm_password {
        from_vw = Some(pw);
    } else if !item.is_empty() {
        match state.creds.login(app, &item).await {
            Ok((u, pw)) => {
                if user.is_empty() {
                    user = u;
                }
                if !pw.is_empty() {
                    from_vw = Some(pw);
                }
            }
            Err(e) => emit(app, id, "log", &format!("Vault: {e}"), Value::Null),
        }
    }
    let mut saved = match from_vw {
        Some(pw) => Some(pw),
        None => state.vault.password(&state.store.lock(), "rdp", &vault_host, session.port, &user).ok().flatten(),
    };
    // No linked login: the vault may still have one for this host.
    if saved.is_none() && item.is_empty() && psm.is_empty() {
        match state.creds.pick_login(app, "rdp", &vault_host, &user, &session.name).await {
            Ok(Some((found, name, u, pw))) if !pw.is_empty() => {
                if user.is_empty() {
                    user = u;
                }
                emit(app, id, "log", &format!("Using the vault login \"{name}\"."), Value::Null);
                crate::sources::link_session(app, &session.id, &found);
                saved = Some(pw);
            }
            Ok(_) => {}
            Err(_) => {
                status(app, id, "closed", "Login cancelled.");
                return Err(Cancelled.into());
            }
        }
    }
    let mut login_remote = false;
    let password = match saved {
        Some(p) => p,
        None if !user.is_empty() => {
            let ans = state
                .prompts
                .ask(
                    app,
                    PromptRequest {
                        id: String::new(),
                        title: format!("Log in to {vault_host}"),
                        message: format!("Password for {user} on {vault_host}"),
                        details: vec![],
                        fields: vec![
                            field("secret", "Password", "password", Value::String(String::new())),
                            field("save", "Remember in the password vault", "checkbox", Value::Bool(false)),
                        ],
                        buttons: vec![
                            button("ok", "Connect", "primary"),
                            button("remote", "Log in on the remote screen", "normal"),
                            button("cancel", "Cancel", "normal"),
                        ],
                        warning: false,
                    },
                )
                .await;
            match ans.button.as_str() {
                "ok" => {
                    let pw = ans.text("secret");
                    if ans.flag("save") {
                        let _ = state.vault.save_password(&state.store.lock(), "rdp", &vault_host, session.port, &user, &pw);
                    }
                    pw
                }
                "remote" => {
                    login_remote = true;
                    String::new()
                }
                _ => {
                    status(app, id, "closed", "Login cancelled.");
                    return Err(Cancelled.into());
                }
            }
        }
        None => String::new(),
    };

    Ok(Resolved { host, port, target, target_port, user, domain, password, login_remote, options, _tunnel: fwd })
}

/// The helper is a Windows program hosted inside Cablebag's window.
#[cfg(windows)]
pub async fn open(app: AppHandle, id: String, session: Session, geo: Geometry, _out: TermOut) -> Result<()> {
    let state = app.state::<AppState>();
    let r = match resolve(&app, &id, &session).await {
        Ok(r) => r,
        Err(e) if e.downcast_ref::<Cancelled>().is_some() => return Ok(()),
        Err(e) => return Err(e),
    };

    // get_window, not get_webview_window: with web tabs open the window holds more than one webview, and then
    // get_webview_window("main") finds nothing.
    let window = app.get_window("main").ok_or_else(|| anyhow!("main window missing"))?;
    let hwnd = window.hwnd()?.0 as isize as i64;
    clip_children(hwnd);
    let mut cmd = Command::new(helper_path()?);
    cmd.args(["--parent", &hwnd.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = cmd.spawn().map_err(|e| anyhow!("Could not start the RDP helper: {e}"))?;
    let stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin"))?;
    let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout"))?;
    let proc_ = Arc::new(RdpProc { stdin: Mutex::new(stdin), child: Mutex::new(child), _tunnel: r._tunnel });

    let app2 = app.clone();
    let id2 = id.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            let ev = s(&v, "event");
            // A reply to the assistant goes to whoever asked for it, not to the window as an event.
            if ev == "reply" {
                app2.state::<AppState>().rdp.replied(v);
                continue;
            }
            match ev.as_str() {
                "connecting" => status(&app2, &id2, "connecting", ""),
                "connected" | "login" => status(&app2, &id2, "connected", ""),
                "disconnected" => status(&app2, &id2, "closed", &s(&v, "text")),
                "fatal" => status(&app2, &id2, "failed", "The remote desktop control reported a fatal error."),
                "error" => status(&app2, &id2, "failed", &s(&v, "text")),
                _ => {}
            }
            emit(&app2, &id2, &ev, &s(&v, "text"), v);
        }
        status(&app2, &id2, "closed", "");
    });

    proc_.send(&json!({"cmd": "bounds", "x": geo.x, "y": geo.y, "w": geo.w, "h": geo.h}));
    proc_.send(&json!({
        "cmd": "connect",
        "host": r.host,
        "port": r.port,
        "user": r.user,
        "domain": r.domain,
        "password": r.password,
        "width": geo.w,
        "height": geo.h,
        "scale": geo.scale,
        "options": r.options,
    }));
    state.rdp.map.lock().insert(id, Backend::Helper(proc_));
    Ok(())
}

#[cfg(not(windows))]
pub async fn open(app: AppHandle, id: String, session: Session, geo: Geometry, out: TermOut) -> Result<()> {
    let state = app.state::<AppState>();
    let r = match resolve(&app, &id, &session).await {
        Ok(r) => r,
        Err(e) if e.downcast_ref::<Cancelled>().is_some() => return Ok(()),
        Err(e) => return Err(e),
    };
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    state.rdp.map.lock().insert(id.clone(), Backend::Engine(tx));
    // Its own current-thread runtime per tab: the IronRDP session futures capture reference
    // arguments across awaits, which rustc cannot prove Send through the crate boundary
    // (rust-lang/rust#96605), and like the Windows helper process the engine is one quiet thread.
    std::thread::spawn(move || {
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
            rt.block_on(engine(app, id, r, out, geo, rx));
        }
    });
    Ok(())
}

#[cfg(not(windows))]
mod engine;

/// One session until it ends: connect, then copy damage to the canvas and input to the server.
#[cfg(not(windows))]
async fn engine(app: AppHandle, id: String, r: Resolved, out: TermOut, geo: Geometry, rx: tokio::sync::mpsc::UnboundedReceiver<Value>) {
    match engine::run(app.clone(), id.clone(), r, out.clone(), geo, rx).await {
        Ok(()) => status(&app, &id, "closed", ""),
        Err(e) => {
            emit(&app, &id, "log", &e.to_string(), Value::Null);
            status(&app, &id, "failed", &e.to_string());
        }
    }
    // The forward may only end after the connection that used it.
    app.state::<AppState>().rdp.map.lock().remove(&id);
}
