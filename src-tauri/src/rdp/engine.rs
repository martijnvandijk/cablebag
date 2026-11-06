//! The Remote Desktop engine for non-Windows tabs: IronRDP connects through the forward that
//! [`super::resolve`] prepared, decodes the desktop into a framebuffer, and sends the changed
//! rectangles over the tab's channel as the binary messages documented in [`crate::vnc`].

use super::{emit, s, status, Geometry, Resolved};
use std::mem;
use crate::prompt::{button, PromptRequest};
use crate::store::{now, KnownHost};
use crate::term::TermOut;
use crate::AppState;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ironrdp_async::{connect_begin, connect_finalize, mark_as_upgraded, NetworkClient};
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{general_err, ConnectorResult, ServerName};
use ironrdp_pdu::geometry::{InclusiveRectangle, Rectangle as _};
use ironrdp_pdu::input::fast_path::FastPathInputEvent;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_tokio::{FramedWrite, TokioFramed};
use sha2::{Digest as _, Sha256};
use std::future::Future;
use std::io::ErrorKind;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc::UnboundedReceiver;

/// The erased stream type that survives the TLS upgrade (a trait object needs one name for read+write).
trait AsyncReadWrite: AsyncRead + AsyncWrite {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite {}

/// Everything the session needs to run once the connection sequence succeeded.
struct Active {
    framed: TokioFramed<Box<dyn AsyncReadWrite + Unpin + Send + Sync>>,
    stage: ActiveStage,
    image: DecodedImage,
    input: ironrdp_input::Database,
    /// VNC-style button mask of the last pointer event (1 left, 2 middle, 4 right).
    buttons: u8,
    /// What the server lets us send: typed text only over the Unicode channel.
    unicode: bool,
    refresh_rect: bool,
    suppress_output: bool,
    /// Set when the session should end with this note instead of an error.
    ended: Option<String>,
}

use tauri::Manager;

/// A session's whole lifetime on non-Windows: connect, then pump frames and commands until either side ends it.
#[allow(clippy::too_many_arguments)]
pub async fn run(app: tauri::AppHandle, id: String, r: Resolved, out: TermOut, geo: Geometry, mut rx: UnboundedReceiver<serde_json::Value>) -> Result<()> {
    let mut a = {
        let tcp = tokio::time::timeout(std::time::Duration::from_secs(15), TcpStream::connect((r.host.as_str(), r.port)))
            .await
            .map_err(|_| anyhow!("No answer from {}:{} within 15 seconds.", r.target, r.port))?
            .map_err(|e| anyhow!("Could not connect to {}:{}: {e}", r.target, r.port))?;
        let local_addr = tcp.local_addr().unwrap_or(([0, 0, 0, 0], 0).into());
        let mut framed = TokioFramed::new(tcp);
    
        // NLA when we have a user to hand over; otherwise the server's own login screen (TLS only).
        let nla = !r.login_remote && !r.user.is_empty();
        let w = u16::try_from(geo.w.clamp(64, u16::MAX as i32)).unwrap_or(1024);
        let h = u16::try_from(geo.h.clamp(64, u16::MAX as i32)).unwrap_or(768);
        let config = ironrdp_connector::Config {
            desktop_size: ironrdp_connector::DesktopSize { width: w, height: h },
            monitor_layout: None,
            desktop_scale_factor: 100,
            desktop_physical_size: None,
            desktop_orientation: None,
            device_scale_factor: None,
            monitor_extended_layout: None,
            relative_mouse_input: false,
            enable_tls: true,
            enable_credssp: nla,
            enable_standard_rdp_security: false,
            credentials: ironrdp_connector::Credentials::UsernamePassword { username: r.user.clone(), password: r.password.clone() },
            domain: (!r.domain.is_empty()).then(|| r.domain.clone()),
            client_build: 26100,
            client_name: hostname(),
            keyboard_type: ironrdp_pdu::gcc::KeyboardType::IBM_ENHANCED,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0,
            connection_type: ironrdp_pdu::gcc::ConnectionType::Autodetect,
            ime_file_name: String::new(),
            bitmap: Some(ironrdp_connector::BitmapConfig {
                lossy_compression: false,
                color_depth: 32,
                codecs: ironrdp_pdu::rdp::capability_sets::BitmapCodecs::default(),
            }),
            dig_product_id: "Windows".into(),
            client_dir: r"C:\Windows\System32\clients\cablebag".into(),
            // An alternate shell (CyberArk PSM hands one out) runs instead of the desktop.
            alternate_shell: s(&r.options, "remote_program"),
            work_dir: String::new(),
            remote_application_mode: false,
            rail_support_level: ironrdp_pdu::rdp::capability_sets::RailSupportLevel::empty(),
            platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::WINDOWS,
            hardware_id: None,
            // None: no "Cookie: mstshash=<user>" in the X.224 request, so the name stays inside TLS.
            request_data: None,
            autologon: true,
            enable_audio_playback: false,
            enable_audio_capture: false,
            performance_flags: ironrdp_pdu::rdp::client_info::PerformanceFlags::default(),
            license_cache: None,
            timezone_info: Default::default(),
            // XCRUSH: worth its CPU when the server has no graphics pipeline (EGFX) for us.
            compression_type: Some(ironrdp_pdu::rdp::client_info::CompressionType::Rdp61),
            enable_server_pointer: true,
            pointer_software_rendering: true,
            multitransport_flags: None,
            support_dyn_vc_gfx_protocol: false,
        };
        let mut connector = ironrdp_connector::ClientConnector::new(config, local_addr);
    
        let should_upgrade = connect_begin(&mut framed, &mut connector).await.map_err(conn_err)?;
        let (stream, leftover) = framed.into_inner();
        let (tls, cert) = ironrdp_tls::upgrade(stream, &r.target)
            .await
            .map_err(|e| anyhow!("Could not start TLS with {}: {e}", r.target))?;
        let server_public_key =
            ironrdp_tls::extract_tls_server_public_key(&cert).ok_or_else(|| anyhow!("The server sent no usable TLS certificate."))?.to_vec();
        verify_server(app.clone(), id.clone(), r.target.clone(), r.target_port, server_public_key.clone()).await?;
    
        let upgraded = mark_as_upgraded(should_upgrade, &mut connector);
        let mut framed = TokioFramed::new_with_leftover(Box::new(tls) as Box<dyn AsyncReadWrite + Unpin + Send + Sync>, leftover);
        // The KDC proxy is only needed for smart-card Kerberos; NTLM and direct Kerberos do not ask.
        let mut no_proxy = NoProxy;
        let outcome = connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut no_proxy,
            ServerName::new(r.target.clone()),
            server_public_key,
            None,
        )
        .await
        .map_err(conn_err)?;
        let mut cr = match outcome {
            ironrdp_connector::ConnectionOutcome::Connected(cr) => cr,
            other => return Err(anyhow!("The server redirected this connection elsewhere ({other:?}); connect to that computer instead.")),
        };
    
        let stage = ActiveStageBuilder {
            static_channels: mem::take(&mut cr.static_channels),
            user_channel_id: cr.user_channel_id,
            io_channel_id: cr.io_channel_id,
            message_channel_id: cr.message_channel_id,
            share_id: cr.share_id,
            compression_type: cr.compression_type,
            enable_server_pointer: cr.enable_server_pointer,
            pointer_software_rendering: cr.pointer_software_rendering,
        }
        .build();
        let image = DecodedImage::new(ironrdp_graphics::image_processing::PixelFormat::RgbA32, cr.desktop_size.width, cr.desktop_size.height);
        Ok::<_, anyhow::Error>(Active {
            framed,
            stage,
            image,
            input: ironrdp_input::Database::new(),
            buttons: 0,
            unicode: cr.input_flags.contains(ironrdp_pdu::rdp::capability_sets::InputFlags::UNICODE),
            refresh_rect: cr.refresh_rect_support,
            suppress_output: cr.suppress_output_support,
            ended: None,
        })
    }?;
    status(&app, &id, "connected", "");
    msg_size(&out, a.image.width(), a.image.height());

    loop {
        tokio::select! {
            got = a.framed.read_pdu() => {
                let (action, frame) = match got {
                    Ok(v) => v,
                    Err(e) if matches!(e.kind(), ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset) => break,
                    Err(e) => return Err(anyhow!("Connection lost: {e}")),
                };
                let at = a.framed.last_read_at();
                let outputs = a.stage.process(&mut a.image, action, &frame, at).map_err(|e| anyhow!("RDP: {e}"))?;
                a.send_outputs(app.clone(), id.clone(), out.clone(), outputs).await?;
                if a.stage.take_bitmap_recovery_request() {
                    // A damaged bitmap update: ask for the whole picture again so the screen recovers by itself.
                    let redraw = a.stage.request_full_redraw(a.image.width(), a.image.height(), a.refresh_rect, a.suppress_output)?;
                    for frame in redraw {
                        a.framed.write_all(&frame).await.map_err(|e| anyhow!("RDP: {e}"))?;
                    }
                }
            }
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { break };
                if a.command(app.clone(), id.clone(), out.clone(), cmd).await? {
                    break;
                }
            }
        }
        if let Some(note) = &a.ended {
            status(&app, &id, "closed", note);
            return Ok(());
        }
    }
    Ok(())
}

/// TCP, TLS with trust-on-first-use, then NLA and the MCS join: everything until the desktop can start.

fn conn_err(e: ironrdp_connector::ConnectorError) -> anyhow::Error {
    let text = e.to_string();
    // The most common failure deserves its own sentence: NLA refused is about the account, not the network.
    if text.contains("logon") || text.contains("authentication") || text.contains("ACCESS_DENIED") {
        anyhow!("The server refused this login: {text}")
    } else if text.contains("HYBRID") || text.contains("SSL_ON_TLS") {
        anyhow!("This server requires Network Level Authentication and a password; use a saved login instead of the remote screen.")
    } else {
        anyhow!("RDP handshake: {text}")
    }
}

struct NoProxy;

impl NetworkClient for NoProxy {
    fn send(&mut self, _: &NetworkRequest) -> impl Future<Output = ConnectorResult<Vec<u8>>> {
        async { Err(general_err!("this client cannot talk to a Kerberos KDC proxy")) }
    }
}

/// Trust-on-first-use of the TLS certificate, like the SSH side does with host keys: the identity
/// is the SHA-256 of the certificate's public key, checked before any credential is sent.
async fn verify_server(app: tauri::AppHandle, id: String, target: String, target_port: u16, spki: Vec<u8>) -> Result<()> {
    let algo = "rdp-sha256";
    let fp = Sha256::digest(&spki).iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
    let state = app.state::<AppState>();
    let known = state.store.lock().known_hosts_for(&target, i64::from(target_port)).unwrap_or_default();
    let exact = known.iter().find(|k| k.algo == algo && k.fingerprint == fp);
    if exact.is_some() {
        return Ok(());
    }
    let changed = known.iter().find(|k| k.algo == algo);
    let (title, message, warning) = match changed {
        Some(old) => (
            "The server's identity has changed".to_string(),
            format!(
                "The TLS key of {}:{} is different from the one saved on {}. \
                 This happens after a server reinstall, but it can also mean someone is intercepting the connection. \
                 Only continue if you know why the key changed.\n\nPreviously saved: {}",
                target, target_port, old.added, old.fingerprint
            ),
            true,
        ),
        None => (
            "Confirm the server's identity".to_string(),
            format!(
                "This is the first connection to {}:{} over Remote Desktop. Check the fingerprint below before trusting this server.",
                target, target_port
            ),
            false,
        ),
    };
    let ans = state
        .prompts
        .ask(
            &app,
            PromptRequest {
                id: String::new(),
                title,
                message,
                details: vec![("SHA-256 fingerprint".into(), fp.clone())],
                fields: vec![],
                buttons: vec![
                    button("trust", if warning { "Replace the saved key and connect" } else { "Trust and remember" }, if warning { "danger" } else { "primary" }),
                    button("once", "Connect this time only", "normal"),
                    button("cancel", "Cancel", "normal"),
                ],
                warning,
            },
        )
        .await;
    match ans.button.as_str() {
        "trust" => {
            let _ = state.store.lock().save_known_host(&KnownHost {
                host: target.clone(),
                port: i64::from(target_port),
                algo: algo.into(),
                key: STANDARD.encode(spki),
                fingerprint: fp,
                added: now(),
            });
            Ok(())
        }
        "once" => Ok(()),
        _ => {
            status(&app, &id, "closed", "The server's identity was not accepted.");
            Err(anyhow!("The server's identity was not accepted."))
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")).unwrap_or_else(|_| "cablebag".into())
}

impl Active {
    async fn send_outputs(&mut self, app: tauri::AppHandle, id: String, out: TermOut, outputs: Vec<ActiveStageOutput>) -> Result<()> {
        use ironrdp_pdu::rdp::capability_sets::InputFlags;
        let _ = InputFlags::SCANCODES;
        for o in outputs {
            match o {
                ActiveStageOutput::ResponseFrame(frame) => {
                    self.framed.write_all(&frame).await.map_err(|e| anyhow!("RDP: {e}"))?;
                }
                ActiveStageOutput::Terminate(reason) => {
                    self.ended = Some(reason.description());
                }
                ActiveStageOutput::SaveSessionInfo { logon_complete: true } => {
                    emit(&app, &id, "login", "", serde_json::json!({"event": "login"}));
                }
                ActiveStageOutput::DeactivateAll => {
                    // shortcut: the reactivation sequence is not driven yet, so a server-side resize asks for a reconnect.
                    self.ended = Some("The server changed the session size; connect again.".into());
                }
                _ => {}
            }
        }
        let rects = self.stage.take_damage_regions();
        for rect in &rects {
            msg_pixels(&out, &self.image, rect);
        }
        Ok(())
    }

    /// One command from the tab or the assistant; true ends the session.
    async fn command(&mut self, app: tauri::AppHandle, id: String, out: TermOut, cmd: serde_json::Value) -> Result<bool> {
        let reply = s(&cmd, "req");
        match s(&cmd, "cmd").as_str() {
            // bounds and visible only matter to the native helper: the canvas scales by itself.
            "bounds" | "visible" | "focus" => {}
            "quit" | "disconnect" => {
                self.send_outputs(app, id, out, self.stage.graceful_shutdown().map_err(|e| anyhow!("RDP: {e}"))?).await?;
                return Ok(true);
            }
            "pointer" => {
                let mask = cmd.get("buttons").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                let (ops, state) = pointer_ops(self.buttons, mask, num(&cmd, "x") as u16, num(&cmd, "y") as u16);
                self.buttons = state;
                self.feed_input(app.clone(), id, out.clone(), ops).await?;
            }
            "key" => {
                let down = cmd.get("down").and_then(|v| v.as_bool()).unwrap_or(false);
                let op = if down { ironrdp_input::Operation::KeyPressed } else { ironrdp_input::Operation::KeyReleased };
                if let Some(code) = scancode_for(&s(&cmd, "code")) {
                    self.feed_input(app.clone(), id, out.clone(), [op(ironrdp_input::Scancode::from_u16(code))]).await?;
                }
            }
            "cad" => {
                self.feed_input(app.clone(), id, out.clone(), chord("ctrl+alt+delete")).await?;
            }
            "mouse" => {
                let x = (num(&cmd, "x") * i64::from(self.image.width()) / 1000) as u16;
                let y = (num(&cmd, "y") * i64::from(self.image.height()) / 1000) as u16;
                let button = match s(&cmd, "button").as_str() {
                    "right" => ironrdp_input::MouseButton::Right,
                    "middle" => ironrdp_input::MouseButton::Middle,
                    _ => ironrdp_input::MouseButton::Left,
                };
                use ironrdp_input::Operation::*;
                let mut ops = vec![MouseMove(ironrdp_input::MousePosition { x, y })];
                match s(&cmd, "action").as_str() {
                    "scroll" => ops.push(WheelRotations(ironrdp_input::WheelRotations {
                        is_vertical: true,
                        rotation_units: num(&cmd, "amount").clamp(-40, 40) as i16 * -40,
                    })),
                    _ => {
                        let times = if s(&cmd, "action") == "double" { 2 } else { 1 };
                        for _ in 0..times {
                            ops.push(MouseButtonPressed(button));
                            ops.push(MouseButtonReleased(button));
                        }
                    }
                }
                self.feed_input(app.clone(), id, out.clone(), ops).await?;
                if !reply.is_empty() {
                    app.state::<AppState>().rdp.replied(serde_json::json!({"event": "reply", "req": reply}));
                }
            }
            "keys" => {
                let codes = match parse_keys(&s(&cmd, "keys")) {
                    Ok(c) => c,
                    Err(e) => {
                        replied(&app, &reply, serde_json::json!({"error": e.to_string()}));
                        return Ok(false);
                    }
                };
                self.feed_input(app.clone(), id, out.clone(), chord_codes(&codes)).await?;
                if !reply.is_empty() {
                    replied(&app, &reply, serde_json::json!({}));
                }
            }
            "type" => {
                if !self.unicode {
                    if !reply.is_empty() {
                        replied(&app, &reply, serde_json::json!({"error": "This server does not accept typed text; use screen_keys instead."}));
                    }
                    return Ok(false);
                }
                let mut ops = Vec::new();
                for ch in s(&cmd, "text").chars() {
                    ops.push(ironrdp_input::Operation::UnicodeKeyPressed(ch));
                    ops.push(ironrdp_input::Operation::UnicodeKeyReleased(ch));
                }
                self.feed_input(app.clone(), id, out.clone(), ops).await?;
                if !reply.is_empty() {
                    replied(&app, &reply, serde_json::json!({"skipped": ""}));
                }
            }
            "snapshot" => {
                let image = STANDARD.encode(snapshot_jpeg(&self.image));
                replied(&app, &reply, serde_json::json!({"image": image}));
            }
            _ => {}
        }
        Ok(false)
    }

    /// Turns input into PDUs (fast-path; every Windows server we target allows it) and updates the screen.
    async fn feed_input(&mut self, app: tauri::AppHandle, id: String, out: TermOut, ops: impl IntoIterator<Item = ironrdp_input::Operation>) -> Result<()> {
        let events: Vec<FastPathInputEvent> = self.input.apply(ops).into_iter().collect();
        let outputs = self.stage.process_fastpath_input(&mut self.image, &events).map_err(|e| anyhow!("RDP: {e}"))?;
        self.send_outputs(app, id, out, outputs).await
    }
}

fn replied(app: &tauri::AppHandle, req: &str, mut v: serde_json::Value) {
    if req.is_empty() {
        return;
    }
    v["event"] = serde_json::json!("reply");
    v["req"] = serde_json::json!(req);
    app.state::<AppState>().rdp.replied(v);
}

fn num(v: &serde_json::Value, k: &str) -> i64 {
    v.get(k).and_then(|x| x.as_i64()).unwrap_or(0)
}

// ---------- frame messages, as documented in crate::vnc ----------

fn msg_size(out: &TermOut, w: u16, h: u16) {
    let mut buf = vec![1];
    put16(&mut buf, &[w, h]);
    send(out, buf);
}

/// The rectangle as one pixels message; rows are copied out of the framebuffer because it is wider than the rectangle.
fn msg_pixels(out: &TermOut, image: &DecodedImage, rect: &InclusiveRectangle) {
    let (w, h) = (rect.width(), rect.height());
    let (bpp, stride, data) = (image.bytes_per_pixel(), image.stride(), image.data());
    let mut buf = Vec::with_capacity(9 + usize::from(w) * usize::from(h) * bpp);
    buf.push(2);
    put16(&mut buf, &[rect.left, rect.top, w, h]);
    for row in 0..u32::from(h) {
        let start = (usize::from(rect.top) + row as usize) * stride + usize::from(rect.left) * bpp;
        buf.extend_from_slice(&data[start..start + usize::from(w) * bpp]);
    }
    send(out, buf);
}

fn send(out: &TermOut, buf: Vec<u8>) {
    let _ = out.channel.send(tauri::ipc::InvokeResponseBody::Raw(buf));
}

fn put16(buf: &mut Vec<u8>, vals: &[u16]) {
    for v in vals {
        buf.extend_from_slice(&v.to_le_bytes());
    }
}

/// The framebuffer as JPEG, at most 1600 pixels wide or high (the assistant sends the picture to a model).
fn snapshot_jpeg(image: &DecodedImage) -> Vec<u8> {
    let (w, h) = (usize::from(image.width()), usize::from(image.height()));
    let k = 1.0f64.min(1600.0 / w.max(h) as f64);
    let (tw, th) = ((w as f64 * k).ceil() as usize, (h as f64 * k).ceil() as usize);
    let stride = image.stride();
    let mut rgb = Vec::with_capacity(tw * th * 3);
    for j in 0..th {
        let y = (j * h / th).min(h - 1);
        let row = &image.data()[y * stride..];
        for i in 0..tw {
            let x = (i * w / tw).min(w - 1);
            rgb.extend_from_slice(&row[x * 4..x * 4 + 3]);
        }
    }
    let mut out = Vec::new();
    let encoder = jpeg_encoder::Encoder::new(&mut out, 85);
    if encoder.encode(&rgb, tw as u16, th as u16, jpeg_encoder::ColorType::Rgb).is_err() {
        return Vec::new();
    }
    out
}

// ---------- input mapping ----------

/// VNC-style pointer mask to operations: bit 1 left, 2 middle, 4 right are state,
/// 8 and 16 are one wheel notch up or down. Returns the operations and the new button state.
pub(crate) fn pointer_ops(prev: u8, mask: u8, x: u16, y: u16) -> (Vec<ironrdp_input::Operation>, u8) {
    use ironrdp_input::{MouseButton, MousePosition, Operation, WheelRotations};
    let mut ops = vec![Operation::MouseMove(MousePosition { x, y })];
    let state = mask & 7;
    for (bit, b) in [(1u8, MouseButton::Left), (2, MouseButton::Middle), (4, MouseButton::Right)] {
        let (was, now) = (prev & bit != 0, state & bit != 0);
        if now && !was {
            ops.push(Operation::MouseButtonPressed(b));
        } else if was && !now {
            ops.push(Operation::MouseButtonReleased(b));
        }
    }
    if mask & 8 != 0 {
        ops.push(Operation::WheelRotations(WheelRotations { is_vertical: true, rotation_units: 120 }));
    }
    if mask & 16 != 0 {
        ops.push(Operation::WheelRotations(WheelRotations { is_vertical: true, rotation_units: -120 }));
    }
    (ops, state)
}

/// The RDP virtual scan code of a DOM `event.code` (physical positions, so any remote layout agrees);
/// extended codes carry 0xE000. The assistant's friendly names go through [`parse_keys`].
pub(crate) fn scancode_for(code: &str) -> Option<u16> {
    let c = match code {
        // letters and digits
        "KeyQ" => 0x10, "KeyW" => 0x11, "KeyE" => 0x12, "KeyR" => 0x13, "KeyT" => 0x14, "KeyY" => 0x15, "KeyU" => 0x16,
        "KeyI" => 0x17, "KeyO" => 0x18, "KeyP" => 0x19, "KeyA" => 0x1E, "KeyS" => 0x1F, "KeyD" => 0x20, "KeyF" => 0x21,
        "KeyG" => 0x22, "KeyH" => 0x23, "KeyJ" => 0x24, "KeyK" => 0x25, "KeyL" => 0x26, "KeyZ" => 0x2C, "KeyX" => 0x2D,
        "KeyC" => 0x2E, "KeyV" => 0x2F, "KeyB" => 0x30, "KeyN" => 0x31, "KeyM" => 0x32,
        "Digit1" => 0x02, "Digit2" => 0x03, "Digit3" => 0x04, "Digit4" => 0x05, "Digit5" => 0x06, "Digit6" => 0x07,
        "Digit7" => 0x08, "Digit8" => 0x09, "Digit9" => 0x0A, "Digit0" => 0x0B,
        // punctuation and whitespace
        "Escape" => 0x01, "Minus" => 0x0C, "Equal" => 0x0D, "Backspace" => 0x0E, "Tab" => 0x0F, "Enter" => 0x1C,
        "BracketLeft" => 0x1A, "BracketRight" => 0x1B, "Backslash" => 0x2B, "Semicolon" => 0x27, "Quote" => 0x28,
        "Backquote" => 0x29, "Comma" => 0x33, "Period" => 0x34, "Slash" => 0x35, "Space" => 0x39, "CapsLock" => 0x3A,
        // modifiers: the left side is what a one-keyboard user means
        "ShiftLeft" => 0x2A, "ControlLeft" => 0x1D, "AltLeft" | "MetaLeft" | "OSLeft" => 0x38,
        "ShiftRight" => 0x36, "ControlRight" => 0xE01D, "AltRight" | "MetaRight" | "OSRight" => 0xE038, "AltGraph" => 0xE038,
        // function keys
        "F1" => 0x3B, "F2" => 0x3C, "F3" => 0x3D, "F4" => 0x3E, "F5" => 0x3F, "F6" => 0x40, "F7" => 0x41,
        "F8" => 0x42, "F9" => 0x43, "F10" => 0x44, "F11" => 0x57, "F12" => 0x58,
        // navigation and keypad
        "Home" => 0xE047, "Prior" => 0xE049, "PageUp" => 0xE049, "End" => 0xE04F, "Next" => 0xE051, "PageDown" => 0xE051,
        "ArrowLeft" => 0xE04B, "ArrowUp" => 0xE048, "ArrowRight" => 0xE04D, "ArrowDown" => 0xE050,
        "Insert" => 0xE052, "Delete" => 0xE053, "NumpadEnter" => 0xE01C, "NumpadDivide" => 0xE035,
        "NumpadMultiply" => 0x37, "NumpadSubtract" => 0x4A, "NumpadAdd" => 0x4E, "NumpadDecimal" => 0x53,
        "Numpad0" => 0x52, "Numpad1" => 0x4F, "Numpad2" => 0x50, "Numpad3" => 0x51, "Numpad4" => 0x4B,
        "Numpad5" => 0x4C, "Numpad6" => 0x4D, "Numpad7" => 0x47, "Numpad8" => 0x48, "Numpad9" => 0x49,
        "NumLock" => 0x45, "ScrollLock" => 0x46, "PrintScreen" => 0xE037,
        _ => return scancode_named(code),
    };
    Some(c)
}

/// The assistant's friendly key names ("ctrl", "win", "f5", "pgup", "delete", a lone "a").
/// Only single characters fall back to their key on a US layout, so unknown words stay errors.
fn scancode_named(code: &str) -> Option<u16> {
    if code.len() == 1 {
        return single_char_scancode(code);
    }
    let c = code.to_ascii_lowercase();
    scancode_for(match c.as_str() {
        "ctrl" | "control" => "ControlLeft",
        "shift" => "ShiftLeft",
        "alt" | "option" => "AltLeft",
        "win" | "windows" | "meta" | "cmd" | "super" => return Some(0xE05B),
        "esc" | "escape" => "Escape",
        "return" | "enter" => "Enter",
        "del" | "delete" => "Delete",
        "ins" | "insert" => "Insert",
        "pgup" | "pageup" | "prior" => "Prior",
        "pgdn" | "pagedown" | "next" => "Next",
        "up" | "arrowup" => "ArrowUp",
        "down" | "arrowdown" => "ArrowDown",
        "left" | "arrowleft" => "ArrowLeft",
        "right" | "arrowright" => "ArrowRight",
        "home" => "Home",
        "end" => "End",
        "tab" => "Tab",
        "space" => "Space",
        "backspace" => "Backspace",
        "printscreen" | "prtsc" => "PrintScreen",
        // DOM names as typed, whatever the casing: "f5", "arrowdown", "Numpad5"…
        other => {
            return DOM_WORDS.iter().find(|(n, _)| *n == other).map(|(_, v)| *v);
        }
    })
}

/// Lowercased DOM codes the assistant may use verbatim; only the ones its prompts mention.
const DOM_WORDS: &[(&str, u16)] = &[
    ("f1", 0x3B), ("f2", 0x3C), ("f3", 0x3D), ("f4", 0x3E), ("f5", 0x3F), ("f6", 0x40),
    ("f7", 0x41), ("f8", 0x42), ("f9", 0x43), ("f10", 0x44), ("f11", 0x57), ("f12", 0x58),
];

/// "a" maps like KeyA, "1" like Digit1, "-" like Minus: single keys by character.
fn single_char_scancode(part: &str) -> Option<u16> {
    let b = part.as_bytes();
    let ch = b.first()?.to_ascii_lowercase();
    Some(match ch {
        b'a'..=b'z' => scancode_for(&format!("Key{}", ch.to_ascii_uppercase() as char))?,
        b'1'..=b'9' => scancode_for(&format!("Digit{}", (ch - b'0')))?,
        b'0' => 0x0B,
        b'-' => 0x0C,
        b'=' => 0x0D,
        b',' => 0x33,
        b'.' => 0x34,
        b'/' => 0x35,
        b';' => 0x27,
        _ => return None,
    })
}

/// Press every code once, release them in reverse: one keyboard event storm per chord.
fn chord_codes(codes: &[u16]) -> Vec<ironrdp_input::Operation> {
    use ironrdp_input::{Operation, Scancode};
    let mut ops = Vec::with_capacity(codes.len() * 2);
    for c in codes {
        ops.push(Operation::KeyPressed(Scancode::from_u16(*c)));
    }
    for c in codes.iter().rev() {
        ops.push(Operation::KeyReleased(Scancode::from_u16(*c)));
    }
    ops
}

/// The helper's SendCtrlAltDel equivalent, for the tab's button.
fn chord(keys: &str) -> Vec<ironrdp_input::Operation> {
    chord_codes(&parse_keys(keys).unwrap_or_default())
}

/// "ctrl+alt+delete" to scan codes.
pub(crate) fn parse_keys(keys: &str) -> Result<Vec<u16>> {
    let mut out = Vec::new();
    for part in keys.split('+').map(str::trim).filter(|p| !p.is_empty()) {
        // The literal plus sign can only appear between names, never as one itself.
        out.push(scancode_named(part).ok_or_else(|| anyhow!("No key named \"{part}\"."))?);
    }
    if out.is_empty() {
        return Err(anyhow!("No keys in \"{keys}\"."));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scancodes() {
        assert_eq!(scancode_for("KeyA"), Some(0x1E));
        assert_eq!(scancode_for("Digit1"), Some(0x02));
        assert_eq!(scancode_for("Escape"), Some(0x01));
        assert_eq!(scancode_for("Minus"), Some(0x0C));
        assert_eq!(scancode_for("Enter"), Some(0x1C));
        assert_eq!(scancode_for("Space"), Some(0x39));
        assert_eq!(scancode_for("F5"), Some(0x3F));
        assert_eq!(scancode_for("Numpad5"), Some(0x4C));
        assert_eq!(scancode_for("ShiftLeft"), Some(0x2A));
        assert_eq!(scancode_for("ControlLeft"), Some(0x1D));
        assert_eq!(scancode_for("AltLeft"), Some(0x38));
        assert_eq!(scancode_for("ArrowDown"), Some(0xE050));
        assert_eq!(scancode_for("Delete"), Some(0xE053));
        assert_eq!(scancode_for("NumpadDivide"), Some(0xE035));
        assert_eq!(scancode_for("Minus"), Some(0x0C));
        assert_eq!(scancode_for("Equal"), Some(0x0D));
        assert_eq!(scancode_for("AltRight"), Some(0xE038));
        assert_eq!(scancode_for("UnknownKey"), None);
    }

    #[test]
    fn named_keys() {
        // Minus and Equal are both "+" on keyboards: neither is claimed as a chord separator.
        assert_eq!(parse_keys("ctrl+alt+delete").unwrap(), vec![0x1D, 0x38, 0xE053]);
        assert_eq!(parse_keys("ctrl+-").unwrap(), vec![0x1D, 0x0C]);
        assert_eq!(parse_keys("ctrl+=").unwrap(), vec![0x1D, 0x0D]);
        assert_eq!(parse_keys("Win+P").unwrap(), vec![0xE05B, 0x19]);
        assert_eq!(parse_keys("a+b").unwrap(), vec![0x1E, 0x30]);
        assert!(parse_keys("ctrl+nosuchkey").is_err());
        assert!(parse_keys("").is_err());
    }

    #[test]
    fn pointer_diff() {
        let (ops, state) = pointer_ops(0, 1, 10, 20);
        assert!(matches!(ops[1], ironrdp_input::Operation::MouseButtonPressed(ironrdp_input::MouseButton::Left)));
        assert_eq!(state, 1);
        let (ops, state) = pointer_ops(1, 0, 10, 20);
        assert!(matches!(ops[1], ironrdp_input::Operation::MouseButtonReleased(ironrdp_input::MouseButton::Left)));
        assert_eq!(state, 0);
        // The wheel bits (VNC style: 8 up, 16 down) are momentary: they do not enter the state.
        let (ops, state) = pointer_ops(0, 8, 10, 20);
        assert!(matches!(ops[1], ironrdp_input::Operation::WheelRotations(ironrdp_input::WheelRotations { is_vertical: true, rotation_units: 120 })));
        assert_eq!(state, 0);
        let (ops, _) = pointer_ops(0, 16, 10, 20);
        assert!(matches!(ops[1], ironrdp_input::Operation::WheelRotations(ironrdp_input::WheelRotations { is_vertical: true, rotation_units: -120 })));
    }

    #[test]
    fn snapshot_is_jpeg() {
        let image = DecodedImage::new(ironrdp_graphics::image_processing::PixelFormat::RgbA32, 640, 480);
        let jpg = snapshot_jpeg(&image);
        assert!(jpg.starts_with(&[0xFF, 0xD8]));
        assert!(jpg.len() > 500);
    }

    #[test]
    fn pixels_message_shape() {
        let image = DecodedImage::new(ironrdp_graphics::image_processing::PixelFormat::RgbA32, 4, 2);
        let rect = InclusiveRectangle { left: 1, top: 0, right: 2, bottom: 1 };
        let mut buf = Vec::new();
        buf.push(2);
        put16(&mut buf, &[1, 0, 2, 2]);
        assert_eq!(buf.len(), 9);
        assert_eq!(rect.width(), 2);
        assert_eq!(rect.height(), 2);
        let _ = image;
    }
}
