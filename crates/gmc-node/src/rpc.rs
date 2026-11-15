//! Minimal bounded loopback HTTP/1.1 + JSON-RPC 2.0 control server (`127.0.0.1`).
//!
//! Designed strictly as a local node control & inspection endpoint (rich public client
//! APIs belong to downstream `gmc-api`). Enforces:
//! - Loopback-only binding (`127.0.0.1` / `::1`) unless explicitly overridden;
//! - Strict `MAX_REQUEST_BYTES = 262_144` (`256 KiB`) ceiling checked **before** body
//!   allocation so untrusted oversized payloads return `413 Payload Too Large` without OOM;
//! - Cryptographic Ed25519 signature verification (`SignedOperation`) on every
//!   `/submit_operation` / `gmc_submitOperation` mutation;
//! - Clean atomic shutdown flushing `snapshot.json`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use gmc_core::types::Timestamp;
use gmc_identity::error::IdentityError;
use gmc_identity::identity_core::Applied;

use crate::error::{NodeError, NodeResult};
use crate::runtime::{NodeRuntime, WireSignedOperation};
use crate::workbench::MERITORA_DESKTOP_HTML;

/// Hard ceiling (`256 KiB`) on incoming HTTP/JSON-RPC request bodies.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
/// Hard ceiling (`16 KiB`) on HTTP request headers.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

const CORS_HEADERS: &str = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n";

const fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct DemoStepParams {
    #[serde(default = "default_true")]
    produce_block: bool,
}

impl Default for DemoStepParams {
    fn default() -> Self {
        DemoStepParams {
            produce_block: true,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SubmitOpEnvelope {
    #[serde(flatten)]
    inner: SubmitOpShape,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SubmitOpShape {
    Wrapped {
        operation: WireSignedOperation,
        #[serde(default)]
        timestamp_secs: u64,
    },
    Direct(WireSignedOperation),
}

#[derive(Debug, Default, Deserialize)]
struct ProduceBlockParams {
    #[serde(default)]
    timestamp_secs: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    id: Value,
}

#[derive(Debug, Serialize)]
struct AppliedDto {
    kind: String,
    detail: Option<String>,
    state_root_hex: String,
}

fn applied_to_dto(applied: &Applied, state_root_hex: String) -> AppliedDto {
    match applied {
        Applied::DelegateAdded => AppliedDto {
            kind: "delegate_added".into(),
            detail: None,
            state_root_hex,
        },
        Applied::DelegateRevoked => AppliedDto {
            kind: "delegate_revoked".into(),
            detail: None,
            state_root_hex,
        },
        Applied::CoFayCreated(id) => AppliedDto {
            kind: "cofay_created".into(),
            detail: Some(id.canonical()),
            state_root_hex,
        },
        Applied::DeviceEnrolled(dev_id) => AppliedDto {
            kind: "device_enrolled".into(),
            detail: Some(dev_id.as_str().to_string()),
            state_root_hex,
        },
        Applied::DeviceRevoked => AppliedDto {
            kind: "device_revoked".into(),
            detail: None,
            state_root_hex,
        },
        Applied::KeyRotated(_) => AppliedDto {
            kind: "key_rotated".into(),
            detail: None,
            state_root_hex,
        },
        Applied::GuardiansConfigured => AppliedDto {
            kind: "guardians_configured".into(),
            detail: None,
            state_root_hex,
        },
        Applied::RecoveryApprovalRecorded {
            approvals,
            threshold,
        } => AppliedDto {
            kind: "recovery_approval_recorded".into(),
            detail: Some(format!("{approvals}/{threshold}")),
            state_root_hex,
        },
        Applied::RecoveryCompleted(_) => AppliedDto {
            kind: "recovery_completed".into(),
            detail: None,
            state_root_hex,
        },
    }
}

/// Handle to a running background loopback control server.
pub struct RpcServerHandle {
    local_addr: SocketAddr,
    stop_flag: Arc<AtomicBool>,
    runtime: Arc<Mutex<NodeRuntime>>,
    join_handle: Option<JoinHandle<()>>,
}

impl RpcServerHandle {
    /// Bound socket address (useful when started with `127.0.0.1:0`).
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns `true` once the server loop has exited (e.g. when `max_requests` was reached).
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::SeqCst)
    }

    /// Signals the server loop to stop, joins the worker thread cleanly, and writes an
    /// atomic `snapshot.json` via [`NodeRuntime::shutdown`].
    pub fn shutdown(mut self) -> NodeResult<[u8; 32]> {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(100));
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
        let mut guard = self
            .runtime
            .lock()
            .map_err(|_| NodeError::Io("runtime mutex poisoned".into()))?;
        guard.shutdown()
    }
}

impl Drop for RpcServerHandle {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(50));
        if let Some(jh) = self.join_handle.take() {
            let _ = jh.join();
        }
    }
}

/// Starts the bounded HTTP/JSON-RPC control server on `bind_addr` (e.g. `"127.0.0.1:0"`).
pub fn start_control_server(
    runtime: Arc<Mutex<NodeRuntime>>,
    bind_addr: &str,
    allow_non_loopback: bool,
    max_requests: Option<usize>,
) -> NodeResult<RpcServerHandle> {
    let parsed_addr: SocketAddr = bind_addr.parse().map_err(|e| {
        NodeError::ConfigInvalid(format!("invalid control bind address '{bind_addr}': {e}"))
    })?;
    if !allow_non_loopback && !parsed_addr.ip().is_loopback() {
        return Err(NodeError::NonLoopbackBindForbidden(bind_addr.to_string()));
    }

    let listener = TcpListener::bind(parsed_addr)?;
    let local_addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;

    let stop_flag = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop_flag);
    let thread_runtime = Arc::clone(&runtime);

    let join_handle = thread::spawn(move || {
        let mut served = 0usize;
        while !thread_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _peer)) => {
                    if thread_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let _ = stream.set_nonblocking(false);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    handle_connection(&mut stream, &thread_runtime);
                    served += 1;
                    if let Some(limit) = max_requests {
                        if served >= limit {
                            thread_stop.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    Ok(RpcServerHandle {
        local_addr,
        stop_flag,
        runtime,
        join_handle: Some(join_handle),
    })
}

struct ParsedHttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

enum HttpParseError {
    TooLarge,
    BadRequest(String),
}

fn read_bounded_http_request(stream: &mut TcpStream) -> Result<ParsedHttpRequest, HttpParseError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let header_end_pos = loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| HttpParseError::BadRequest(format!("read error: {e}")))?;
        if n == 0 {
            return Err(HttpParseError::BadRequest("empty request".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(HttpParseError::TooLarge);
        }
    };

    let header_str = std::str::from_utf8(&buf[..header_end_pos])
        .map_err(|_| HttpParseError::BadRequest("non-utf8 headers".into()))?;
    let mut lines = header_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| HttpParseError::BadRequest("missing request line".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HttpParseError::BadRequest("missing HTTP method".into()))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| HttpParseError::BadRequest("missing HTTP path".into()))?
        .to_string();

    let mut content_length: usize = 0;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                let parsed: u64 = val
                    .trim()
                    .parse()
                    .map_err(|_| HttpParseError::BadRequest("invalid Content-Length".into()))?;
                if parsed > MAX_REQUEST_BYTES as u64 {
                    // Reject BEFORE allocating body buffer!
                    return Err(HttpParseError::TooLarge);
                }
                content_length = parsed as usize;
            }
        }
    }

    let body_start = header_end_pos + 4;
    let already_read = buf.len().saturating_sub(body_start);
    if already_read > MAX_REQUEST_BYTES {
        return Err(HttpParseError::TooLarge);
    }

    let mut body = Vec::with_capacity(content_length.min(MAX_REQUEST_BYTES));
    if already_read > 0 {
        let take_initial = already_read.min(content_length.max(already_read));
        body.extend_from_slice(&buf[body_start..body_start + take_initial]);
    }

    while body.len() < content_length {
        let remaining = content_length - body.len();
        let to_read = remaining.min(chunk.len());
        let n = stream
            .read(&mut chunk[..to_read])
            .map_err(|e| HttpParseError::BadRequest(format!("body read error: {e}")))?;
        if n == 0 {
            return Err(HttpParseError::BadRequest("truncated HTTP body".into()));
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > MAX_REQUEST_BYTES {
            return Err(HttpParseError::TooLarge);
        }
    }

    if body.len() > MAX_REQUEST_BYTES {
        return Err(HttpParseError::TooLarge);
    }
    if content_length > 0 && body.len() > content_length {
        body.truncate(content_length);
    }

    Ok(ParsedHttpRequest { method, path, body })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_json_response(stream: &mut TcpStream, status_code: u16, status_text: &str, body: &Value) {
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let header = format!(
        "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: application/json\r\n{CORS_HEADERS}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&payload);
    let _ = stream.flush();
}

fn write_html_response(stream: &mut TcpStream, html: &str) {
    let payload = html.as_bytes();
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n{CORS_HEADERS}Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(payload);
    let _ = stream.flush();
}

fn write_options_response(stream: &mut TcpStream) {
    let header =
        format!("HTTP/1.1 204 No Content\r\n{CORS_HEADERS}Content-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.flush();
}

fn handle_connection(stream: &mut TcpStream, runtime: &Arc<Mutex<NodeRuntime>>) {
    let req = match read_bounded_http_request(stream) {
        Ok(r) => r,
        Err(HttpParseError::TooLarge) => {
            write_json_response(
                stream,
                413,
                "Payload Too Large",
                &json!({
                    "error": "request_too_large",
                    "max_bytes": MAX_REQUEST_BYTES,
                }),
            );
            return;
        }
        Err(HttpParseError::BadRequest(reason)) => {
            write_json_response(
                stream,
                400,
                "Bad Request",
                &json!({ "error": "bad_request", "reason": reason }),
            );
            return;
        }
    };

    if req.method == "OPTIONS" {
        write_options_response(stream);
        return;
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") | ("GET", "/workbench") => {
            write_html_response(stream, MERITORA_DESKTOP_HTML);
        }
        ("GET", "/health") => {
            write_json_response(stream, 200, "OK", &json!({ "ok": true }));
        }
        ("GET", "/status") => {
            let Ok(guard) = runtime.lock() else {
                write_json_response(
                    stream,
                    500,
                    "Internal Server Error",
                    &json!({ "error": "poisoned" }),
                );
                return;
            };
            let st = guard.status();
            write_json_response(stream, 200, "OK", &serde_json::to_value(st).unwrap());
        }
        ("POST", "/submit_operation") => {
            let env: SubmitOpEnvelope = match serde_json::from_slice(&req.body) {
                Ok(e) => e,
                Err(e) => {
                    write_json_response(
                        stream,
                        400,
                        "Bad Request",
                        &json!({
                            "error": "invalid_signed_operation_json",
                            "reason": e.to_string()
                        }),
                    );
                    return;
                }
            };
            let (wire_op, ts_secs) = match env.inner {
                SubmitOpShape::Wrapped {
                    operation,
                    timestamp_secs,
                } => (operation, timestamp_secs),
                SubmitOpShape::Direct(operation) => (operation, 0),
            };
            let signed_op = match wire_op.into_signed() {
                Ok(op) => op,
                Err(e) => {
                    write_json_response(
                        stream,
                        400,
                        "Bad Request",
                        &json!({ "error": e.to_string() }),
                    );
                    return;
                }
            };

            let Ok(mut guard) = runtime.lock() else {
                write_json_response(
                    stream,
                    500,
                    "Internal Server Error",
                    &json!({ "error": "poisoned" }),
                );
                return;
            };
            match guard.submit_signed_operation(signed_op, Timestamp::from_secs(ts_secs)) {
                Ok(applied) => {
                    let dto = applied_to_dto(&applied, guard.state_root_hex());
                    write_json_response(stream, 200, "OK", &serde_json::to_value(dto).unwrap());
                }
                Err(NodeError::Identity(
                    err @ (IdentityError::SignatureInvalid
                    | IdentityError::UnauthorizedActor
                    | IdentityError::IdentityMismatch),
                )) => {
                    write_json_response(
                        stream,
                        401,
                        "Unauthorized",
                        &json!({ "error": format!("{err:?}") }),
                    );
                }
                Err(e) => {
                    write_json_response(
                        stream,
                        400,
                        "Bad Request",
                        &json!({ "error": e.to_string() }),
                    );
                }
            }
        }
        ("POST", "/produce_block") => {
            let params: ProduceBlockParams = if req.body.is_empty() {
                ProduceBlockParams::default()
            } else {
                match serde_json::from_slice(&req.body) {
                    Ok(p) => p,
                    Err(e) => {
                        write_json_response(
                            stream,
                            400,
                            "Bad Request",
                            &json!({ "error": e.to_string() }),
                        );
                        return;
                    }
                }
            };
            let Ok(mut guard) = runtime.lock() else {
                write_json_response(
                    stream,
                    500,
                    "Internal Server Error",
                    &json!({ "error": "poisoned" }),
                );
                return;
            };
            match guard.produce_block(Timestamp::from_secs(params.timestamp_secs)) {
                Ok(receipt) => {
                    write_json_response(
                        stream,
                        200,
                        "OK",
                        &serde_json::to_value(receipt).unwrap(),
                    );
                }
                Err(e) => {
                    write_json_response(
                        stream,
                        400,
                        "Bad Request",
                        &json!({ "error": e.to_string() }),
                    );
                }
            }
        }
        ("POST", "/rpc") | ("POST", "/") => {
            let rpc_req: JsonRpcRequest = match serde_json::from_slice(&req.body) {
                Ok(r) => r,
                Err(e) => {
                    write_json_response(
                        stream,
                        400,
                        "Bad Request",
                        &json!({
                            "jsonrpc": "2.0",
                            "id": null,
                            "error": { "code": -32700, "message": format!("parse error: {e}") }
                        }),
                    );
                    return;
                }
            };
            let resp = dispatch_json_rpc(rpc_req, runtime);
            write_json_response(stream, 200, "OK", &resp);
        }
        _ => {
            write_json_response(
                stream,
                404,
                "Not Found",
                &json!({ "error": "not_found" }),
            );
        }
    }
}

fn dispatch_json_rpc(req: JsonRpcRequest, runtime: &Arc<Mutex<NodeRuntime>>) -> Value {
    let id = req.id;
    match req.method.as_str() {
        "gmc_health" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "ok": true }
        }),
        "gmc_status" => {
            let Ok(guard) = runtime.lock() else {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": "internal lock error" }
                });
            };
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": guard.status()
            })
        }
        "gmc_validators" => {
            let Ok(guard) = runtime.lock() else {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": "internal lock error" }
                });
            };
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": guard.validators_summary()
            })
        }
        "gmc_auditLog" => {
            let Ok(guard) = runtime.lock() else {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": "internal lock error" }
                });
            };
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": guard.audit_log_summary()
            })
        }
        "gmc_demoStep" => {
            let params: DemoStepParams = serde_json::from_value(req.params).unwrap_or_default();
            let Ok(mut guard) = runtime.lock() else {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": "internal lock error" }
                });
            };
            match guard.demo_step(params.produce_block) {
                Ok(res) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": res
                }),
                Err(e) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32003, "message": e.to_string() }
                }),
            }
        }
        "gmc_submitOperation" => {
            let env: SubmitOpEnvelope = match serde_json::from_value(req.params) {
                Ok(e) => e,
                Err(e) => {
                    return json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32602, "message": e.to_string() }
                    });
                }
            };
            let (wire_op, ts_secs) = match env.inner {
                SubmitOpShape::Wrapped {
                    operation,
                    timestamp_secs,
                } => (operation, timestamp_secs),
                SubmitOpShape::Direct(operation) => (operation, 0),
            };
            let signed_op = match wire_op.into_signed() {
                Ok(op) => op,
                Err(e) => {
                    return json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": { "code": -32602, "message": e.to_string() }
                    });
                }
            };
            let Ok(mut guard) = runtime.lock() else {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": "internal lock error" }
                });
            };
            match guard.submit_signed_operation(signed_op, Timestamp::from_secs(ts_secs)) {
                Ok(applied) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": applied_to_dto(&applied, guard.state_root_hex())
                }),
                Err(e) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32001, "message": e.to_string() }
                }),
            }
        }
        "gmc_produceBlock" => {
            let params: ProduceBlockParams =
                serde_json::from_value(req.params).unwrap_or_default();
            let Ok(mut guard) = runtime.lock() else {
                return json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32603, "message": "internal lock error" }
                });
            };
            match guard.produce_block(Timestamp::from_secs(params.timestamp_secs)) {
                Ok(receipt) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": receipt
                }),
                Err(e) => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32002, "message": e.to_string() }
                }),
            }
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32601, "message": format!("unknown method '{other}'") }
        }),
    }
}
