//! Minimal, strict JSON-RPC 2.0 Model Context Protocol (MCP) stdio server engine.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{BufRead, Write};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
/// Supported MCP protocol versions for `initialize` negotiation.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
/// Maximum allowed JSON-RPC line frame size (16 MiB) to prevent memory exhaustion.
pub const MAX_MCP_LINE_BYTES: usize = 16 * 1024 * 1024;

/// Incoming JSON-RPC 2.0 request/notification.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Outgoing JSON-RPC 2.0 response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
}

/// Metadata describing an MCP tool exposed by the server.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Result returned by a tool handler.
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub text: String,
    pub is_error: bool,
}

impl ToolResult {
    #[must_use]
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }

    #[must_use]
    pub fn err(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }
}

/// Optional MCP Tool Annotations (`2025-03-26`+) guiding client auto-approval & safety UX.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
pub struct ToolAnnotations {
    pub read_only_hint: bool,
    pub destructive_hint: bool,
    pub idempotent_hint: bool,
    pub open_world_hint: bool,
}

impl ToolAnnotations {
    /// Preset for deterministic, local, read-only analysis tools.
    #[must_use]
    pub const fn read_only() -> Self {
        Self {
            read_only_hint: true,
            destructive_hint: false,
            idempotent_hint: true,
            open_world_hint: false,
        }
    }

    /// Preset for local state-mutating tools (e.g., Swarm blackboard/locks).
    #[must_use]
    pub const fn local_mutation() -> Self {
        Self {
            read_only_hint: false,
            destructive_hint: false,
            idempotent_hint: false,
            open_world_hint: false,
        }
    }
}

/// Metadata describing an MCP resource exposed by the server.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

/// Trait implemented by every Vektor MCP resource.
pub trait ResourceHandler: Send + Sync {
    fn definition(&self) -> ResourceDefinition;
    fn read(&self) -> Result<String>;
}

/// Trait implemented by every Vektor MCP tool.
pub trait ToolHandler: Send + Sync {
    fn definition(&self) -> ToolDefinition;
    fn call(&self, args: Value) -> ToolResult;
    /// Optional MCP tool annotations (defaults to read-only local analysis).
    fn annotations(&self) -> Option<ToolAnnotations> {
        Some(ToolAnnotations::read_only())
    }
}

#[derive(Serialize)]
struct ToolListEntry {
    #[serde(flatten)]
    definition: ToolDefinition,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<ToolAnnotations>,
}

/// Registry and dispatcher for MCP tools and resources.
pub struct McpServer {
    name: String,
    version: String,
    tools: BTreeMap<String, Box<dyn ToolHandler>>,
    resources: BTreeMap<String, Box<dyn ResourceHandler>>,
}

impl fmt::Debug for McpServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpServer")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("tools", &self.tools.keys().collect::<Vec<_>>())
            .field("resources", &self.resources.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl McpServer {
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            tools: BTreeMap::new(),
            resources: BTreeMap::new(),
        }
    }

    pub fn register<T: ToolHandler + 'static>(&mut self, handler: T) {
        let def = handler.definition();
        self.tools.insert(def.name, Box::new(handler));
    }

    pub fn register_resource<R: ResourceHandler + 'static>(&mut self, handler: R) {
        let def = handler.definition();
        self.resources.insert(def.uri, Box::new(handler));
    }

    /// Process a single JSON-RPC line. Returns `None` for notifications.
    #[must_use]
    pub fn handle_line(&self, line: &str) -> Option<JsonRpcResponse> {
        let req: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(req) => req,
            Err(err) => {
                return Some(JsonRpcResponse {
                    jsonrpc: "2.0",
                    id: Value::Null,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {err}"),
                    }),
                });
            }
        };

        // Notifications have no `id` and must not receive a response.
        let id = req.id?;

        let response = match req.method.as_str() {
            "initialize" => {
                let negotiated = req
                    .params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .and_then(|v| {
                        SUPPORTED_PROTOCOL_VERSIONS
                            .iter()
                            .copied()
                            .find(|&supported| supported == v)
                    })
                    .unwrap_or(MCP_PROTOCOL_VERSION);
                let capabilities = if self.resources.is_empty() {
                    json!({ "tools": {} })
                } else {
                    json!({ "tools": {}, "resources": {} })
                };
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!({
                        "protocolVersion": negotiated,
                        "capabilities": capabilities,
                        "serverInfo": {
                            "name": self.name,
                            "version": self.version
                        }
                    })),
                    error: None,
                }
            }
            "ping" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({})),
                error: None,
            },
            "tools/list" => {
                let defs: Vec<ToolListEntry> = self
                    .tools
                    .values()
                    .map(|t| ToolListEntry {
                        definition: t.definition(),
                        annotations: t.annotations(),
                    })
                    .collect();
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!({ "tools": defs })),
                    error: None,
                }
            }
            "tools/call" => self.handle_tool_call(id, &req.params),
            "resources/list" => {
                let defs: Vec<ResourceDefinition> =
                    self.resources.values().map(|r| r.definition()).collect();
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!({ "resources": defs })),
                    error: None,
                }
            }
            "resources/read" => self.handle_resource_read(id, &req.params),
            other => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {other}"),
                }),
            },
        };

        Some(response)
    }

    fn handle_resource_read(&self, id: Value, params: &Value) -> JsonRpcResponse {
        let Some(uri) = params.get("uri").and_then(Value::as_str) else {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Missing required parameter: uri".to_string(),
                }),
            };
        };

        let Some(handler) = self.resources.get(uri) else {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: format!("Unknown resource URI: {uri}"),
                }),
            };
        };

        let def = handler.definition();
        match handler.read() {
            Ok(text) => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "contents": [
                        {
                            "uri": def.uri,
                            "mimeType": def.mime_type,
                            "text": text
                        }
                    ]
                })),
                error: None,
            },
            Err(err) => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32603,
                    message: format!("Failed to read resource {uri}: {err}"),
                }),
            },
        }
    }

    fn handle_tool_call(&self, id: Value, params: &Value) -> JsonRpcResponse {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Missing required parameter: name".to_string(),
                }),
            };
        };

        let Some(handler) = self.tools.get(name) else {
            return JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: format!("Unknown tool: {name}"),
                }),
            };
        };

        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let res = handler.call(args);

        JsonRpcResponse {
            jsonrpc: "2.0",
            id,
            result: Some(json!({
                "content": [
                    {
                        "type": "text",
                        "text": res.text
                    }
                ],
                "isError": res.is_error
            })),
            error: None,
        }
    }

    /// Run the MCP server loop reading newline-delimited JSON-RPC from `reader` and writing to `writer`.
    /// Frames exceeding `MAX_MCP_LINE_BYTES` are drained safely and answered with JSON-RPC `-32600`.
    pub fn run_stdio<R: BufRead, W: Write>(&self, reader: R, writer: W) -> Result<()> {
        self.run_stdio_with_limit(reader, writer, MAX_MCP_LINE_BYTES)
    }

    /// Run the MCP stdio loop with an explicit maximum frame size in bytes.
    pub fn run_stdio_with_limit<R: BufRead, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        max_line_bytes: usize,
    ) -> Result<()> {
        let mut buf = Vec::new();
        loop {
            buf.clear();
            let status = read_line_capped(&mut reader, &mut buf, max_line_bytes)?;
            match status {
                ReadLineStatus::Eof => break,
                ReadLineStatus::TooLong => {
                    let resp = JsonRpcResponse {
                        jsonrpc: "2.0",
                        id: Value::Null,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32600,
                            message: format!(
                                "Request payload exceeds maximum size ({max_line_bytes} bytes)"
                            ),
                        }),
                    };
                    serde_json::to_writer(&mut writer, &resp)?;
                    writer.write_all(b"\n")?;
                    writer.flush()?;
                }
                ReadLineStatus::Ok => {
                    let line = String::from_utf8_lossy(&buf);
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Some(resp) = self.handle_line(trimmed) {
                        serde_json::to_writer(&mut writer, &resp)?;
                        writer.write_all(b"\n")?;
                        writer.flush()?;
                    }
                }
            }
        }
        Ok(())
    }
}

enum ReadLineStatus {
    Ok,
    TooLong,
    Eof,
}

fn read_line_capped<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<ReadLineStatus> {
    let mut exceeded = false;
    let mut any_bytes = false;

    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if !any_bytes {
                Ok(ReadLineStatus::Eof)
            } else if exceeded {
                Ok(ReadLineStatus::TooLong)
            } else {
                Ok(ReadLineStatus::Ok)
            };
        }

        any_bytes = true;
        let newline_pos = available.iter().position(|&b| b == b'\n');
        let chunk_len = newline_pos.map_or(available.len(), |pos| pos + 1);

        if !exceeded {
            if out.len().saturating_add(chunk_len) > max_bytes {
                exceeded = true;
                out.clear();
            } else {
                out.extend_from_slice(&available[..chunk_len]);
            }
        }

        reader.consume(chunk_len);

        if newline_pos.is_some() {
            return Ok(if exceeded {
                ReadLineStatus::TooLong
            } else {
                ReadLineStatus::Ok
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EchoTool;

    impl ToolHandler for EchoTool {
        fn definition(&self) -> ToolDefinition {
            ToolDefinition {
                name: "echo".to_string(),
                description: "Echoes message".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": { "msg": { "type": "string" } }
                }),
            }
        }

        fn call(&self, args: Value) -> ToolResult {
            let msg = args.get("msg").and_then(Value::as_str).unwrap_or("empty");
            if msg == "fail" {
                return ToolResult::err("forced failure");
            }
            ToolResult::ok(msg)
        }
    }

    #[test]
    fn handles_initialize_list_ping_and_call() {
        let mut server = McpServer::new("vektor-test", "0.1.0");
        server.register(EchoTool);

        let init = server
            .handle_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
            .expect("init response");
        assert!(init.error.is_none());
        assert_eq!(
            init.result.unwrap()["serverInfo"]["name"],
            Value::String("vektor-test".to_string())
        );

        let ping = server
            .handle_line(r#"{"jsonrpc":"2.0","id":"p1","method":"ping"}"#)
            .expect("ping response");
        assert!(ping.error.is_none());
        assert_eq!(ping.result.unwrap(), json!({}));

        let notif = server
            .handle_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#);
        assert!(notif.is_none());

        let call = server
            .handle_line(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hello"}}}"#,
            )
            .expect("call response");
        assert!(call.error.is_none());
        assert_eq!(call.result.unwrap()["content"][0]["text"], "hello");

        let err_call = server
            .handle_line(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"fail"}}}"#,
            )
            .expect("err tool response");
        assert!(err_call.error.is_none());
        assert_eq!(err_call.result.unwrap()["isError"], true);
    }

    #[test]
    fn returns_standard_json_rpc_error_codes_and_enforces_frame_limit() {
        let mut server = McpServer::new("vektor-test", "0.1.0");
        server.register(EchoTool);

        let parse_err = server.handle_line("{not-json").expect("parse error");
        assert_eq!(parse_err.error.unwrap().code, -32700);
        assert_eq!(parse_err.id, Value::Null);

        let unknown_method = server
            .handle_line(r#"{"jsonrpc":"2.0","id":9,"method":"nonexistent"}"#)
            .expect("method not found");
        assert_eq!(unknown_method.error.unwrap().code, -32601);

        let missing_name = server
            .handle_line(r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{}}"#)
            .expect("missing name");
        assert_eq!(missing_name.error.unwrap().code, -32602);

        let unknown_tool = server
            .handle_line(
                r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"missing"}}"#,
            )
            .expect("unknown tool");
        assert_eq!(unknown_tool.error.unwrap().code, -32602);

        let oversized = format!(
            "{}\n{}\n",
            "x".repeat(256),
            r#"{"jsonrpc":"2.0","id":12,"method":"ping"}"#
        );
        let mut out = Vec::new();
        server
            .run_stdio_with_limit(oversized.as_bytes(), &mut out, 64)
            .expect("run_stdio_with_limit");
        let output = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).expect("parse first");
        assert_eq!(first["error"]["code"], -32600);
        let second: Value = serde_json::from_str(lines[1]).expect("parse second");
        assert_eq!(second["id"], 12);
        assert!(second.get("error").is_none());
    }

    struct DemoResource;
    impl ResourceHandler for DemoResource {
        fn definition(&self) -> ResourceDefinition {
            ResourceDefinition {
                uri: "vektor://demo".to_string(),
                name: "Demo".to_string(),
                description: "Demo resource".to_string(),
                mime_type: "text/plain".to_string(),
            }
        }
        fn read(&self) -> Result<String> {
            Ok("hello-resource".to_string())
        }
    }

    #[test]
    fn negotiates_protocol_version_and_serves_resources() {
        let mut server = McpServer::new("vektor-test", "0.1.0");
        server.register(EchoTool);
        server.register_resource(DemoResource);

        let init = server
            .handle_line(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
            )
            .expect("init");
        assert_eq!(init.result.unwrap()["protocolVersion"], "2025-06-18");

        let list = server
            .handle_line(r#"{"jsonrpc":"2.0","id":2,"method":"resources/list"}"#)
            .expect("list");
        assert_eq!(list.result.unwrap()["resources"][0]["uri"], "vektor://demo");

        let read = server
            .handle_line(
                r#"{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"vektor://demo"}}"#,
            )
            .expect("read");
        assert_eq!(
            read.result.unwrap()["contents"][0]["text"],
            "hello-resource"
        );

        let missing = server
            .handle_line(
                r#"{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"vektor://nope"}}"#,
            )
            .expect("missing");
        assert_eq!(missing.error.unwrap().code, -32602);
    }
}
