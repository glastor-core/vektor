//! Minimal, strict JSON-RPC 2.0 Model Context Protocol (MCP) stdio server engine.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

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

/// Trait implemented by every Vektor MCP tool.
pub trait ToolHandler: Send + Sync {
    fn definition(&self) -> ToolDefinition;
    fn call(&self, args: Value) -> ToolResult;
}

/// Registry and dispatcher for MCP tools.
pub struct McpServer {
    name: String,
    version: String,
    tools: BTreeMap<String, Box<dyn ToolHandler>>,
}

impl McpServer {
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            tools: BTreeMap::new(),
        }
    }

    pub fn register<T: ToolHandler + 'static>(&mut self, handler: T) {
        let def = handler.definition();
        self.tools.insert(def.name, Box::new(handler));
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
            "initialize" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version
                    }
                })),
                error: None,
            },
            "ping" => JsonRpcResponse {
                jsonrpc: "2.0",
                id,
                result: Some(json!({})),
                error: None,
            },
            "tools/list" => {
                let defs: Vec<ToolDefinition> =
                    self.tools.values().map(|t| t.definition()).collect();
                JsonRpcResponse {
                    jsonrpc: "2.0",
                    id,
                    result: Some(json!({ "tools": defs })),
                    error: None,
                }
            }
            "tools/call" => self.handle_tool_call(id, &req.params),
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
    pub fn run_stdio<R: BufRead, W: Write>(&self, reader: R, mut writer: W) -> Result<()> {
        for line_result in reader.lines() {
            let line = line_result?;
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
        Ok(())
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
            ToolResult::ok(msg)
        }
    }

    #[test]
    fn handles_initialize_list_and_call() {
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
    }
}
