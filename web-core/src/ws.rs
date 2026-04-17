//! WebSocket handler for real-time communication with the UI

use crate::protocol::{ClientMessage, ServerMessage};
use crate::state::{Commandable, Observable};
use alloy_primitives::U256;
use axum::extract::ws::{Message, WebSocket};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// Handle a WebSocket connection
pub async fn handle_websocket<S: Observable + Commandable>(
    socket: WebSocket,
    state: Arc<S>,
    mut broadcast_rx: broadcast::Receiver<ServerMessage>,
) {
    let (ws_sender, mut ws_receiver) = socket.split();

    // Use a channel to send messages back to the client from multiple sources
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ServerMessage>(100);

    // Send initial state (run in blocking task to avoid blocking async runtime)
    // This is important because get_init_payload() acquires locks and does CPU work
    let state_for_init = Arc::clone(&state);
    let init_result = tokio::task::spawn_blocking(move || {
        state_for_init.get_init_payload()
    }).await;

    match init_result {
        Ok(payload) => {
            let init = ServerMessage::Init(payload);
            if tx.send(init).await.is_err() {
                error!("Failed to queue init message");
                return;
            }
        }
        Err(e) => {
            error!("Failed to compute init payload: {}", e);
            return;
        }
    }

    info!("WebSocket client connected");

    // Clone tx for broadcast forwarding
    let broadcast_tx = tx.clone();

    // Spawn task to forward broadcast messages
    let broadcast_handle = tokio::spawn(async move {
        while let Ok(msg) = broadcast_rx.recv().await {
            if broadcast_tx.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Spawn task to send all messages to the WebSocket
    let sender_handle = tokio::spawn(async move {
        let mut ws_sender = ws_sender;
        while let Some(msg) = rx.recv().await {
            match serde_json::to_string(&msg) {
                Ok(json) => {
                    if ws_sender.send(Message::Text(json.into())).await.is_err() {
                        error!("Failed to send WebSocket message");
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize message: {} - {:?}", e, msg);
                }
            }
        }
    });

    // Handle incoming messages from the client
    while let Some(result) = ws_receiver.next().await {
        match result {
            Ok(Message::Text(text)) => {
                match serde_json::from_str::<ClientMessage>(&text) {
                    Ok(msg) => {
                        let response = handle_client_message(msg, &state).await;
                        // Send response back to the client
                        if let Some(resp) = response {
                            debug!("Command response: {:?}", resp);
                            if tx.send(resp).await.is_err() {
                                error!("Failed to send command response");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse client message: {}", e);
                        // Send error response
                        let _ = tx.send(ServerMessage::Error {
                            message: format!("Failed to parse message: {}", e),
                        }).await;
                    }
                }
            }
            Ok(Message::Binary(_)) => {
                // Ignore binary messages
            }
            Ok(Message::Ping(data)) => {
                // Pong is sent automatically by axum
                debug!("Received ping: {:?}", data);
            }
            Ok(Message::Pong(_)) => {
                // Ignore pongs
            }
            Ok(Message::Close(_)) => {
                info!("WebSocket client disconnected");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
        }
    }

    // Clean up tasks
    broadcast_handle.abort();
    sender_handle.abort();
    info!("WebSocket connection closed");
}

/// Handle a client message and return an optional response
async fn handle_client_message<S: Observable + Commandable>(
    msg: ClientMessage,
    state: &Arc<S>,
) -> Option<ServerMessage> {
    match msg {
        ClientMessage::InjectDictionary {
            id,
            values,
            broadcast,
        } => {
            let parsed_values: Result<Vec<U256>, _> = values
                .iter()
                .map(|v| {
                    let v = v.trim_start_matches("0x");
                    U256::from_str_radix(v, 16).or_else(|_| v.parse::<U256>())
                })
                .collect();

            match parsed_values {
                Ok(vals) => match state.inject_dictionary(vals, broadcast) {
                    Ok(()) => Some(ServerMessage::CommandResult {
                        id,
                        success: true,
                        message: "Dictionary values injected".to_string(),
                    }),
                    Err(e) => Some(ServerMessage::CommandResult {
                        id,
                        success: false,
                        message: e,
                    }),
                },
                Err(e) => Some(ServerMessage::CommandResult {
                    id,
                    success: false,
                    message: format!("Failed to parse values: {}", e),
                }),
            }
        }

        ClientMessage::InjectSequence { id, sequence } => {
            match state.inject_sequence(sequence) {
                Ok(()) => Some(ServerMessage::CommandResult {
                    id,
                    success: true,
                    message: "Sequence injected".to_string(),
                }),
                Err(e) => Some(ServerMessage::CommandResult {
                    id,
                    success: false,
                    message: e,
                }),
            }
        }

        ClientMessage::ClampArgument {
            id,
            function,
            param_idx,
            value,
        } => match state.clamp_argument(&function, param_idx, &value) {
            Ok(()) => Some(ServerMessage::CommandResult {
                id,
                success: true,
                message: format!("Clamped {}[{}]", function, param_idx),
            }),
            Err(e) => Some(ServerMessage::CommandResult {
                id,
                success: false,
                message: e,
            }),
        },

        ClientMessage::UnclampArgument {
            id,
            function,
            param_idx,
        } => match state.unclamp_argument(&function, param_idx) {
            Ok(()) => Some(ServerMessage::CommandResult {
                id,
                success: true,
                message: format!("Unclamped {}[{}]", function, param_idx),
            }),
            Err(e) => Some(ServerMessage::CommandResult {
                id,
                success: false,
                message: e,
            }),
        },

        ClientMessage::ClearAllClamps { id } => match state.clear_clamps() {
            Ok(()) => Some(ServerMessage::CommandResult {
                id,
                success: true,
                message: "All clamps cleared".to_string(),
            }),
            Err(e) => Some(ServerMessage::CommandResult {
                id,
                success: false,
                message: e,
            }),
        },

        ClientMessage::SetTargetFunctions { id, functions } => {
            match state.set_target_functions(functions) {
                Ok(()) => Some(ServerMessage::CommandResult {
                    id,
                    success: true,
                    message: "Target functions updated".to_string(),
                }),
                Err(e) => Some(ServerMessage::CommandResult {
                    id,
                    success: false,
                    message: e,
                }),
            }
        }

        ClientMessage::InjectFuzzTransactions {
            id,
            template,
            priority,
        } => match state.inject_fuzz_transactions(&template, priority) {
            Ok(()) => Some(ServerMessage::CommandResult {
                id,
                success: true,
                message: format!("Injected fuzz template with priority {}", priority),
            }),
            Err(e) => Some(ServerMessage::CommandResult {
                id,
                success: false,
                message: e,
            }),
        },

        ClientMessage::ClearFuzzTemplates { id } => match state.clear_fuzz_templates() {
            Ok(()) => Some(ServerMessage::CommandResult {
                id,
                success: true,
                message: "Cleared all fuzz templates".to_string(),
            }),
            Err(e) => Some(ServerMessage::CommandResult {
                id,
                success: false,
                message: e,
            }),
        },

        ClientMessage::RequestFullState { id: _ } => {
            // The full state is sent via the Init message mechanism
            // This is useful after reconnect
            // Run in blocking task since it acquires locks and does CPU work
            let state_clone = Arc::clone(state);
            let result = tokio::task::spawn_blocking(move || {
                state_clone.get_init_payload()
            }).await;

            match result {
                Ok(payload) => Some(ServerMessage::Init(payload)),
                Err(e) => {
                    error!("Failed to compute init payload: {}", e);
                    None
                }
            }
        }

        ClientMessage::Ping { id } => Some(ServerMessage::CommandResult {
            id,
            success: true,
            message: "pong".to_string(),
        }),

        ClientMessage::GetContractDetails { id, contract_name } => {
            let contract = state.get_contract_details(&contract_name);
            Some(ServerMessage::ContractDetails { id, contract })
        }

        ClientMessage::GetSourceFile { id, path } => {
            let file = state.get_source_file_content(&path);
            Some(ServerMessage::SourceFileContent { id, file })
        }

        ClientMessage::ReplaySequence { id, sequence_json } => {
            // Run replay in a blocking thread since it's CPU-intensive
            info!("ReplaySequence request received (id={}, json_len={})", id, sequence_json.len());
            let state_clone = Arc::clone(state);
            let json = sequence_json.clone();

            let result = tokio::task::spawn_blocking(move || {
                debug!("Starting replay in blocking thread");
                let result = state_clone.replay_sequence(&json);
                debug!("Replay completed: success={}", result.is_ok());
                result
            }).await;

            let response = match result {
                Ok(Ok(traces)) => {
                    info!("ReplaySequence succeeded with {} traces", traces.len());
                    Some(ServerMessage::ReplayResult {
                        id,
                        success: true,
                        traces,
                        error: None,
                    })
                }
                Ok(Err(e)) => {
                    warn!("ReplaySequence failed: {}", e);
                    Some(ServerMessage::ReplayResult {
                        id,
                        success: false,
                        traces: vec![],
                        error: Some(e),
                    })
                }
                Err(e) => {
                    error!("ReplaySequence task panicked: {}", e);
                    Some(ServerMessage::ReplayResult {
                        id,
                        success: false,
                        traces: vec![],
                        error: Some(format!("Task failed: {}", e)),
                    })
                }
            };

            debug!("Returning ReplaySequence response");
            response
        }
    }
}
