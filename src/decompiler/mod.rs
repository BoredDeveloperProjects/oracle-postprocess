use std::{
    collections::{HashMap, VecDeque},
    future::pending,
    sync::Arc,
};

use futures::{Sink, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Error as TungsteniteError;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig, Bytes, Message},
    MaybeTlsStream, WebSocketStream,
};

use crate::decompiler::options::DecompileOptions;

mod options;

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum WebsocketServerboundMessage<'a> {
    #[serde(rename = "decompile")]
    Decompile { data: Vec<&'a str> },
    // i dont care about this thing existing!
    // users, however, might!
    #[allow(dead_code)]
    #[serde(rename = "options")]
    Options { options: &'a DecompileOptions },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
enum WebsocketClientboundMessage {
    #[serde(rename = "decompilation_result")]
    DecompilationResult {
        success: bool,
        data: String,
        input_hash: String,
    },
}

pub struct DecompilationRequest {
    pub bytecode: Arc<str>,
    pub bytecode_hash: String,
    pub bytecode_len: u32,
    pub tx: oneshot::Sender<Result<String, String>>,
}

pub struct Decompiler {
    decompile_tx: mpsc::Sender<DecompilationRequest>,
    _websocket_handle: tokio::task::JoinHandle<()>,
}

const MAX_BYTES_IN_FLIGHT: u32 = 8 * 1024 * 1024; // 8 mib
const REQUEST_CHANNEL_CAPACITY: usize = 512;

type DecompilationResponse = Result<String, String>;

struct PendingRequestGroup {
    waiters: Vec<oneshot::Sender<DecompilationResponse>>,
    byte_size: u32,
}

struct QueuedRequestGroup {
    bytecode: Arc<str>,
    bytecode_len: u32,
    waiters: Vec<oneshot::Sender<DecompilationResponse>>,
}

struct BatchRequestGroup {
    hash: String,
    bytecode: Arc<str>,
    bytecode_len: u32,
    waiters: Vec<oneshot::Sender<DecompilationResponse>>,
}

impl Decompiler {
    pub async fn new(endpoint: &str, auth_token: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut request = endpoint.into_client_request()?;
        request
            .headers_mut()
            .insert("Authorization", format!("Bearer {}", auth_token).parse()?);

        let ws_config = WebSocketConfig::default().max_frame_size(Some(512 * 1024 * 1024)).max_message_size(Some(512 * 1024 * 1024));
        let ws_connect = connect_async_with_config(request, Some(ws_config), false).await;

        let ws_stream = match ws_connect {
            Ok((ws_stream, _)) => ws_stream,
            Err(TungsteniteError::Http(e)) => {
                if let Some(body) = e.body() {
                    if let Ok(body_string) = String::from_utf8(body.clone()) {
                        return Err(body_string.into());
                    }
                }
                return Err(format!("http error: {:?}", e).into());
            }
            Err(e) => {
                eprintln!("error: {:?}", e);
                return Err(e.into());
            }
        };

        let (decompile_tx, decompile_rx) = mpsc::channel::<DecompilationRequest>(REQUEST_CHANNEL_CAPACITY);
        let websocket_handle = tokio::spawn(Self::websocket_handler(ws_stream, decompile_rx));

        Ok(Self {
            decompile_tx,
            _websocket_handle: websocket_handle,
        })
    }

    async fn websocket_handler(
        ws_stream: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
        mut decompile_rx: mpsc::Receiver<DecompilationRequest>,
    ) {
        let (mut write, mut read) = ws_stream.split();

        let mut bytes_in_flight = 0u32;
        let mut pending_requests: HashMap<String, PendingRequestGroup> = HashMap::new();
        let mut queued_order = VecDeque::new();
        let mut queued_requests: HashMap<String, QueuedRequestGroup> = HashMap::new();

        let mut ping_interval = tokio::time::interval(tokio::time::Duration::from_secs(20));
        ping_interval.tick().await;
        let mut input_closed = false;

        loop {
            if let Err(error) = Self::flush_queued_requests(
                &mut write,
                &mut bytes_in_flight,
                &mut queued_order,
                &mut queued_requests,
                &mut pending_requests,
            )
            .await
            {
                eprintln!(
                    "error: failed to send websocket message (connection lost): {}",
                    error
                );
                std::process::exit(1);
            }

            if input_closed && pending_requests.is_empty() && queued_order.is_empty() {
                break;
            }

            tokio::select! {
                _ = ping_interval.tick() => {
                    if let Err(e) = write.send(Message::Ping(Bytes::from_static(b"ping"))).await {
                        eprintln!("error: failed to send ping (connection lost): {}", e);
                        std::process::exit(1);
                    }
                }
                message = read.next() => {
                    let text = match message {
                        Some(Ok(Message::Text(text))) => text,
                        Some(Ok(Message::Close(_))) => {
                            eprintln!("error: websocket connection closed by server");
                            std::process::exit(1);
                        },
                        Some(Err(e)) => {
                            eprintln!("error: websocket connection error: {}", e);
                            std::process::exit(1);
                        },
                        None => {
                            eprintln!("error: websocket connection terminated unexpectedly");
                            std::process::exit(1);
                        },
                        _ => continue
                    };

                    let Ok(response) = serde_json::from_str::<WebsocketClientboundMessage>(&text) else {
                        println!("server sent something unknown: {:?}", &text);
                        continue;
                    };

                    let WebsocketClientboundMessage::DecompilationResult { success, data, input_hash } = response;

                    let Some(pending_group) = pending_requests.remove(input_hash.as_str()) else {
                        continue;
                    };

                    bytes_in_flight = bytes_in_flight.saturating_sub(pending_group.byte_size);
                    Self::complete_waiters(
                        pending_group.waiters,
                        if success { Ok(data) } else { Err(data) },
                    );
                }
                decompile_request = async {
                    if input_closed {
                        pending::<Option<DecompilationRequest>>().await
                    } else {
                        decompile_rx.recv().await
                    }
                } => {
                    match decompile_request {
                        Some(request) => Self::queue_request(
                            request,
                            &mut pending_requests,
                            &mut queued_order,
                            &mut queued_requests,
                        ),
                        None => input_closed = true,
                    }
                }
            }
        }
    }

    fn queue_request(
        request: DecompilationRequest,
        pending_requests: &mut HashMap<String, PendingRequestGroup>,
        queued_order: &mut VecDeque<String>,
        queued_requests: &mut HashMap<String, QueuedRequestGroup>,
    ) {
        if request.bytecode_len > MAX_BYTES_IN_FLIGHT {
            let _ = request.tx.send(Err(format!(
                "bytecode too large ({:.2} mb) exceeds 8mb limit",
                request.bytecode_len as f64 / 1024.0 / 1024.0
            )));
            return;
        }

        if let Some(existing_request) = pending_requests.get_mut(&request.bytecode_hash) {
            existing_request.waiters.push(request.tx);
            return;
        }

        if let Some(existing_request) = queued_requests.get_mut(&request.bytecode_hash) {
            existing_request.waiters.push(request.tx);
            return;
        }

        queued_order.push_back(request.bytecode_hash.clone());
        queued_requests.insert(
            request.bytecode_hash,
            QueuedRequestGroup {
                bytecode: request.bytecode,
                bytecode_len: request.bytecode_len,
                waiters: vec![request.tx],
            },
        );
    }

    async fn flush_queued_requests<W>(
        write: &mut W,
        bytes_in_flight: &mut u32,
        queued_order: &mut VecDeque<String>,
        queued_requests: &mut HashMap<String, QueuedRequestGroup>,
        pending_requests: &mut HashMap<String, PendingRequestGroup>,
    ) -> Result<(), TungsteniteError>
    where
        W: Sink<Message, Error = TungsteniteError> + Unpin,
    {
        let available_bytes = MAX_BYTES_IN_FLIGHT.saturating_sub(*bytes_in_flight);
        if available_bytes == 0 || queued_order.is_empty() {
            return Ok(());
        }

        let mut batch = Vec::new();
        let mut batch_bytes = 0u32;

        while let Some(next_hash) = queued_order.front() {
            let next_request = queued_requests
                .get(next_hash)
                .expect("queued order and queued request map out of sync");

            if batch_bytes + next_request.bytecode_len > available_bytes {
                break;
            }

            let hash = queued_order
                .pop_front()
                .expect("queue front disappeared during flush");
            let request = queued_requests
                .remove(&hash)
                .expect("queued request disappeared during flush");

            batch_bytes += request.bytecode_len;
            batch.push(BatchRequestGroup {
                hash,
                bytecode: request.bytecode,
                bytecode_len: request.bytecode_len,
                waiters: request.waiters,
            });
        }

        if batch.is_empty() {
            return Ok(());
        }

        let message = serde_json::to_string(&WebsocketServerboundMessage::Decompile {
            data: batch.iter().map(|request| request.bytecode.as_ref()).collect(),
        })
        .expect("failed to serialize decompile batch");

        write.send(Message::Text(message.into())).await?;
        *bytes_in_flight += batch_bytes;

        for request in batch {
            pending_requests.insert(
                request.hash,
                PendingRequestGroup {
                    waiters: request.waiters,
                    byte_size: request.bytecode_len,
                },
            );
        }

        Ok(())
    }

    fn complete_waiters(
        waiters: Vec<oneshot::Sender<DecompilationResponse>>,
        result: DecompilationResponse,
    ) {
        let mut result = Some(result);
        let mut remaining_waiters = waiters.into_iter().peekable();

        while let Some(waiter) = remaining_waiters.next() {
            let response = if remaining_waiters.peek().is_some() {
                result
                    .as_ref()
                    .expect("result unexpectedly missing before final waiter")
                    .clone()
            } else {
                result
                    .take()
                    .expect("result unexpectedly missing for final waiter")
            };

            let _ = waiter.send(response);
        }
    }

    pub async fn enqueue_request(
        &self,
        request: DecompilationRequest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.decompile_tx.send(request).await?;
        Ok(())
    }

    pub async fn decompile_batch(
        &self,
        requests: Vec<DecompilationRequest>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for request in requests {
            self.enqueue_request(request).await?;
        }
        Ok(())
    }

    pub async fn decompile_single(
        &self,
        bytecode: &str,
    ) -> Result<Result<String, String>, Box<dyn std::error::Error>> {
        let (tx, rx) = oneshot::channel();
        let bytecode_hash = format!("{:x}", Sha256::digest(bytecode.as_bytes()));
        let bytecode_len = bytecode.len() as u32;

        let request = DecompilationRequest {
            bytecode: Arc::from(bytecode),
            bytecode_hash,
            bytecode_len,
            tx,
        };

        self.enqueue_request(request).await?;
        let result = rx.await?;
        Ok(result)
    }
}
