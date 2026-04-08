#![allow(dead_code)]
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::{accept_async, tungstenite::Message};

pub const MAX_BYTES_IN_FLIGHT: usize = 8 * 1024 * 1024;

static NEXT_TEMP_FILE_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Default)]
struct MockServerState {
    received_hashes: Mutex<Vec<String>>,
    hash_counts: Mutex<HashMap<String, usize>>,
    current_inflight_bytes: AtomicUsize,
    max_inflight_bytes: AtomicUsize,
}

pub struct MockServer {
    pub url: String,
    state: Arc<MockServerState>,
    handle: JoinHandle<()>,
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ServerboundMessage {
    #[serde(rename = "decompile")]
    Decompile { data: Vec<String> },
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ClientboundMessage<'a> {
    #[serde(rename = "decompilation_result")]
    DecompilationResult {
        success: bool,
        data: &'a str,
        input_hash: &'a str,
    },
}

struct ResponseJob {
    input_hash: String,
    data: String,
    byte_len: usize,
}

impl MockServer {
    pub fn received_hashes(&self) -> Vec<String> {
        self.state
            .received_hashes
            .lock()
            .expect("mock server received hash mutex poisoned")
            .clone()
    }

    pub fn hash_count(&self, hash: &str) -> usize {
        self.state
            .hash_counts
            .lock()
            .expect("mock server hash count mutex poisoned")
            .get(hash)
            .copied()
            .unwrap_or(0)
    }

    pub fn max_inflight_bytes(&self) -> usize {
        self.state.max_inflight_bytes.load(Ordering::Relaxed)
    }

    pub async fn finish(self) {
        let _ = self.handle.await;
    }
}

pub async fn spawn_mock_server(response_delay: Duration) -> io::Result<MockServer> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let state = Arc::new(MockServerState::default());
    let state_for_task = state.clone();

    let handle = tokio::spawn(async move {
        let (stream, _) = match listener.accept().await {
            Ok(connection) => connection,
            Err(error) => {
                panic!("failed to accept test websocket connection: {error}");
            }
        };

        let websocket = accept_async(stream)
            .await
            .expect("failed to accept websocket handshake");
        let (write, mut read) = websocket.split();
        let write = Arc::new(tokio::sync::Mutex::new(write));
        let (response_tx, mut response_rx) = mpsc::unbounded_channel::<ResponseJob>();
        let write_for_sender = write.clone();
        let state_for_sender = state_for_task.clone();

        let sender_handle = tokio::spawn(async move {
            while let Some(job) = response_rx.recv().await {
                if !response_delay.is_zero() {
                    tokio::time::sleep(response_delay).await;
                }

                let payload = serde_json::to_string(&ClientboundMessage::DecompilationResult {
                    success: true,
                    data: &job.data,
                    input_hash: &job.input_hash,
                })
                .expect("failed to serialize mock response");

                let mut write = write_for_sender.lock().await;
                if write.send(Message::Text(payload.into())).await.is_err() {
                    break;
                }

                state_for_sender
                    .current_inflight_bytes
                    .fetch_sub(job.byte_len, Ordering::Relaxed);
            }
        });

        while let Some(message) = read.next().await {
            match message {
                Ok(Message::Text(text)) => {
                    let ServerboundMessage::Decompile { data } = serde_json::from_str(&text)
                        .expect("failed to decode mock serverbound payload");

                    for bytecode in data {
                        let input_hash = sha256_hex(&bytecode);

                        {
                            let mut received_hashes = state_for_task
                                .received_hashes
                                .lock()
                                .expect("mock server received hash mutex poisoned");
                            received_hashes.push(input_hash.clone());
                        }

                        {
                            let mut hash_counts = state_for_task
                                .hash_counts
                                .lock()
                                .expect("mock server hash count mutex poisoned");
                            *hash_counts.entry(input_hash.clone()).or_insert(0) += 1;
                        }

                        let inflight_now = state_for_task
                            .current_inflight_bytes
                            .fetch_add(bytecode.len(), Ordering::Relaxed)
                            + bytecode.len();
                        update_max(&state_for_task.max_inflight_bytes, inflight_now);

                        response_tx
                            .send(ResponseJob {
                                input_hash,
                                data: mock_decompilation(&bytecode),
                                byte_len: bytecode.len(),
                            })
                            .expect("mock response channel unexpectedly closed");
                    }
                }
                Ok(Message::Ping(payload)) => {
                    let mut write = write.lock().await;
                    let _ = write.send(Message::Pong(payload)).await;
                }
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }

        drop(response_tx);
        let _ = sender_handle.await;
    });

    Ok(MockServer {
        url: format!("ws://{}", address),
        state,
        handle,
    })
}

pub fn sha256_hex(input: &str) -> String {
    format!("{:x}", Sha256::digest(input.as_bytes()))
}

pub fn mock_decompilation(bytecode: &str) -> String {
    format!("print(\"{}\")", sha256_hex(bytecode))
}

pub fn script_cdata(bytecode: &str) -> String {
    format!("<![CDATA[-- Bytecode (Base64):\n-- {}]]>", bytecode)
}

pub fn plain_cdata(text: &str) -> String {
    format!("<![CDATA[{}]]>", text)
}

pub fn build_rbxlx_fixture(sources: &[String]) -> String {
    let mut output = String::from("<roblox>");
    for source in sources {
        output.push_str("<Item class=\"LocalScript\"><ProtectedString name=\"Source\">");
        output.push_str(source);
        output.push_str("</ProtectedString></Item>");
    }
    output.push_str("</roblox>");
    output
}

pub fn expected_script_output(bytecode: &str) -> String {
    format!(
        "<![CDATA[-- Bytecode (Base64):\n-- {}\n\n-- decompilation:\n{}\n]]>",
        bytecode,
        mock_decompilation(bytecode)
    )
}

pub fn synthetic_bytecode(fill: char, len: usize) -> String {
    std::iter::repeat_n(fill, len).collect()
}

pub fn temp_file_path(prefix: &str, extension: &str) -> PathBuf {
    let id = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "oracle-postprocess-{}-{}-{}.{}",
        prefix,
        std::process::id(),
        id,
        extension
    ));
    path
}

pub fn update_max(maximum: &AtomicUsize, candidate: usize) {
    let mut current = maximum.load(Ordering::Relaxed);
    while candidate > current {
        match maximum.compare_exchange(current, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

