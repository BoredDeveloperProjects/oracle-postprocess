mod common;

use std::fs;
use std::time::Duration;

use common::{
    build_rbxlx_fixture, expected_script_output, mock_decompilation, plain_cdata, script_cdata,
    sha256_hex, spawn_mock_server, synthetic_bytecode, temp_file_path, MAX_BYTES_IN_FLIGHT,
};
use oracle_postprocess::decompiler::{DecompilationRequest, Decompiler};
use oracle_postprocess::rbxlx::process_rbxlx_file;
use sha2::{Digest, Sha256};
use tokio::sync::oneshot;

#[tokio::test]
async fn process_rbxlx_file_roundtrips_and_deduplicates_requests() {
    let script_a = "QUJDREVGRw==";
    let script_b = "SElKS0xtbg==";
    let fixture = build_rbxlx_fixture(&[
        script_cdata(script_a),
        plain_cdata("plain <![CDATA[ content stays here"),
        script_cdata(script_a),
        script_cdata(script_b),
    ]);

    let input_path = temp_file_path("roundtrip-input", "rbxlx");
    let output_path = temp_file_path("roundtrip-output", "rbxlx");
    fs::write(&input_path, fixture).expect("failed to write input fixture");

    let server = spawn_mock_server(Duration::from_millis(1))
        .await
        .expect("failed to start mock server");
    let decompiler = Decompiler::new(&server.url, "test-key")
        .await
        .expect("failed to construct decompiler");

    process_rbxlx_file(
        &decompiler,
        input_path.to_str().expect("non-utf8 input path"),
        output_path.to_str().expect("non-utf8 output path"),
    )
    .await
    .expect("rbxlx processing failed");

    let script_a_count = server_hash_count(&server, script_a);
    let script_b_count = server_hash_count(&server, script_b);
    drop(decompiler);
    server.finish().await;

    let output = fs::read_to_string(&output_path).expect("failed to read processed output");
    let expected = build_rbxlx_fixture(&[
        expected_script_output(script_a),
        plain_cdata("plain <![CDATA[ content stays here"),
        expected_script_output(script_a),
        expected_script_output(script_b),
    ]);

    assert_eq!(output, expected);
    assert_eq!(mock_decompilation(script_a), format!("print(\"{}\")", sha256_hex(script_a)));
    assert_eq!(script_a_count, 1);
    assert_eq!(script_b_count, 1);

    let _ = fs::remove_file(input_path);
    let _ = fs::remove_file(output_path);
}

#[tokio::test]
async fn decompiler_transport_batches_fifo_and_caps_inflight_bytes() {
    let first = synthetic_bytecode('A', 3 * 1024 * 1024);
    let second = synthetic_bytecode('B', 3 * 1024 * 1024);
    let third = synthetic_bytecode('C', 3 * 1024 * 1024);
    let fourth = synthetic_bytecode('D', 1024 * 1024);
    let duplicate_third = third.clone();

    let server = spawn_mock_server(Duration::from_millis(25))
        .await
        .expect("failed to start mock server");
    let decompiler = Decompiler::new(&server.url, "test-key")
        .await
        .expect("failed to construct decompiler");

    let requests = vec![
        request_for(&first),
        request_for(&second),
        request_for(&third),
        request_for(&fourth),
        request_for(&duplicate_third),
    ];
    let (batch, receivers): (Vec<_>, Vec<_>) = requests.into_iter().unzip();

    decompiler
        .decompile_batch(batch)
        .await
        .expect("failed to enqueue decompile batch");

    let mut results = Vec::new();
    for receiver in receivers {
        results.push(receiver.await.expect("response channel closed"));
    }

    let received_hashes = server.received_hashes();
    let max_inflight = server.max_inflight_bytes();
    let third_count = server_hash_count(&server, &third);
    drop(decompiler);
    server.finish().await;

    assert_eq!(
        received_hashes,
        vec![
            sha256_hex(&first),
            sha256_hex(&second),
            sha256_hex(&third),
            sha256_hex(&fourth),
        ]
    );
    assert!(max_inflight <= MAX_BYTES_IN_FLIGHT);
    assert_eq!(third_count, 1);
    assert_eq!(results[0], Ok(mock_decompilation(&first)));
    assert_eq!(results[1], Ok(mock_decompilation(&second)));
    assert_eq!(results[2], Ok(mock_decompilation(&third)));
    assert_eq!(results[3], Ok(mock_decompilation(&fourth)));
    assert_eq!(results[4], Ok(mock_decompilation(&duplicate_third)));
}

fn request_for(bytecode: &str) -> (DecompilationRequest, oneshot::Receiver<Result<String, String>>) {
    let (tx, rx) = oneshot::channel();
    (
        DecompilationRequest {
            bytecode: bytecode.into(),
            bytecode_hash: format!("{:x}", Sha256::digest(bytecode.as_bytes())),
            bytecode_len: bytecode.len() as u32,
            tx,
        },
        rx,
    )
}

fn server_hash_count(server: &common::MockServer, bytecode: &str) -> usize {
    server.hash_count(&sha256_hex(bytecode))
}
