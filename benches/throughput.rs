#[path = "../tests/common/mod.rs"]
mod common;

use std::fs;
use std::hint::black_box;
use std::time::{Duration, Instant};

use oracle_postprocess::decompiler::Decompiler;
use oracle_postprocess::rbxlx::process_rbxlx_file;

use common::{
    build_rbxlx_fixture, plain_cdata, script_cdata, spawn_mock_server, synthetic_bytecode,
    temp_file_path,
};

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for benchmarks");

    runtime.block_on(async {
        run_scenario(
            "many-small",
            (0..64)
                .map(|index| {
                    let fill = (b'A' + (index % 16) as u8) as char;
                    script_cdata(&synthetic_bytecode(fill, 8 * 1024))
                })
                .collect(),
            3,
        )
        .await;

        run_scenario(
            "duplicate-heavy",
            {
                let repeated = script_cdata(&synthetic_bytecode('Z', 32 * 1024));
                let mut sources = vec![plain_cdata("metadata")];
                sources.extend((0..48).map(|_| repeated.clone()));
                sources
            },
            3,
        )
        .await;

        run_scenario(
            "large-near-cap",
            vec![
                script_cdata(&synthetic_bytecode('A', 3 * 1024 * 1024)),
                script_cdata(&synthetic_bytecode('B', 3 * 1024 * 1024)),
                script_cdata(&synthetic_bytecode('C', 1024 * 1024)),
            ],
            2,
        )
        .await;
    });
}

async fn run_scenario(name: &str, sources: Vec<String>, iterations: usize) {
    let fixture = build_rbxlx_fixture(&sources);
    let mut elapsed = Duration::ZERO;

    for iteration in 0..iterations {
        let input_path = temp_file_path(&format!("bench-{name}-{iteration}-input"), "rbxlx");
        let output_path = temp_file_path(&format!("bench-{name}-{iteration}-output"), "rbxlx");
        fs::write(&input_path, &fixture).expect("failed to write benchmark fixture");

        let server = spawn_mock_server(Duration::ZERO)
            .await
            .expect("failed to start benchmark mock server");
        let decompiler = Decompiler::new(&server.url, "bench-key")
            .await
            .expect("failed to construct benchmark decompiler");

        let start = Instant::now();
        process_rbxlx_file(
            &decompiler,
            input_path.to_str().expect("non-utf8 benchmark input path"),
            output_path.to_str().expect("non-utf8 benchmark output path"),
        )
        .await
        .expect("benchmark processing failed");
        elapsed += start.elapsed();

        black_box(fs::metadata(&output_path).expect("missing benchmark output").len());

        drop(decompiler);
        server.finish().await;

        let _ = fs::remove_file(input_path);
        let _ = fs::remove_file(output_path);
    }

    println!(
        "benchmark {name}: total {:?}, avg {:?}",
        elapsed,
        elapsed / iterations as u32
    );
}
