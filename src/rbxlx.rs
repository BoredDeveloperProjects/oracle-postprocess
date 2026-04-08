use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicU32, Ordering},
    Arc,
};

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use xml::reader::{EventReader, XmlEvent};
use xml::writer::{EmitterConfig, XmlEvent as WriteXmlEvent};

use crate::bytecode::extract_embedded_bytecode;
use crate::decompiler::{DecompilationRequest, Decompiler};

const IO_BUFFER_CAPACITY: usize = 8 * 1024 * 1024;
const WRITE_CHANNEL_CAPACITY: usize = 256;
const REPLACEMENT_CHARACTER: &[u8] = &[0xef, 0xbf, 0xbd];

enum ToWrite {
    XmlEvent(XmlEvent),
    DecompilationResult {
        header: String,
        bytecode: Arc<str>,
        rx: oneshot::Receiver<Result<String, String>>,
    },
}

struct Utf8BoundaryReader<R: Read> {
    inner: R,
    pending: Vec<u8>,
    pending_start: usize,
    output: Vec<u8>,
    output_start: usize,
    eof: bool,
}

impl<R: Read> Utf8BoundaryReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            pending: Vec::with_capacity(64 * 1024),
            pending_start: 0,
            output: Vec::with_capacity(64 * 1024),
            output_start: 0,
            eof: false,
        }
    }

    fn fill_pending(&mut self) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }

        self.compact_pending();

        let mut buf = [0u8; 64 * 1024];
        let read = self.inner.read(&mut buf)?;
        if read == 0 {
            self.eof = true;
        } else {
            self.pending.extend_from_slice(&buf[..read]);
        }

        Ok(())
    }

    fn process_pending(&mut self) -> io::Result<()> {
        loop {
            let pending_len = self.pending_slice().len();
            if pending_len == 0 {
                return Ok(());
            }

            match std::str::from_utf8(self.pending_slice()) {
                Ok(_) => {
                    self.append_pending_xml_bytes(pending_len);
                    self.consume_pending(pending_len);
                    return Ok(());
                }
                Err(error) => {
                    let valid_up_to = error.valid_up_to();
                    if valid_up_to > 0 {
                        self.append_pending_xml_bytes(valid_up_to);
                        self.consume_pending(valid_up_to);
                        return Ok(());
                    }

                    if error.error_len().is_none() && !self.eof {
                        self.fill_pending()?;
                        continue;
                    }

                    let invalid_len = error.error_len().unwrap_or(1).min(pending_len);
                    self.consume_pending(invalid_len);
                    self.output.extend_from_slice(REPLACEMENT_CHARACTER);
                    return Ok(());
                }
            }
        }
    }

    fn pending_slice(&self) -> &[u8] {
        &self.pending[self.pending_start..]
    }

    fn append_pending_xml_bytes(&mut self, len: usize) {
        let start = self.pending_start;
        let end = start + len;
        self.output.reserve(len);
        for &byte in &self.pending[start..end] {
            if is_xml_valid(byte) {
                self.output.push(byte);
            }
        }
    }

    fn consume_pending(&mut self, count: usize) {
        self.pending_start += count;
        if self.pending_start >= self.pending.len() {
            self.pending.clear();
            self.pending_start = 0;
        } else {
            self.compact_pending();
        }
    }

    fn compact_pending(&mut self) {
        if self.pending_start == 0 {
            return;
        }

        if self.pending_start >= self.pending.len() {
            self.pending.clear();
            self.pending_start = 0;
            return;
        }

        if self.pending_start >= 4096 || self.pending_start * 2 >= self.pending.len() {
            self.pending.drain(..self.pending_start);
            self.pending_start = 0;
        }
    }

    fn output_slice(&self) -> &[u8] {
        &self.output[self.output_start..]
    }

    fn consume_output(&mut self, count: usize) {
        self.output_start += count;
        if self.output_start >= self.output.len() {
            self.output.clear();
            self.output_start = 0;
        }
    }
}

impl<R: Read> Read for Utf8BoundaryReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        while self.output_slice().is_empty() {
            if self.pending_slice().is_empty() && !self.eof {
                self.fill_pending()?;
            }

            if self.pending_slice().is_empty() && self.eof {
                return Ok(0);
            }

            self.process_pending()?;
        }

        let available = self.output_slice();
        let written = available.len().min(out.len());
        out[..written].copy_from_slice(&available[..written]);
        self.consume_output(written);

        Ok(written)
    }
}

pub async fn process_rbxlx_file(
    decompiler: &Decompiler,
    input_file: &str,
    output_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let total_scripts = Arc::new(AtomicU32::new(0));
    let decompiled_count = Arc::new(AtomicU32::new(0));
    let total_events = Arc::new(AtomicU32::new(0));
    let written_events = Arc::new(AtomicU32::new(0));
    let reader_done = Arc::new(AtomicBool::new(false));

    let (write_tx, mut write_rx) = mpsc::channel::<ToWrite>(WRITE_CHANNEL_CAPACITY);
    let decompiled_count_clone = decompiled_count.clone();
    let written_events_clone = written_events.clone();
    let output_path = output_file.to_string();
    let writer_handle = tokio::spawn(async move {
        let file = File::create(&output_path)?;
        let mut buf_writer = BufWriter::with_capacity(IO_BUFFER_CAPACITY, file);
        let mut writer = EmitterConfig::new()
            .write_document_declaration(false)
            .create_writer(&mut buf_writer);

        while let Some(task) = write_rx.recv().await {
            match task {
                ToWrite::XmlEvent(event) => write_xml_event(&mut writer, event)?,
                ToWrite::DecompilationResult { header, bytecode, rx } => {
                    let result = match rx.await {
                        Ok(response) => response,
                        Err(_) => Err("oracle-postprocess error: sender dropped".to_string()),
                    };

                    let formatted_result = build_decompiled_cdata(&header, &bytecode, result);
                    decompiled_count_clone.fetch_add(1, Ordering::Relaxed);
                    writer.write(WriteXmlEvent::cdata(&formatted_result))?;
                }
            }

            written_events_clone.fetch_add(1, Ordering::Relaxed);
        }

        buf_writer.flush()?;

        if let Ok(metadata) = std::fs::metadata(&output_path) {
            println!("wrote {} KiB to {}", metadata.len() / 1024, output_path);
        } else {
            println!("wrote output file to {}", output_path);
        }

        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    let decompiled_count_clone = decompiled_count.clone();
    let total_scripts_clone = total_scripts.clone();
    let total_events_clone = total_events.clone();
    let written_events_clone = written_events.clone();
    let reader_done_clone = reader_done.clone();
    let progress_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            interval.tick().await;
            let decompiled = decompiled_count_clone.load(Ordering::Relaxed);
            let total = total_scripts_clone.load(Ordering::Relaxed);
            let total_ev = total_events_clone.load(Ordering::Relaxed);
            let written_ev = written_events_clone.load(Ordering::Relaxed);
            let is_reader_done = reader_done_clone.load(Ordering::Relaxed);

            if total_ev > 0 {
                let write_pct = (written_ev as f64 / total_ev as f64) * 100.0;
                if total > 0 {
                    let decompile_pct = (decompiled as f64 / total as f64) * 100.0;
                    println!(
                        "xml: {}/{} ({:.1}%) | decompiled: {}/{} ({:.1}%)",
                        written_ev, total_ev, write_pct, decompiled, total, decompile_pct
                    );
                } else {
                    println!("xml: {}/{} ({:.1}%)", written_ev, total_ev, write_pct);
                }
            }

            if is_reader_done && (total_ev == 0 || written_ev >= total_ev) {
                break;
            }
        }
    });

    let input_file_handle = File::open(input_file)?;
    let file = BufReader::with_capacity(IO_BUFFER_CAPACITY, input_file_handle);
    let utf8_reader = Utf8BoundaryReader::new(file);
    let parser = EventReader::new(utf8_reader);

    let mut event_count = 0u64;
    for event in parser {
        event_count += 1;
        match event {
            Ok(XmlEvent::CData(cdata_string)) => {
                total_events.fetch_add(1, Ordering::Relaxed);

                let Some(embedded) = extract_embedded_bytecode(&cdata_string) else {
                    send_write_task(&write_tx, ToWrite::XmlEvent(XmlEvent::CData(cdata_string))).await?;
                    continue;
                };

                total_scripts.fetch_add(1, Ordering::Relaxed);

                let header = embedded.header.to_owned();
                let bytecode: Arc<str> = Arc::from(embedded.bytecode);
                let (dec_tx, dec_rx) = oneshot::channel::<Result<String, String>>();
                let request = DecompilationRequest {
                    bytecode: bytecode.clone(),
                    bytecode_hash: format!("{:x}", Sha256::digest(bytecode.as_bytes())),
                    bytecode_len: bytecode.len() as u32,
                    tx: dec_tx,
                };

                decompiler.enqueue_request(request).await?;
                send_write_task(
                    &write_tx,
                    ToWrite::DecompilationResult {
                        header,
                        bytecode,
                        rx: dec_rx,
                    },
                )
                .await?;
            }
            Ok(xml_event) => {
                total_events.fetch_add(1, Ordering::Relaxed);
                send_write_task(&write_tx, ToWrite::XmlEvent(xml_event)).await?;
            }
            Err(error) => {
                eprintln!("xml parsing error at event #{}: {error}", event_count);
                return Err(error.into());
            }
        }
    }

    reader_done.store(true, Ordering::Relaxed);
    progress_handle.await?;
    drop(write_tx);

    let writer_result: Result<(), Box<dyn std::error::Error + Send + Sync>> = writer_handle.await?;
    if let Err(error) = writer_result {
        return Err(error.to_string().into());
    }

    if total_scripts.load(Ordering::Relaxed) == 0 {
        println!("no scripts found to decompile");
    }

    Ok(())
}

async fn send_write_task(
    write_tx: &mpsc::Sender<ToWrite>,
    task: ToWrite,
) -> Result<(), Box<dyn std::error::Error>> {
    write_tx.send(task).await.map_err(|_| {
        Box::new(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "writer task exited unexpectedly",
        )) as Box<dyn std::error::Error>
    })
}

fn write_xml_event<W: Write>(
    writer: &mut xml::writer::EventWriter<W>,
    event: XmlEvent,
) -> Result<(), xml::writer::Error> {
    match event {
        XmlEvent::StartElement {
            name, attributes, ..
        } => {
            use xml::name::Name;

            let mut builder = WriteXmlEvent::start_element(Name::local(name.local_name.as_str()));
            for attribute in &attributes {
                builder = builder.attr(
                    Name::local(attribute.name.local_name.as_str()),
                    attribute.value.as_str(),
                );
            }
            writer.write(builder)?;
        }
        XmlEvent::EndElement { .. } => writer.write(WriteXmlEvent::end_element())?,
        XmlEvent::CData(text) => writer.write(WriteXmlEvent::cdata(&text))?,
        XmlEvent::Characters(text) => writer.write(WriteXmlEvent::characters(&text))?,
        XmlEvent::Comment(text) => writer.write(WriteXmlEvent::comment(&text))?,
        XmlEvent::ProcessingInstruction { .. } | XmlEvent::StartDocument { .. } | XmlEvent::EndDocument => {}
        other => println!("unknownevent: {:?}", other),
    }

    Ok(())
}

fn build_decompiled_cdata(
    header: &str,
    bytecode: &str,
    result: Result<String, String>,
) -> String {
    let body_len = match &result {
        Ok(text) => text.len(),
        Err(text) => text.len(),
    };

    let mut output = String::with_capacity(header.len() + bytecode.len() + body_len + 64);
    push_cdata_escaped(&mut output, header);
    push_cdata_escaped(&mut output, bytecode);
    push_cdata_escaped(&mut output, "\n\n");

    match result {
        Ok(text) => {
            push_cdata_escaped(&mut output, "-- decompilation:\n");
            push_cdata_escaped(&mut output, &text);
        }
        Err(text) => {
            push_cdata_escaped(&mut output, "-- decompilation failed:\n-- ");
            push_cdata_escaped(&mut output, &text);
        }
    }

    push_cdata_escaped(&mut output, "\n");
    output
}

fn push_cdata_escaped(output: &mut String, input: &str) {
    let mut start = 0;
    while let Some(position) = input[start..].find("]]>") {
        let absolute = start + position;
        output.push_str(&input[start..absolute]);
        output.push_str("]]]]><![CDATA[>");
        start = absolute + 3;
    }
    output.push_str(&input[start..]);
}

fn is_xml_valid(byte: u8) -> bool {
    byte >= 0x20 || byte == b'\t' || byte == b'\n' || byte == b'\r'
}

#[cfg(test)]
mod tests {
    use super::build_decompiled_cdata;

    #[test]
    fn escapes_cdata_end_markers_in_decompiled_output() {
        let output = build_decompiled_cdata(
            "-- Bytecode (Base64):\n-- ",
            "QUJD",
            Ok("print(\"]]> inside\")".to_string()),
        );

        assert!(output.contains("]]]]><![CDATA[>"));
        assert!(output.contains("-- decompilation:\nprint("));
    }
}


