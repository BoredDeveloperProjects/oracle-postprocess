use crate::bytecode::{extract_embedded_bytecode, is_bytecode};

pub fn get_bytecode_from_file(
    filename: &str,
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    use std::fs;

    let file_contents = fs::read(filename)?;
    get_bytecode_from_bytes(&file_contents)
}

pub fn get_bytecode_from_bytes(
    file_contents: &[u8],
) -> Result<(String, Option<String>), Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose, Engine as _};

    // check for direct bytecode
    if is_bytecode(file_contents) {
        let bytecode = general_purpose::STANDARD.encode(file_contents);
        return Ok((bytecode, None));
    }

    // try decoding as base64
    if let Ok(decoded) = general_purpose::STANDARD.decode(file_contents) {
        if is_bytecode(&decoded) {
            let bytecode = String::from_utf8_lossy(file_contents).into_owned();
            return Ok((bytecode, None));
        }
    }

    // try extracting from rbxlx-style header
    let file_string = String::from_utf8_lossy(file_contents);
    if let Some(embedded) = extract_embedded_bytecode(&file_string) {
        return Ok((
            embedded.bytecode.to_owned(),
            Some(embedded.header.to_owned()),
        ));
    }

    Err("no bytecode found in file".into())
}

#[cfg(test)]
mod tests {
    use super::get_bytecode_from_bytes;

    #[test]
    fn detects_raw_lua_bytecode() {
        let input = [0x1b, b'L', b'u', b'a', 0x51];
        let (bytecode, header) = get_bytecode_from_bytes(&input).expect("expected bytecode");

        assert_eq!(bytecode, "G0x1YVE=");
        assert_eq!(header, None);
    }

    #[test]
    fn detects_raw_luajit_bytecode() {
        let input = [0x1b, b'L', b'J', 0x2, 0x10];
        let (bytecode, header) = get_bytecode_from_bytes(&input).expect("expected bytecode");

        assert_eq!(bytecode, "G0xKAhA=");
        assert_eq!(header, None);
    }

    #[test]
    fn accepts_base64_encoded_bytecode() {
        let input = b"G0x1YVE=";
        let (bytecode, header) = get_bytecode_from_bytes(input).expect("expected bytecode");

        assert_eq!(bytecode, "G0x1YVE=");
        assert_eq!(header, None);
    }

    #[test]
    fn extracts_rbxlx_embedded_bytecode_with_lf() {
        let input = b"local x = 1\n-- Bytecode (Base64):\n-- QUJDREVGRw==\n-- suffix";
        let (bytecode, header) = get_bytecode_from_bytes(input).expect("expected bytecode");

        assert_eq!(bytecode, "QUJDREVGRw==");
        assert_eq!(header.as_deref(), Some("local x = 1\n-- Bytecode (Base64):\n-- "));
    }

    #[test]
    fn extracts_rbxlx_embedded_bytecode_with_crlf() {
        let input = b"local x = 1\r\n-- Bytecode (Base64):\r\n-- QUJDREVGRw==\r\n-- suffix";
        let (bytecode, header) = get_bytecode_from_bytes(input).expect("expected bytecode");

        assert_eq!(bytecode, "QUJDREVGRw==");
        assert_eq!(
            header.as_deref(),
            Some("local x = 1\r\n-- Bytecode (Base64):\r\n-- ")
        );
    }

    #[test]
    fn errors_when_no_bytecode_is_present() {
        let err = get_bytecode_from_bytes(b"print('hello')").expect_err("expected failure");
        assert_eq!(err.to_string(), "no bytecode found in file");
    }
}
