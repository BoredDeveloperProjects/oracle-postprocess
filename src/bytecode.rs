pub const BYTECODE_START_LF: &[u8] = b"-- Bytecode (Base64):\n-- ";
pub const BYTECODE_START_CRLF: &[u8] = b"-- Bytecode (Base64):\r\n-- ";

pub struct EmbeddedBytecode<'a> {
    pub header: &'a str,
    pub bytecode: &'a str,
}

pub fn is_bytecode(data: &[u8]) -> bool {
    if data.len() < 5 {
        return false;
    }

    let header = &data[0..4];
    let first_byte = data[0];

    header == [0x1b, b'L', b'u', b'a']
        || header == [0x1b, b'L', b'J', 0x1]
        || header == [0x1b, b'L', b'J', 0x2]
        || matches!(first_byte, 3..=8)
}

pub fn extract_embedded_bytecode(input: &str) -> Option<EmbeddedBytecode<'_>> {
    let bytes = input.as_bytes();
    let (start, marker_len) = find_marker(bytes)?;
    let bytecode_start = start + marker_len;
    let bytecode_end = bytecode_start
        + bytes[bytecode_start..]
            .iter()
            .position(|&byte| byte == b'\n' || byte == b'\r')
            .unwrap_or(bytes.len() - bytecode_start);

    Some(EmbeddedBytecode {
        header: &input[..bytecode_start],
        bytecode: &input[bytecode_start..bytecode_end],
    })
}

fn find_marker(bytes: &[u8]) -> Option<(usize, usize)> {
    find_subslice(bytes, BYTECODE_START_LF)
        .map(|position| (position, BYTECODE_START_LF.len()))
        .or_else(|| {
            find_subslice(bytes, BYTECODE_START_CRLF)
                .map(|position| (position, BYTECODE_START_CRLF.len()))
        })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::extract_embedded_bytecode;

    #[test]
    fn extracts_embedded_bytecode_with_lf() {
        let input = "prefix\n-- Bytecode (Base64):\n-- QUJDREVGRw==\nrest";
        let embedded = extract_embedded_bytecode(input).expect("expected embedded bytecode");

        assert_eq!(embedded.header, "prefix\n-- Bytecode (Base64):\n-- ");
        assert_eq!(embedded.bytecode, "QUJDREVGRw==");
    }

    #[test]
    fn extracts_embedded_bytecode_with_crlf() {
        let input = "prefix\r\n-- Bytecode (Base64):\r\n-- QUJDREVGRw==\r\nrest";
        let embedded = extract_embedded_bytecode(input).expect("expected embedded bytecode");

        assert_eq!(embedded.header, "prefix\r\n-- Bytecode (Base64):\r\n-- ");
        assert_eq!(embedded.bytecode, "QUJDREVGRw==");
    }
}
