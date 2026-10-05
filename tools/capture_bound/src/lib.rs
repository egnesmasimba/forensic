//! Copy a bounded prefix of a classic PCAP. Packet bytes are not printed.
use std::io::{self, Read, Write};

pub const MAX_PACKETS: usize = 1000;
pub const MAX_BYTES: usize = 1_000_000;

#[derive(Debug, PartialEq, Eq)]
pub struct Bound {
    pub packets: usize,
    pub included_bytes: usize,
    pub truncated: bool,
    pub stop_reason: &'static str,
}

pub fn copy_bound(input: &mut impl Read, output: &mut impl Write) -> io::Result<Bound> {
    let mut header = [0u8; 24];
    input.read_exact(&mut header)?;
    let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let little = magic == 0xA1B2C3D4;
    if !little && u32::from_be_bytes(header[0..4].try_into().unwrap()) != 0xA1B2C3D4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "classic pcap magic required"));
    }
    output.write_all(&header)?;
    let mut result = Bound { packets: 0, included_bytes: 0, truncated: false, stop_reason: "end" };
    let mut record = [0u8; 16];
    loop {
        if result.packets >= MAX_PACKETS {
            result.truncated = true;
            result.stop_reason = "packet budget";
            return Ok(result);
        }
        match input.read_exact(&mut record) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(result),
            Err(error) => return Err(error),
        }
        let size = if little {
            u32::from_le_bytes(record[8..12].try_into().unwrap())
        } else {
            u32::from_be_bytes(record[8..12].try_into().unwrap())
        } as usize;
        if size > 65535 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet length is outside the capture bound"));
        }
        if result.included_bytes + size > MAX_BYTES {
            result.truncated = true;
            result.stop_reason = "byte budget";
            return Ok(result);
        }
        let mut body = vec![0u8; size];
        input.read_exact(&mut body)?;
        output.write_all(&record)?;
        output.write_all(&body)?;
        result.packets += 1;
        result.included_bytes += size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn header() -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        raw.extend_from_slice(&2u16.to_le_bytes());
        raw.extend_from_slice(&4u16.to_le_bytes());
        raw.extend_from_slice(&0i32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&65535u32.to_le_bytes());
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw
    }

    fn packet(raw: &mut Vec<u8>, body: &[u8]) {
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes());
        raw.extend_from_slice(&(body.len() as u32).to_le_bytes());
        raw.extend_from_slice(&(body.len() as u32).to_le_bytes());
        raw.extend_from_slice(body);
    }

    #[test]
    fn stops_before_a_packet_that_would_pass_the_byte_budget() {
        let body = vec![b'x'; 60_000];
        let mut input = header();
        for _ in 0..17 {
            packet(&mut input, &body);
        }
        let mut output = Vec::new();
        let bound = copy_bound(&mut Cursor::new(input), &mut output).unwrap();
        assert_eq!(bound.packets, 16);
        assert!(bound.truncated);
        assert_eq!(bound.stop_reason, "byte budget");
        assert_eq!(output.len(), 24 + 16 * (16 + body.len()));
    }
}
