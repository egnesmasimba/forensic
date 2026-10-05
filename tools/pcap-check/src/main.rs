//! Bounded, streaming classic-PCAP structural validation. No packet payload is printed.
use std::{env, fs::File, io::{Read, BufReader}};
fn check(mut input: impl Read) -> Result<(u64,u64), String> {
    let mut h=[0u8;24]; input.read_exact(&mut h).map_err(|_| "truncated PCAP header")?;
    let (little, resolution)=match &h[..4] {
        [0xd4,0xc3,0xb2,0xa1] => (true,1_000_000),
        [0xa1,0xb2,0xc3,0xd4] => (false,1_000_000),
        [0x4d,0x3c,0xb2,0xa1] => (true,1_000_000_000),
        [0xa1,0xb2,0x3c,0x4d] => (false,1_000_000_000),
        _ => return Err("expected classic PCAP (PCAPNG is handled by the Python sensor)".into())
    };
    let u32at=|b:&[u8]| { let a:[u8;4]=b.try_into().unwrap(); if little {u32::from_le_bytes(a)} else {u32::from_be_bytes(a)} };
    let version=if little {[2,0,4,0]} else {[0,2,0,4]};
    if h[4..8]!=version {return Err("unsupported PCAP version".into());}
    let snap=u32at(&h[16..20]);
    if snap==0 || snap>1_048_576 {return Err("invalid snapshot length".into());}
    if ![1,101,113,276].contains(&u32at(&h[20..24])) {return Err("unsupported link type".into());}
    let mut packets=0u64; let mut bytes=0u64; let mut buffer=[0u8;8192];
    loop {
        let mut r=[0u8;16];
        match input.read(&mut r[..1]) {Ok(0)=>break, Ok(_)=>(), Err(e)=>return Err(e.to_string())}
        input.read_exact(&mut r[1..]).map_err(|_| "truncated record header")?;
        let size=u32at(&r[8..12]);
        if size>snap || size>u32at(&r[12..16]) || u32at(&r[4..8])>=resolution {return Err("invalid packet record".into());}
        packets+=1; bytes+=size as u64;
        if packets>1_000_000 || bytes>1_073_741_824 {return Err("capture exceeds safety limits".into());}
        let mut remaining=size as usize;
        while remaining>0 {let n=remaining.min(buffer.len()); input.read_exact(&mut buffer[..n]).map_err(|_| "truncated packet")?; remaining-=n;}
    }
    Ok((packets,bytes))
}
fn main() {
    let args:Vec<String>=env::args().collect();
    if args.len()!=2 {eprintln!("usage: pcap-check capture.pcap"); std::process::exit(2);}
    let result=File::open(&args[1]).map_err(|e|e.to_string()).and_then(|f|check(BufReader::new(f)));
    match result {Ok((packets,bytes))=>println!("{{\"packets\":{packets},\"captured_bytes\":{bytes}}}"), Err(e)=>{eprintln!("{e}");std::process::exit(1);}}
}
#[cfg(test)] mod tests {
    use super::*;
    fn header()->Vec<u8> {let mut v=vec![0xd4,0xc3,0xb2,0xa1,2,0,4,0]; v.extend([0;8]); v.extend(65535u32.to_le_bytes());v.extend(1u32.to_le_bytes());v}
    #[test] fn empty_and_truncated() {assert_eq!(check(&header()[..]).unwrap(),(0,0));assert!(check(&header()[..23]).is_err());}
    #[test] fn rejects_short_payload() {let mut v=header();v.extend([0;8]);v.extend(4u32.to_le_bytes());v.extend(4u32.to_le_bytes());v.push(0);assert!(check(&v[..]).is_err());}
    #[test] fn accepts_packet() {let mut v=header();v.extend([0;8]);v.extend(4u32.to_le_bytes());v.extend(4u32.to_le_bytes());v.extend([0;4]);assert_eq!(check(&v[..]).unwrap(),(1,4));}
}
