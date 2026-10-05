use capture_bound::copy_bound;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(source) = args.next() else { return usage() };
    let Some(destination) = args.next() else { return usage() };
    if args.next().is_some() || source == destination {
        return usage();
    }
    let mut input = match File::open(&source) {
        Ok(file) => file,
        Err(error) => return fail(error),
    };
    let mut output = match File::create(&destination) {
        Ok(file) => file,
        Err(error) => return fail(error),
    };
    match copy_bound(&mut input, &mut output) {
        Ok(bound) => {
            let _ = writeln!(
                io::stdout(),
                "{{\"packets\":{},\"included_bytes\":{},\"truncated\":{},\"stop_reason\":\"{}\"}}",
                bound.packets, bound.included_bytes, bound.truncated, bound.stop_reason
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(error),
    }
}

fn usage() -> ExitCode {
    let _ = writeln!(io::stderr(), "usage: capture_bound <input.pcap> <output.pcap>");
    ExitCode::from(2)
}

fn fail(error: io::Error) -> ExitCode {
    let _ = writeln!(io::stderr(), "{error}");
    ExitCode::from(1)
}
