use anyhow;
use haxial::lcx_hx;
use hex;
use std::{env, fs};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Usage: {} <hex string>", args[0]);
        return Ok(());
    }

    let key = u32::from_str_radix(&args[1][0..8], 16)?;
    let mut data = hex::decode(&args[1][8..])?;

    lcx_hx(key, &mut data[..]);
    fs::write(format!("{:08X}.bin", key), &data[..])?;

    Ok(())
}
