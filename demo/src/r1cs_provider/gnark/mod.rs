use aleo_std_profiler::{end_timer, start_timer};
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use scopeguard::defer;
use std::env;
use std::process::Command;
use std::process::Stdio;
use tempfile::Builder;

use crate::TestCase;

pub fn build_r1cs(test_case: TestCase) -> Result<()> {
    let build_time = start_timer!(|| "build_r1cs()");
    defer! {
        end_timer!(build_time);
    }

    let _tmp_dir = Builder::new().prefix("hap").tempdir()?;
    let tmp_dir = _tmp_dir.path();

    // go run your_program.go -pk_x "123456789012345678901234567890" -pk_y "987654321098765432109876543210" -sig_r "112233445566778899001122334455" -sig_s "998877665544332211009988776655" -hash "123123123123123123123123123123"
    let output_dir = tmp_dir.join("output");
    std::fs::create_dir_all(&output_dir)
        .with_context(|| format!("Failed to create output dir at: {output_dir:?}"))?;
    run_external_process(
        Command::new(env::current_dir()?.join("../gnark-circuit-gen/main"))
            .args(&[match test_case {
                TestCase::Test1 => "test1",
                TestCase::Test2 => "test2",
                TestCase::Test3 => "test3",
            }])
            .current_dir(&tmp_dir),
    )
    .context("Failed to execute gnark-circuit-gen")?;

    let ret = super::builder::construct_r1cs_from_file(
        output_dir.join("r1cs.cbor"),
        output_dir.join("assignment.cbor"),
        Some(output_dir.join("lookup.cbor")),
    );
    ret
}

fn run_external_process(cmd: &mut Command) -> Result<()> {
    debug!("run cmd: {:?}", cmd);
    cmd.stdout(Stdio::null());
    cmd.stdin(Stdio::null());
    cmd.stderr(Stdio::null());
    let status = cmd
        .status()
        .with_context(|| format!("Failed to execute{:?}", cmd))?;
    if !status.success() {
        bail!("Run process {:?} exited: {}", cmd, status);
    }
    Ok(())
}
