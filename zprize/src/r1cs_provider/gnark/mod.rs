use std::process::Command;

use anyhow::bail;
use anyhow::Result;
use tempfile::Builder;
use aleo_std_profiler::{end_timer, start_timer};

pub fn build_r1cs_for_verify_plonky2() -> Result<()> {
    let _tmp_dir = Builder::new().prefix("zprize-ecdsa-varuna").tempdir()?;
    let tmp_dir = _tmp_dir.path();

    // TODO: call ganrk-plonky2-verifier and gnark-ecdsa-test to generate R1CS

    let construct_time = start_timer!(|| "builder::construct_r1cs_from_file()");
    let ret = super::builder::construct_r1cs_from_file(
        "/home/imlk/workspace/zprize/gnark-ecdsa-test/output/r1cs.cbor",
        "/home/imlk/workspace/zprize/gnark-ecdsa-test/output/assignment.cbor",
        Some("/home/imlk/workspace/zprize/gnark-ecdsa-test/output/lookup.cbor"),
    );
    end_timer!(construct_time);
    ret
}
