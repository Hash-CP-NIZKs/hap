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
        "../gnark-ecdsa-test/output/r1cs.cbor",
        "../gnark-ecdsa-test/output/assignment.cbor",
        Some("../gnark-ecdsa-test/output/lookup.cbor"),
    );
    end_timer!(construct_time);
    ret
}
// input: 50 * data

// (1) keccak <- input * 50 -> 1 proof , 50 * hash  | 1 * proof with ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>, VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>, CommonCircuitData<GoldilocksField, 2>
// gnark-verifier <- 3*json
//  ->  r1cs(3*json) -> veruna
// ------
// gnark-ecdsa <- 


// output: proof