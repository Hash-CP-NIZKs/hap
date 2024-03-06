use std::fs::File;
use std::process::Command;
use aleo_std_profiler::{end_timer, start_timer};
use anyhow::bail;
use anyhow::Result;
use k256::elliptic_curve::sec1;

use tempfile::Builder;

use crate::console;

fn u64_4_from_slice(x: &[u8]) -> [u64; 4] {
    let array: [u64; 4] = x
        .chunks(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<u64>>()
        .try_into()
        .unwrap();
    array
}

pub fn build_r1cs_for_verify_plonky2(
    public_key: console::ECDSAPublicKey,
    signature: console::ECDSASignature,
    msg: Vec<Vec<u8>>,
) -> Result<()> {
    let pk = if let sec1::Coordinates::Uncompressed { x, y } =
        public_key.public_key.to_encoded_point(false).coordinates()
    {
        use plonky2_01::field::secp256k1_base::Secp256K1Base;
        use plonky2_ecdsa::curve::curve_types::AffinePoint;
        use plonky2_ecdsa::curve::ecdsa::ECDSAPublicKey;
        use plonky2_ecdsa::curve::secp256k1::Secp256K1;

        ECDSAPublicKey(AffinePoint::<Secp256K1>::nonzero(
            Secp256K1Base(u64_4_from_slice(&x.to_vec())),
            Secp256K1Base(u64_4_from_slice(&y.to_vec())),
        ))
    } else {
        unreachable!();
    };

    let sig = {
        use plonky2_01::field::secp256k1_scalar::Secp256K1Scalar;
        use plonky2_ecdsa::curve::ecdsa::ECDSASignature;
        use plonky2_ecdsa::curve::secp256k1::Secp256K1;
        let (r, s) = signature.signature.split_bytes();
        let r: Vec<u8> = r.to_vec();
        let s: Vec<u8> = s.to_vec();
        ECDSASignature {
            r: Secp256K1Scalar(u64_4_from_slice(&r)),
            s: Secp256K1Scalar(u64_4_from_slice(&s)),
        }
    };
    let hash_input = (0..10000).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    // plonky2_ecdsa::curve::curve_types::AffinePoint::<plonky2_ecdsa::curve::secp256k1::Secp256K1>::nonzero(x, y)
    let _tmp_dir = Builder::new().prefix("zprize-ecdsa-varuna").tempdir()?;
    let tmp_dir = _tmp_dir.path();
    // plonky2 kecaak && ecdsa -> json -> garnk-plonky2 -> cbor
    // TODO: call ganrk-plonky2-verifier and gnark-ecdsa-test to generate R1CS
    let (tuple, _) = plonky2_evm::hash2::prove_and_aggregate(pk, sig, vec![hash_input]).unwrap();

    let common_data_file =
        File::create("../gnark-plonky2-verifier/testdata/zprice/common_circuit_data.json").unwrap();
    serde_json::to_writer(&common_data_file, &tuple.2).unwrap();
    println!("Succesfully wrote common circuit data to common_circuit_data.json");

    let verifier_data_file =
        File::create("../gnark-plonky2-verifier/testdata/zprice/verifier_only_circuit_data.json")
            .unwrap();
    serde_json::to_writer(&verifier_data_file, &tuple.1).unwrap();
    println!("Succesfully wrote verifier data to verifier_only_circuit_data.json");

    let proof_file =
        File::create("../gnark-plonky2-verifier/testdata/zprice/proof_with_public_inputs.json")
            .unwrap();
    serde_json::to_writer(&proof_file, &tuple.0).unwrap();
    println!("Succesfully wrote proof to proof_with_public_inputs.json");

    std::process::Command::new("../gnark-plonky2-verifier/benchmark")
        .args(&["-proof-system", "groth16", "-plonky2-circuit", "zprize"])
        .current_dir("../gnark-plonky2-verifier")
        .status()
        .unwrap();
    // go run benchmark.go -proof-system groth16 -plonky2-circuit zprize

    let construct_time = start_timer!(|| "builder::construct_r1cs_from_file()");
    let ret = super::builder::construct_r1cs_from_file(
        "../gnark-plonky2-verifier/output/r1cs.cbor",
        "../gnark-plonky2-verifier/output/assignment.cbor",
        Some("../gnark-plonky2-verifier/output/lookup.cbor"),
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
