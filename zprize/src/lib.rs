// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeMap;

use aleo_std_profiler::{end_timer, start_timer};
use k256::ecdsa::{Signature, VerifyingKey};
use snarkvm_algorithms::{
    polycommit::kzg10::UniversalParams,
    snark::varuna::{CircuitProvingKey, CircuitVerifyingKey, VarunaHidingMode},
};
use snarkvm_console::program::Itertools;
use snarkvm_curves::bls12_377::Bls12_377;

pub mod api;
pub mod circuit;
pub mod console;
pub mod r1cs_provider;

// Config code here for testing KECCAK or ECDSA only
pub const ENABLE_CIRCUIT_FOR_KECCAK: bool = true;
pub const ENABLE_CIRCUIT_FOR_ECDSA: bool = false;

/// A (public key, msg, signature) tuple.
pub type Tuples<'a> = &'a [(VerifyingKey, Vec<u8>, Signature)];

pub fn prove_and_verify(
    urs: &UniversalParams<Bls12_377>,
    circuit_keys: &[(
        CircuitProvingKey<Bls12_377, VarunaHidingMode>,
        CircuitVerifyingKey<Bls12_377>,
    )],
    tuples: Tuples,
) {
    // TODO: test could be adjusted to pass references and clone less
    let pks = circuit_keys.iter().map(|key| &key.0).collect_vec();
    let prove_time = start_timer!(|| format!("Generate proof for all {} tuples", tuples.len()));
    let (proof, all_inputs) = api::prove(urs, &pks, tuples);
    end_timer!(prove_time);

    // Note: proof verification should take negligible time,
    let mut vks_to_inputs = BTreeMap::new();
    circuit_keys
        .iter()
        .map(|key| &key.1)
        .zip_eq(&all_inputs)
        .for_each(|(vks, inputs)| {
            vks_to_inputs.insert(vks, &inputs[..]);
        });
    let verify_time = start_timer!(|| format!("Verify proof for all {} tuples", tuples.len()));
    api::verify_proof(urs, &proof, &vks_to_inputs);
    end_timer!(verify_time);
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;



    #[test]
    fn it_works() {
        // generate `num` (pubkey, msg, signature)
        // with messages of length `msg_len`
        let num = 10;
        let msg_len = 50000;
        // let msg_len = 100;
        let tuples = console::generate_signatures(msg_len, num);

        // setup
        let urs = api::setup(1000, 1000, 1000);
        let circuit_keys = api::compile(&urs, num, msg_len);

        // prove and verify
        prove_and_verify(&urs, &circuit_keys, &tuples);
    }

    #[test]
    fn download_towns_of_blobs() -> Result<()> {
        snarkvm_parameters::testnet3::Degree16::load_bytes()?;
        snarkvm_parameters::testnet3::Degree17::load_bytes()?;
        snarkvm_parameters::testnet3::Degree18::load_bytes()?;
        snarkvm_parameters::testnet3::Degree19::load_bytes()?;
        snarkvm_parameters::testnet3::Degree20::load_bytes()?;
        snarkvm_parameters::testnet3::Degree21::load_bytes()?;
        snarkvm_parameters::testnet3::Degree22::load_bytes()?;
        snarkvm_parameters::testnet3::Degree23::load_bytes()?;
        snarkvm_parameters::testnet3::Degree24::load_bytes()?;

        snarkvm_parameters::testnet3::ShiftedDegree16::load_bytes()?;
        snarkvm_parameters::testnet3::ShiftedDegree17::load_bytes()?;
        snarkvm_parameters::testnet3::ShiftedDegree18::load_bytes()?;
        snarkvm_parameters::testnet3::ShiftedDegree19::load_bytes()?;
        snarkvm_parameters::testnet3::ShiftedDegree20::load_bytes()?;
        snarkvm_parameters::testnet3::ShiftedDegree21::load_bytes()?;
        snarkvm_parameters::testnet3::ShiftedDegree22::load_bytes()?;
        snarkvm_parameters::testnet3::ShiftedDegree23::load_bytes()?;
        snarkvm_parameters::testnet3::ShiftedDegree24::load_bytes()?;

        Ok(())
    }
}
