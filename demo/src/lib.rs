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
use log::info;
use snarkvm_algorithms::{
    polycommit::kzg10::UniversalParams,
    snark::varuna::{CircuitProvingKey, CircuitVerifyingKey, VarunaHidingMode},
};
use snarkvm_curves::bls12_377::Bls12_377;

pub mod api;
pub mod r1cs_provider;

/// We have define a enum to control which the circuits to run
#[derive(Debug, Copy, Clone)]
pub enum TestCase {
    Test1,
    Test2,
    Test3,
}

pub fn prove_and_verify(
    test_case: TestCase,
    urs: &UniversalParams<Bls12_377>,
    circuit_keys: &(
        CircuitProvingKey<Bls12_377, VarunaHidingMode>,
        CircuitVerifyingKey<Bls12_377>,
    ),
    batch_num: u32,
) {
    info!("prove_and_verify for {test_case:?}");

    let pk = &circuit_keys.0;
    let prove_time = start_timer!(|| format!("Generate proof for a batch with size {batch_num}"));
    let (proof, inputs) = api::prove(test_case, urs, &pk, batch_num);
    end_timer!(prove_time);

    /* Prepare vks_to_inputs for verifier */
    let mut vks_to_inputs = BTreeMap::new();
    let vk = &circuit_keys.1;

    vks_to_inputs.insert(vk, &inputs[..]);

    // Note: proof verification should take negligible time,
    let verify_time = start_timer!(|| format!("Verify proof for a batch with size {batch_num}"));
    api::verify_proof(urs, &proof, &vks_to_inputs);
    end_timer!(verify_time);
}

#[cfg(test)]
mod tests {

    use anyhow::Result;

    #[test]
    fn download_tons_of_blobs() -> Result<()> {
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
