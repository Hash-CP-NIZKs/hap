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

use anyhow::Context;
use log::{debug, info};
use rand::rngs::OsRng;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use snarkvm_algorithms::{
    crypto_hash::PoseidonSponge,
    polycommit::kzg10::UniversalParams,
    snark::varuna::{self, AHPForR1CS, CircuitProvingKey, CircuitVerifyingKey, VarunaHidingMode},
    traits::SNARK,
};
use snarkvm_circuit::{
    environment::{Assignment, Circuit},
    Environment as _,
};
use snarkvm_circuit_environment::SameCircuitAssignment;
use snarkvm_console::{network::Testnet3 as Network, program::Itertools};
use snarkvm_console_network::Network as _;
use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
use std::{collections::BTreeMap, sync::Arc, time::Instant};

use crate::{r1cs_provider, TestCase};

//
// Aliases
// =======
//

type FS = PoseidonSponge<Fq, 2, 1>;
type VarunaInst = varuna::VarunaSNARK<Bls12_377, FS, VarunaHidingMode>;

//
// Functions
// =========
//

/// Our circuit synthesizer for ecdsa.
///
pub fn run_circuit(test_case: TestCase) -> Assignment<Fr> {
    // reset circuit writer
    Circuit::reset();

    r1cs_provider::gnark::build_r1cs(test_case)
        .context("failed to build circuit")
        .unwrap();

    // return circuit
    Circuit::eject_assignment_and_reset()
}

/// Setup the parameters.
pub fn setup(
    num_constraints: usize,
    num_variables: usize,
    num_non_zero: usize,
) -> UniversalParams<Bls12_377> {
    // Note: you can change this to increase the size of the circuit.
    // Of course, the higher these values, the slower the prover...
    let max_degree = AHPForR1CS::<Fr, VarunaHidingMode>::max_degree(
        num_constraints,
        num_variables,
        num_non_zero,
    )
    .unwrap();
    VarunaInst::universal_setup(max_degree).unwrap()
}

/// Compile the circuit.
pub fn compile(
    test_case: TestCase,
    urs: &UniversalParams<Bls12_377>,
) -> (
    CircuitProvingKey<Bls12_377, VarunaHidingMode>,
    CircuitVerifyingKey<Bls12_377>,
) {
    info!("compile circuit for {test_case:?}");

    // Let's get one of the circuits
    let circuit = run_circuit(test_case);
    debug!("circuit: num constraints: {}", circuit.num_constraints());
    debug!(
        "circuit: num lookup tables: {}",
        circuit.num_lookup_tables()
    );
    debug!(
        "circuit: num lookup constraints: {}",
        circuit.num_lookup_constraints()
    );
    debug!("circuit: num public: {}", circuit.num_public());
    debug!("circuit: num private: {}", circuit.num_private());
    debug!(
        "circuit: num non-zeros(both non-lookup and lookup): {:?}",
        circuit.num_nonzeros()
    );

    VarunaInst::batch_circuit_setup(&urs, &[&circuit])
        .unwrap()
        .into_iter()
        .next()
        .expect("there should be one and only one element")
}

/// Run and prove the circuit.
pub fn prove(
    test_case: TestCase,
    urs: &UniversalParams<Bls12_377>,
    pk: &CircuitProvingKey<Bls12_377, VarunaHidingMode>,
    batch_num: u32,
) -> (varuna::Proof<Bls12_377>, Vec<Vec<Fr>>) {
    let mut pks_to_constraints = BTreeMap::new();

    info!("Generate all circuits (with gnark)");
    let assignments;
    let base_assignment = run_circuit(test_case);

    if batch_num == 1 {
        assignments = Some(vec![SameCircuitAssignment::single_one(base_assignment)]);
        pks_to_constraints.insert(pk, &assignments.as_ref().unwrap()[..]);
    } else {
        let base_assignment = Arc::new(base_assignment);

        /* limit num of parallel tasks here for saving memory */
        let num_parallel_tasks = 5;
        assignments = Some(
            (0..batch_num)
                .into_par_iter()
                .with_min_len(batch_num as usize / num_parallel_tasks)
                .map(|_| {
                    // Note: we use a naive encoding here,
                    // you can modify it as long as a verifier can still pass tuples `(public key, msg, signature)`.
                    let assignment = run_circuit(test_case);
                    SameCircuitAssignment::create_with_base(base_assignment.clone(), assignment)
                })
                .collect::<Vec<_>>(),
        );

        pks_to_constraints.insert(pk, &assignments.as_ref().unwrap()[..]);
    }

    info!("Compute the proof");
    let rng = &mut OsRng::default();
    let universal_prover = urs.to_universal_prover().unwrap();
    let fiat_shamir = Network::varuna_fs_parameters();

    let start = Instant::now();
    let proof =
        VarunaInst::prove_batch(&universal_prover, fiat_shamir, &pks_to_constraints, rng).unwrap();
    let duration = start.elapsed();
    info!("Compute the proof finished ({duration:?})");

    /* Prepare inputs for verifier, this should be verify fast since it is just memory copy ... */
    info!("Prepare inputs for verifier");

    let inputs = assignments
        .as_ref()
        .unwrap()
        .iter()
        .map(|assignment| {
            assignment
                .public_inputs()
                .iter()
                .map(|(_, input)| *input)
                .collect_vec()
        })
        .collect_vec();

    (proof, inputs)
}

/// Verify a proof.
pub fn verify_proof(
    urs: &UniversalParams<Bls12_377>,
    proof: &varuna::Proof<Bls12_377>,
    vks_to_inputs: &BTreeMap<&CircuitVerifyingKey<Bls12_377>, &[Vec<Fr>]>,
) {
    // verify
    let fiat_shamir = Network::varuna_fs_parameters();
    let universal_verifier = urs.to_universal_verifier().unwrap();

    // Note: same comment here, verify_batch could verify several proofs instead of one ;)
    info!("Verify the proof");
    let start = Instant::now();
    VarunaInst::verify_batch(&universal_verifier, fiat_shamir, vks_to_inputs, proof).unwrap();
    let duration = start.elapsed();
    info!("Verify the proof finished ({duration:?})");
}
