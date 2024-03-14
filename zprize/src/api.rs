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

use aleo_std_profiler::{end_timer, start_timer};
use anyhow::Context;
use rand::rngs::OsRng;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use sha3::{Digest, Keccak256};
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
use std::{collections::BTreeMap, sync::Arc};

use crate::console;
use crate::r1cs_provider;
use crate::Tuples;

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

pub fn run_circuit_keccak(msgs: Vec<Vec<u8>>) -> Assignment<Fr> {
    // reset circuit writer
    Circuit::reset();

    r1cs_provider::gnark::build_r1cs_for_verify_plonky2(msgs)
        .context("failed to build keccak circuit")
        .unwrap();

    // return circuit
    Circuit::eject_assignment_and_reset()
}

/// Our circuit synthesizer for ecdsa.
///
pub fn run_circuit_ecdsa(
    public_key: &console::ECDSAPublicKey,
    signature: &console::ECDSASignature,
    msg: &[u8],
) -> Assignment<Fr> {
    // reset circuit writer
    Circuit::reset();

    let mut hasher = Keccak256::new();
    hasher.update(&msg);
    let hash = hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("Wrong length");

    r1cs_provider::gnark::build_r1cs_for_verify_ecdsa(public_key, signature, &hash)
        .context("failed to build ecdsa circuit")
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
    urs: &UniversalParams<Bls12_377>,
    tuple_num: usize,
    msg_len: usize,
) -> Vec<(
    CircuitProvingKey<Bls12_377, VarunaHidingMode>,
    CircuitVerifyingKey<Bls12_377>,
)> {
    let msg = console::sample_msg(msg_len);
    let (public_key, signature) = console::sample_pubkey_sig(&msg);

    let mut unique_circuits = vec![];

    if crate::ENABLE_CIRCUIT_FOR_KECCAK {
        // Let's get a keccak circuit
        let keccak_circuit = run_circuit_keccak(
            // TODO: optimize this alloc
            (0..tuple_num)
                .into_iter()
                .map(|_| msg.clone())
                .collect_vec(),
        );
        println!(
            "keccak_circuit: num constraints: {}",
            keccak_circuit.num_constraints()
        );
        println!(
            "keccak_circuit: num lookup tables: {}",
            keccak_circuit.num_lookup_tables()
        );
        println!(
            "keccak_circuit: num lookup constraints: {}",
            keccak_circuit.num_lookup_constraints()
        );
        println!(
            "keccak_circuit: num public: {}",
            keccak_circuit.num_public()
        );
        println!(
            "keccak_circuit: num private: {}",
            keccak_circuit.num_private()
        );
        println!(
            "keccak_circuit: num non-zeros(both non-lookup and lookup): {:?}",
            keccak_circuit.num_nonzeros()
        );
        unique_circuits.push(keccak_circuit);
    }

    if crate::ENABLE_CIRCUIT_FOR_ECDSA {
        // Let's get a ecdsa circuit
        let ecdsa_circuit = run_circuit_ecdsa(&public_key, &signature, &msg);
        println!(
            "ecdsa_circuit: num constraints: {}",
            ecdsa_circuit.num_constraints()
        );
        println!(
            "ecdsa_circuit: num lookup tables: {}",
            ecdsa_circuit.num_lookup_tables()
        );
        println!(
            "ecdsa_circuit: num lookup constraints: {}",
            ecdsa_circuit.num_lookup_constraints()
        );
        println!("ecdsa_circuit: num public: {}", ecdsa_circuit.num_public());
        println!(
            "ecdsa_circuit: num private: {}",
            ecdsa_circuit.num_private()
        );
        println!(
            "ecdsa_circuit: num non-zeros(both non-lookup and lookup): {:?}",
            ecdsa_circuit.num_nonzeros()
        );
        unique_circuits.push(ecdsa_circuit);
    }

    let unique_circuits = unique_circuits.iter().map(|c| c).collect_vec();
    VarunaInst::batch_circuit_setup(&urs, &unique_circuits).unwrap()
}

/// Run and prove the circuit.
pub fn prove(
    urs: &UniversalParams<Bls12_377>,
    pks: &[&CircuitProvingKey<Bls12_377, VarunaHidingMode>],
    tuples: Tuples,
) -> varuna::Proof<Bls12_377> {
    let mut pks_to_constraints = BTreeMap::new();

    let keccak_assignments;
    if crate::ENABLE_CIRCUIT_FOR_KECCAK {
        let keccak_pk = pks[0];
        let keccak_assignment = run_circuit_keccak(
            // TODO: optimize this alloc
            tuples.iter().map(|t| t.1.clone()).collect_vec(),
        );
        keccak_assignments = [SameCircuitAssignment::single_one(keccak_assignment)];
        pks_to_constraints.insert(keccak_pk, &keccak_assignments[..]);
    }

    let ecdsa_assignments;
    if crate::ENABLE_CIRCUIT_FOR_ECDSA {
        let ecdsa_pk = if crate::ENABLE_CIRCUIT_FOR_KECCAK {
            pks[1]
        } else {
            pks[0]
        };

        let base_assignment = run_circuit_ecdsa(
            &console::ECDSAPublicKey {
                public_key: tuples[0].0.clone(),
            },
            &console::ECDSASignature {
                signature: tuples[0].2.clone(),
            },
            &tuples[0].1,
        );

        if tuples.len() == 1 {
            ecdsa_assignments = vec![SameCircuitAssignment::single_one(base_assignment)];
            pks_to_constraints.insert(ecdsa_pk, &ecdsa_assignments[..]);
        } else {
            let base_assignment = Arc::new(base_assignment);

            let num_parallel_tasks = 5;
            ecdsa_assignments = tuples
                .into_par_iter()
                .with_min_len(tuples.len() / num_parallel_tasks)
                .map(|tuple| {
                    // Note: we use a naive encoding here,
                    // you can modify it as long as a verifier can still pass tuples `(public key, msg, signature)`.
                    let (public_key, msg, signature) = tuple;
                    let assignment = run_circuit_ecdsa(
                        &console::ECDSAPublicKey {
                            public_key: public_key.clone(),
                        },
                        &console::ECDSASignature {
                            signature: signature.clone(),
                        },
                        msg,
                    );
                    SameCircuitAssignment::create_with_base(base_assignment.clone(), assignment)
                })
                .collect::<Vec<_>>();

            pks_to_constraints.insert(ecdsa_pk, &ecdsa_assignments[..]);
        }
    }

    // Compute the proof.
    let rng = &mut OsRng::default();
    let universal_prover = urs.to_universal_prover().unwrap();
    let fiat_shamir = Network::varuna_fs_parameters();
    let proof =
        VarunaInst::prove_batch(&universal_prover, fiat_shamir, &pks_to_constraints, rng).unwrap();
    proof
}

/// Verify a proof.
pub fn verify_proof(
    urs: &UniversalParams<Bls12_377>,
    vks: &[&CircuitVerifyingKey<Bls12_377>],
    tuples: Tuples,
    proof: &varuna::Proof<Bls12_377>,
) {
    // Note: this is a hacky way of formatting public inputs,
    // we shouldn't have to run the circuit to do that.

    let mut vks_to_inputs = BTreeMap::new();

    let keccak_inputs;
    if crate::ENABLE_CIRCUIT_FOR_KECCAK {
        let keccak_vk = vks[0];
        let keccak_assignment = run_circuit_keccak(
            // TODO: optimize this alloc
            tuples.iter().map(|t| t.1.clone()).collect_vec(),
        );
        let keccak_input = keccak_assignment
            .public_inputs()
            .iter()
            .map(|(_, input)| *input)
            .collect_vec();
        keccak_inputs = [keccak_input];
        vks_to_inputs.insert(keccak_vk, &keccak_inputs[..]);
    }

    let mut ecdsa_inputs;
    if crate::ENABLE_CIRCUIT_FOR_ECDSA {
        let ecdsa_vk = if crate::ENABLE_CIRCUIT_FOR_KECCAK {
            vks[1]
        } else {
            vks[0]
        };

        // TODO: optimize memory usage with SameCircuitAssignment
        ecdsa_inputs = Vec::with_capacity(tuples.len());
        for tuple in tuples {
            // Note: we use a naive encoding here,
            // you can modify it as long as a verifier can still pass tuples `(public key, msg, signature)`.
            let (public_key, msg, signature) = tuple;
            let ecdsa_assignment = run_circuit_ecdsa(
                &console::ECDSAPublicKey {
                    public_key: public_key.clone(),
                },
                &console::ECDSASignature {
                    signature: signature.clone(),
                },
                msg,
            );
            ecdsa_inputs.push(
                ecdsa_assignment
                    .public_inputs()
                    .iter()
                    .map(|(_, input)| *input)
                    .collect_vec(),
            );
        }
        vks_to_inputs.insert(ecdsa_vk, &ecdsa_inputs[..]);
    }

    // verify
    let fiat_shamir = Network::varuna_fs_parameters();
    let universal_verifier = urs.to_universal_verifier().unwrap();

    // Note: same comment here, verify_batch could verify several proofs instead of one ;)
    let time = start_timer!(|| "Run VarunaInst::verify_batch()");
    VarunaInst::verify_batch(&universal_verifier, fiat_shamir, &vks_to_inputs, proof).unwrap();
    end_timer!(time);
}
