use anyhow::Context;
use snarkvm_algorithms::r1cs::LookupTable;
use snarkvm_circuit::environment::Circuit;
use snarkvm_circuit_environment::{prelude::PrimeField, Eject, Environment, Inject, Mode};
use snarkvm_console_network::{prelude::Itertools, Testnet3};
use snarkvm_utilities::biginteger::BigInteger;

// TODO: better to use AleoV0 or Circuit?
use snarkvm_circuit::{Circuit as Env, Field};

use crate::{console, r1cs_provider};
//use snarkvm_circuit::{AleoV0 as Env, Field};

//
// Aliases
// =======
//

type F = Field<Env>;

//
// Data structures
// ===============
//
// We use the Bls12_377 curve to instantiate Varuna.
// This means that the circuit field (Fr) is modulo the following prime:
//
// 8444461749428370424248824938781546531375899335154063827935233455917409239041
//
// To verify ECDSA signatures with the secp256k1 curve,
// we have to handle scalar field and base field elements:
//
// - scalar field: 115792089237316195423570985008687907852837564279074904382605163141518161494337
// - base field: 115792089237316195423570985008687907853269984665640564039457584007908834671663
//
// Both of these are larger than our circuit field.
// While both the secp256k1 fields are 256 bits, the Bls12_377 circuit field is 253 bits.
// So this means we'll have to cut things up.
//
// Since the job is really on you to figure out how to optimize sutff,
// we use a super naive way to encode things: 1 field = 1 byte.
//

pub struct ECDSAPublicKey {
    bytes: Vec<F>,
}

pub struct ECDSASignature {
    bytes: Vec<F>,
}

pub struct Message {
    bytes: Vec<F>,
}

//
// Trait implementations
// =====================
//

impl Inject for Message {
    type Primitive = Vec<u8>;

    fn new(mode: Mode, message: Self::Primitive) -> Self {
        match mode {
            // we'd have to constrain things to be bytes
            Mode::Private => unimplemented!(),
            Mode::Constant | Mode::Public => Message {
                bytes: message
                    .iter()
                    .map(|b| {
                        let f = snarkvm_console::types::Field::from_u8(*b);
                        F::new(mode, f)
                    })
                    .collect_vec(),
            },
        }
    }
}

impl Eject for Message {
    type Primitive = Vec<u8>;

    fn eject_mode(&self) -> Mode {
        self.bytes[0].eject_mode()
    }

    fn eject_value(&self) -> Self::Primitive {
        self.bytes
            .iter()
            .map(|b| {
                let f = b.eject_value();
                let big = f.to_bigint();
                let res = big.to_biguint().to_bytes_le();
                assert_eq!(res.len(), 1);
                res[0]
            })
            .collect_vec()
    }
}

impl Inject for ECDSAPublicKey {
    type Primitive = super::console::ECDSAPublicKey;

    fn new(mode: Mode, public_key: Self::Primitive) -> Self {
        match mode {
            // might have to check point size
            Mode::Private => unimplemented!(),
            Mode::Constant | Mode::Public => {
                let public_key = public_key
                    .public_key
                    .to_encoded_point(true)
                    .as_bytes()
                    .iter()
                    .map(|b| {
                        let f = snarkvm_console::types::Field::from_u8(*b);
                        F::new(mode, f)
                    })
                    .collect_vec();
                Self { bytes: public_key }
            }
        }
    }
}

impl Eject for ECDSAPublicKey {
    type Primitive = super::console::ECDSAPublicKey;

    fn eject_mode(&self) -> Mode {
        self.bytes[0].eject_mode()
    }

    fn eject_value(&self) -> Self::Primitive {
        let res = self
            .bytes
            .iter()
            .map(|b| {
                let f = b.eject_value();
                let big = f.to_bigint();
                let res = big.to_biguint().to_bytes_le();
                assert_eq!(res.len(), 1);
                res[0]
            })
            .collect_vec();
        let encoded_pubkey = k256::EncodedPoint::from_bytes(res).unwrap();
        let public_key = k256::ecdsa::VerifyingKey::from_encoded_point(&encoded_pubkey).unwrap();
        Self::Primitive { public_key }
    }
}

impl Inject for ECDSASignature {
    type Primitive = super::console::ECDSASignature;

    fn new(mode: Mode, signature: Self::Primitive) -> Self {
        match mode {
            // might have to check point size
            Mode::Private => unimplemented!(),
            Mode::Constant | Mode::Public => {
                let signature = signature
                    .signature
                    .to_bytes()
                    .iter()
                    .map(|b| {
                        let f = snarkvm_console::types::Field::from_u8(*b);
                        F::new(mode, f)
                    })
                    .collect_vec();
                Self { bytes: signature }
            }
        }
    }
}

impl Eject for ECDSASignature {
    type Primitive = super::console::ECDSASignature;

    fn eject_mode(&self) -> Mode {
        self.bytes[0].eject_mode()
    }

    fn eject_value(&self) -> Self::Primitive {
        let bytes = self
            .bytes
            .iter()
            .map(|b| {
                let f = b.eject_value();
                let big = f.to_bigint();
                let res = big.to_biguint().to_bytes_le();
                assert_eq!(res.len(), 1);
                res[0]
            })
            .collect_vec();
        let signature = k256::ecdsa::Signature::from_slice(&bytes).unwrap();
        Self::Primitive { signature }
    }
}

//
// Functions
// =========
//

/// Verifies a single ECDSA signature on a message.
pub fn verify_one(
    public_key: console::ECDSAPublicKey,
    signature: console::ECDSASignature,
    msg: Vec<u8>,
) {
    // println!("size of public_key bytes:\t{}", public_key.bytes.len());
    // println!("size of signature bytes:\t{}", signature.bytes.len());
    // println!("size of msg bytes:\t{}", msg.bytes.len());

    // Clean all circuits
    Circuit::reset();
    // r1cs_provider::xjsnark::build_r1cs_for_verify_ecdsa(
    //     &msg,
    //     public_key.public_key.to_encoded_point(true).as_bytes(),
    //     &signature.signature.to_bytes(),
    // )
    // .context("failed to build circuit")
    // .unwrap();

    r1cs_provider::gnark::build_r1cs_for_verify_plonky2()
        .context("failed to build circuit")
        .unwrap();

    // let x = F::new(Mode::Public, snarkvm_console::types::Field::from_u8(3));
    // let y = F::new(Mode::Public, snarkvm_console::types::Field::from_u8(12));
    // let z = F::new(Mode::Public, snarkvm_console::types::Field::from_u8(15));

    // Env::assert_eq(x.clone(), x.clone());

    // type EF = <Testnet3 as snarkvm_console_network::Environment>::Field;
    // let mut table = LookupTable::default();
    // table.fill([EF::from(3u32), EF::from(12u32)], EF::from(15u32));
    // Env::add_lookup_table(table);
    // Env::enforce_lookup(|| (x, y, z, 0));
}
