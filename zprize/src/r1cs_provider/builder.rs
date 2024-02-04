use std::collections::HashMap;
use std::convert::From;
use std::path::Path;

use aleo_std_profiler::{end_timer, start_timer};
use anyhow::Result;
use snarkvm_algorithms::r1cs::LookupTable;
use snarkvm_circuit::Circuit as Env;
use snarkvm_circuit::Field;
use snarkvm_circuit_environment::prelude::snarkvm_fields::Fp256;
use snarkvm_circuit_environment::prelude::PrimeField;
use snarkvm_circuit_environment::{Environment as _, Inject as _, LinearCombination, Mode};
use snarkvm_console_network::{Environment, Testnet3};
use snarkvm_curves::bls12_377::FrParameters;
use snarkvm_utilities::BigInteger256;

use super::deserialize;
use super::deserialize::BigInt;

type EF = <Testnet3 as Environment>::Field;
type F = Field<Env>;

impl From<&BigInt> for Fp256<FrParameters> {
    fn from(value: &BigInt) -> Self {
        // Self(BigInteger256(value.0), PhantomData)
        Self::from_bigint(BigInteger256(value.0)).unwrap()
    }
}

pub(crate) fn construct_r1cs_from_file(
    r1cs_file: impl AsRef<Path>,
    assignment_file: impl AsRef<Path>,
    lookup_file: Option<impl AsRef<Path>>,
) -> Result<()> {
    let parse_time = start_timer!(|| "deserialize::parse_file()");
    let (r1cs, assignment, lookup) =
        deserialize::parse_file(r1cs_file, assignment_file, lookup_file)?;
    end_timer!(parse_time);

    let mut fields = assignment
        .variables
        .iter()
        .map(|variable| {
            Ok(F::new(
                Mode::Public,
                snarkvm_console::types::Field::new(EF::from(variable)),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    // insert first element `1`
    fields.insert(0, F::from(Env::one()));

    let func_convert_lc = |lc: &HashMap<usize, BigInt>| -> Result<_> {
        // create Field<Env> from libsnark's linear_combination
        let mut f: Field<Env> = F::from(Env::zero());
        for term in lc {
            let coeff = EF::from(term.1);
            f += &F::from(LinearCombination::from(&fields[*term.0]) * (&coeff));
        }
        Ok(f)
    };

    r1cs.0.iter().try_for_each(|constraint| -> Result<_> {
        let a = func_convert_lc(&constraint.a)?;
        let b = func_convert_lc(&constraint.b)?;
        let c = func_convert_lc(&constraint.c)?;

        Env::enforce(|| (a, b, c));
        Ok(())
    })?;

    if let Some(lookup) = lookup {
        let mut table = LookupTable::default();
        lookup.table.0.iter().try_for_each(|item| -> Result<_> {
            table.fill([EF::from(item[0]), EF::from(item[1])], EF::from(item[2]));
            Ok(())
        })?;
        Env::add_lookup_table(table);

        let table_index = 0; /* Currently we only have one table */
        lookup
            .constraints
            .iter()
            .try_for_each(|constraint| -> Result<_> {
                let a = func_convert_lc(&constraint.a)?;
                let b = func_convert_lc(&constraint.b)?;
                let c = func_convert_lc(&constraint.c)?;

                Env::enforce_lookup(|| (a, b, c, table_index));
                Ok(())
            })?;
    }

    Ok(())
}
