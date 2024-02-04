use std::collections::HashMap;
use std::path::Path;
use std::str::FromStr;

use aleo_std_profiler::{end_timer, start_timer};
use anyhow::Result;
use snarkvm_algorithms::r1cs::LookupTable;
use snarkvm_circuit::Circuit as Env;
use snarkvm_circuit::Field;
use snarkvm_circuit_environment::{Environment as _, Inject as _, LinearCombination, Mode};
use snarkvm_console_network::{Environment, Testnet3};

use super::deserialize;

type EF = <Testnet3 as Environment>::Field;
type F = Field<Env>;

pub(crate) fn construct_r1cs_from_json(
    r1cs_json_file: impl AsRef<Path>,
    assignment_json_file: impl AsRef<Path>,
    lookup_json_file: Option<impl AsRef<Path>>,
) -> Result<()> {

    let parse_time = start_timer!(|| "deserialize::parse_file()");
    let (r1cs, assignment, lookup) =
        deserialize::parse_file(r1cs_json_file, assignment_json_file, lookup_json_file)?;
    end_timer!(parse_time);

    let mut fields = assignment
        .variables
        .iter()
        .map(|variable| {
            Ok(F::new(
                Mode::Public,
                snarkvm_console::types::Field::new(EF::from_str(&variable)?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    // insert first element `1`
    fields.insert(0, F::from(Env::one()));

    let func_convert_lc = |lc: &HashMap<usize, String>| -> Result<_> {
        // create Field<Env> from libsnark's linear_combination
        let mut f: Field<Env> = F::from(Env::zero());
        for term in lc {
            let coeff = EF::from_str(&term.1)?;
            f += F::from(LinearCombination::from(fields[*term.0].clone()) * (coeff));
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
            table.fill(
                [EF::from_str(&item[0])?, EF::from_str(&item[1])?],
                EF::from_str(&item[2])?,
            );
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
