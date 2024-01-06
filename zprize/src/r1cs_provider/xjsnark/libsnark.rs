use std::collections::HashMap;
use std::path::Path;
use std::{fs::File, io::BufReader};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct R1CS(pub Vec<Constraint>);

#[derive(Debug, Serialize, Deserialize)]
pub struct Constraint {
    pub a: HashMap<usize, String>,
    pub b: HashMap<usize, String>,
    pub c: HashMap<usize, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Assignment {
    pub variables: Vec<String>,
    pub primary_input_size: usize, // number of public
    pub auxiliary_input_size: usize,
}

pub fn parse_file(
    r1cs_json_file: impl AsRef<Path>,
    assignment_json_file: impl AsRef<Path>,
) -> Result<(R1CS, Assignment)> {
    let file = File::open(r1cs_json_file)?;
    let reader = BufReader::new(file);
    let r1cs: R1CS = serde_json::from_reader(reader).context("error while parsing r1cs json")?;

    let file = File::open(assignment_json_file)?;
    let reader = BufReader::new(file);
    let assignment: Assignment =
        serde_json::from_reader(reader).context("error while parsing assignment json")?;

    Ok((r1cs, assignment))
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_parse() -> Result<()> {
        let file = File::open("/home/imlk/workspace/zprize/jsnark/libsnark/build/r1cs.json")?;
        let reader = BufReader::new(file);
        let r1cs: R1CS = serde_json::from_reader(reader)?;
        println!("{:#?}", r1cs);

        let file = File::open("/home/imlk/workspace/zprize/jsnark/libsnark/build/assignment.json")?;
        let reader = BufReader::new(file);
        let assignment: Assignment = serde_json::from_reader(reader)?;
        println!("{:#?}", assignment);
        Ok(())
    }
}
