use std::convert::TryFrom;

use fuels_types::errors::Error;

use crate::code_gen::abi_types::FullProgramABI;
use crate::source::Source;

#[derive(Debug, Clone)]
pub struct AbigenTarget {
    pub name: String,
    pub abi: String,
    pub program_type: ProgramType,
}

pub(crate) struct ParsedAbigenTarget {
    pub name: String,
    pub source: FullProgramABI,
    pub program_type: ProgramType,
}

impl TryFrom<AbigenTarget> for ParsedAbigenTarget {
    type Error = Error;

    fn try_from(value: AbigenTarget) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            source: parse_program_abi(&value.abi)?,
            program_type: value.program_type,
        })
    }
}

fn parse_program_abi(abi_source: &str) -> Result<FullProgramABI, Error> {
    let source = Source::parse(abi_source).expect("failed to parse JSON ABI");
    let json_abi_str = source.get().expect("failed to parse JSON ABI from string");
    FullProgramABI::from_json_abi(&json_abi_str)
}

#[derive(Debug, Clone, Copy)]
pub enum ProgramType {
    Script,
    Contract,
    Predicate,
}
