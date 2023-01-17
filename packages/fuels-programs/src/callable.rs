use fuel_tx::Output;

use fuel_types::{Address, AssetId};
use fuels_core::parameters::CallParameters;

use fuels_types::bech32::Bech32ContractId;

use crate::{contract_call::ContractCall, script_call::ScriptCall};

pub(crate) trait ProgramCall {
    fn with_external_contracts(self, external_contracts: Vec<Bech32ContractId>) -> Self;
    fn with_call_parameters(self, call_parameters: CallParameters) -> Self;
    fn with_variable_outputs(self, variable_outputs: Vec<Output>) -> Self;
    fn with_message_outputs(self, message_outputs: Vec<Output>) -> Self;
    fn append_variable_outputs(&mut self, num: u64);
    fn append_external_contracts(&mut self, contract_id: Bech32ContractId);
    fn append_message_outputs(&mut self, num: u64);
}

macro_rules! impl_builder_fns {
    ($target:ty) => {
        impl ProgramCall for $target {
            fn with_external_contracts(self, external_contracts: Vec<Bech32ContractId>) -> Self {
                Self {
                    external_contracts,
                    ..self
                }
            }

            fn with_call_parameters(self, call_parameters: CallParameters) -> Self {
                Self {
                    call_parameters,
                    ..self
                }
            }

            fn with_variable_outputs(self, variable_outputs: Vec<Output>) -> Self {
                Self {
                    variable_outputs,
                    ..self
                }
            }

            fn with_message_outputs(self, message_outputs: Vec<Output>) -> Self {
                Self {
                    message_outputs,
                    ..self
                }
            }

            fn append_variable_outputs(&mut self, num: u64) {
                let new_variable_outputs = vec![
                    Output::Variable {
                        amount: 0,
                        to: Address::zeroed(),
                        asset_id: AssetId::default(),
                    };
                    num as usize
                ];
                self.variable_outputs.extend(new_variable_outputs)
            }

            fn append_external_contracts(&mut self, contract_id: Bech32ContractId) {
                self.external_contracts.push(contract_id)
            }

            fn append_message_outputs(&mut self, num: u64) {
                let new_message_outputs = vec![
                    Output::Message {
                        recipient: Address::zeroed(),
                        amount: 0,
                    };
                    num as usize
                ];
                self.message_outputs.extend(new_message_outputs)
            }
        }
    };
}

impl_builder_fns!(ContractCall);
impl_builder_fns!(ScriptCall);
