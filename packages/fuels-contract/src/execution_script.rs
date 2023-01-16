use crate::contract_calls_utils::{
    convert_to_signed_resources, extract_message_outputs, extract_unique_asset_ids,
    extract_unique_contract_ids, extract_variable_outputs, generate_asset_change_outputs,
    generate_contract_inputs, generate_contract_outputs, get_single_call_instructions,
    sum_up_amounts_for_each_asset_id, CallOpcodeParamsOffset,
};
use anyhow::Result;
use std::collections::HashSet;
use std::fmt::Debug;

use fuel_gql_client::fuel_tx::{Receipt, Transaction};

use fuel_tx::{AssetId, Checkable, Input, Output, ScriptExecutionResult};
use fuels_core::{offsets::call_script_data_offset, parameters::TxParameters};
use fuels_signers::provider::Provider;
use fuels_signers::{Signer, WalletUnlocked};

use fuel_tx::field::{Inputs, Outputs};
use fuels_core::tx::ContractId;
use fuels_types::errors::Error;
use itertools::chain;
use std::vec;

use crate::contract::ContractCall;
use crate::contract_calls_utils::{
    build_script_data_from_contract_calls, calculate_required_asset_amounts, get_instructions,
};

/// [`TransactionExecution`] provides methods to create and call/simulate a transaction that carries
/// out contract method calls or script calls.The [`ExecutableFuelCall`] structure contains a
/// [`pub tx: fuels_core::tx::Script`] field that can be modified.
/// Using this structure is recommended only when the user has a thorough understanding of what they
/// are doing, since incorrect settings during execution may result in errors
///
#[derive(Debug)]
pub struct ExecutableFuelCall {
    pub(crate) tx: fuels_core::tx::Script,
    pub(crate) prepared_assets: CallsPreparedAssets,
    pub(crate) wallet: WalletUnlocked,
    pub(crate) inputs: Vec<Input>,
    pub(crate) outputs: Vec<Output>,
}

#[derive(Debug, Default)]
pub struct CallsPreparedAssets {
    pub required_asset_amounts: Vec<(AssetId, u64)>,
    pub contract_ids: HashSet<ContractId>,
    pub variable_outputs: Vec<Output>,
    pub message_outputs: Vec<Output>,
}

impl ExecutableFuelCall {

    pub async fn from_contract_calls(
        calls: &[ContractCall],
        tx_parameters: &TxParameters,
        wallet: &WalletUnlocked,
    ) -> Result<Self, Error> {
        let consensus_parameters = wallet.get_provider()?.consensus_parameters().await?;

        // Calculate instructions length for call instructions
        // Use placeholder for call param offsets, we only care about the length
        let calls_instructions_len =
            get_single_call_instructions(&CallOpcodeParamsOffset::default()).len() * calls.len();

        let data_offset = call_script_data_offset(&consensus_parameters, calls_instructions_len);

        let (script_data, call_param_offsets) =
            build_script_data_from_contract_calls(calls, data_offset, tx_parameters.gas_limit);

        let script = get_instructions(calls, call_param_offsets);

        let tx = Transaction::script(
            tx_parameters.gas_price,
            tx_parameters.gas_limit,
            tx_parameters.maturity,
            script,
            script_data,
            vec![],
            vec![],
            vec![],
        );

        let calls = CallsPreparedAssets {
            required_asset_amounts: calculate_required_asset_amounts(calls),
            contract_ids: extract_unique_contract_ids(calls),
            variable_outputs: extract_variable_outputs(calls),
            message_outputs: extract_message_outputs(calls),
        };

        Ok(PrepareExecutableFuelCall::new(tx, calls, wallet.clone()))
    }

    pub fn add_input(&mut self, input: Input) -> &mut ExecutableFuelCall {
        self.inputs.extend(input);
        self
    }

    pub fn add_output(&mut self, outputs: Output) -> &mut ExecutableFuelCall {
        self.outputs.extend(outputs);
        self
    }

    /// This function creates an [`ExecutableFuelCall`] from a [`PrepareExecutableFuelCall`], which avoids
    /// the possibility of duplication of inputs and outputs.
    /// For this reason, we strongly recommend the use of this function
    pub async fn prepare(&mut self) -> Result<ExecutableFuelCall, Error> {
        Self::prepare_inputs_outputs(self).await?;
        Ok(ExecutableFuelCall::new(self.tx.clone()))
    }

    pub async fn prepare_inputs_outputs(
        script: &mut ExecutableFuelCall,
    ) -> Result<(), Error> {
        let mut spendable_resources = vec![];

        let user_inputs = script
            .tx
            .inputs()
            .iter()
            .filter(|input|
                {
                    !matches!(input, Input::Contract { .. }) &&
                        !matches!(input, Input::CoinPredicate { .. }) &&
                        !matches!(input, Input::MessagePredicate { .. })
                }
            ).map(|values| (*values.asset_id().unwrap(), values.amount().unwrap()))
            .collect::<Vec<_>>();

        let (user_message_output, user_coin_output): (Vec<_>, Vec<_>) = script
            .tx
            .outputs()
            .iter()
            .cloned()
            .partition(|input| matches!(input, Output::Message { .. }));

        let merged_inputs = sum_up_amounts_for_each_asset_id(
            chain!(script.calls.required_asset_amounts.clone(), user_inputs).collect::<Vec<_>>(),
        );

        for (asset_id, amount) in &merged_inputs {
            let resources = script
                .wallet
                .get_spendable_resources(*asset_id, *amount)
                .await?;
            spendable_resources.extend(resources);
        }

        let asset_ids = extract_unique_asset_ids(&spendable_resources);
        *script.tx.inputs_mut() = chain!(
            generate_contract_inputs(script.calls.calls_contract_ids.clone()),
            convert_to_signed_resources(spendable_resources),
        )
            .collect::<Vec<Input>>();

        // Note the contract_outputs need to come first since the
        // contract_inputs are referencing them via `output_index`. The node
        // will, upon receiving our request, use `output_index` to index the
        // `inputs` array we've sent over.
        *script.tx.outputs_mut() = chain!(
            generate_contract_outputs(script.calls.calls_contract_ids.len()),
            generate_asset_change_outputs(script.wallet.address(), asset_ids),
            chain!(
                script.calls.calls_variable_outputs.clone(),
                user_coin_output
            ),
            chain!(
                script.calls.calls_message_outputs.clone(),
                user_message_output
            ),
        )
            .collect::<Vec<Output>>();

        let base_asset_amount = merged_inputs
            .iter()
            .find(|(asset_id, _)| *asset_id == AssetId::default())
            .map(|(_, amount)| *amount)
            .unwrap_or(0);

        script
            .wallet
            .add_fee_resources(&mut script.tx, base_asset_amount, 0)
            .await?;

        script
            .wallet
            .sign_transaction(&mut script.tx)
            .await
            .unwrap();

        Ok(())
    }


    /// Execute the transaction in a state-modifying manner.
    pub async fn execute(&self, provider: &Provider) -> Result<Vec<Receipt>, Error> {

        let chain_info = provider.chain_info().await?;

        self.tx.check_without_signatures(
            chain_info.latest_block.header.height,
            &chain_info.consensus_parameters,
        )?;

        provider.send_transaction(&self.tx).await
    }

    /// Execute the transaction in a simulated manner, not modifying blockchain state
    pub async fn simulate(&self, provider: &Provider) -> Result<Vec<Receipt>, Error> {
        let chain_info = provider.chain_info().await?;

        self.tx.check_without_signatures(
            chain_info.latest_block.header.height,
            &chain_info.consensus_parameters,
        )?;

        let receipts = provider.dry_run(&self.tx.clone().into()).await?;
        if receipts
            .iter()
            .any(|r|
                matches!(r, Receipt::ScriptResult { result, .. } if *result != ScriptExecutionResult::Success)
            ) {
            return Err(Error::RevertTransactionError(Default::default(), receipts));
        }

        Ok(receipts)
    }
}
