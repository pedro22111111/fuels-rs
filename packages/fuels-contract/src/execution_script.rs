use std::borrow::{Borrow, BorrowMut};
use crate::contract_calls_utils::{get_single_call_instructions, CallOpcodeParamsOffset};
use anyhow::Result;
use std::fmt::Debug;

use fuel_gql_client::fuel_tx::{Receipt, Transaction};

use fuel_tx::{AssetId, Checkable, ScriptExecutionResult};
use fuels_core::{offsets::call_script_data_offset, parameters::TxParameters};
use fuels_signers::provider::Provider;
use fuels_signers::{Signer, WalletUnlocked};

use fuels_types::errors::Error;

use std::vec;

use crate::contract::ContractCall;
use crate::contract_calls_utils::{
    build_script_data_from_contract_calls, calculate_required_asset_amounts, get_instructions,
    get_transaction_inputs_outputs,
};

/// [`TransactionExecution`] provides methods to create and call/simulate a transaction that carries
/// out contract method calls or script calls
#[derive(Debug)]
pub struct ExecutableFuelCall {
    calls: Vec<ContractCall>,
    tx_parameters: TxParameters,
    wallet: WalletUnlocked,
    pub tx: fuels_core::tx::Script,
}

// #[derive(Debug, Default)]
// pub struct Calls {
//     // pub required_asset_amounts: Vec<(AssetId, u64)>,
//     pub calls_contract_ids: HashSet<ContractId>,
//     pub calls_variable_outputs: Vec<Output>,
//     pub calls_message_outputs: Vec<Output>,
// }

impl ExecutableFuelCall {
    // pub fn new(tx: fuels_core::tx::Script) -> Self {
    //     Self { calls: &[], tx_parameters: &Default::default(), wallet: Default::default(), tx }
    // }

    /// Creates a [`TransactionExecution`] from contract calls. The internal [`Transaction`] is
    /// initialized with the actual script instructions, script data needed to perform the call and
    /// transaction inputs/outputs consisting of assets and contracts.
    pub async fn from_contract_calls(
        calls: &[ContractCall],
        tx_parameters: TxParameters,
        wallet: WalletUnlocked,
    ) -> Result<Self, Error> {
        Ok(ExecutableFuelCall {
            calls,
            tx_parameters,
            wallet,
            tx: Default::default(),
        })

    }

    pub async fn prepare(&mut self) -> Result<(), Error> {
        let consensus_parameters = self.wallet.get_provider()?.consensus_parameters().await?;

        // Calculate instructions length for call instructions
        // Use placeholder for call param offsets, we only care about the length
        let calls_instructions_len =
            get_single_call_instructions(&CallOpcodeParamsOffset::default()).len() * self.calls.len();

        let data_offset = call_script_data_offset(&consensus_parameters, calls_instructions_len);

        let (script_data, call_param_offsets) =
            build_script_data_from_contract_calls(self.calls, data_offset, self.tx_parameters.gas_limit);

        let script = get_instructions(self.calls, call_param_offsets);

        let required_asset_amounts = calculate_required_asset_amounts(self.calls);
        let mut spendable_resources = vec![];

        // Find the spendable resources required for those calls
        for (asset_id, amount) in &required_asset_amounts {
            let resources = self.wallet.get_spendable_resources(*asset_id, *amount).await?;
            spendable_resources.extend(resources);
        }

        let (inputs, outputs) =
            get_transaction_inputs_outputs(self.calls, self.wallet.address(), spendable_resources);

        let mut tx = Transaction::script(
            self.tx_parameters.gas_price,
            self.tx_parameters.gas_limit,
            self.tx_parameters.maturity,
            script,
            script_data,
            inputs,
            outputs,
            vec![],
        );

        let base_asset_amount = required_asset_amounts
            .iter()
            .find(|(asset_id, _)| *asset_id == AssetId::default());
        match base_asset_amount {
            Some((_, base_amount)) => self.wallet.add_fee_resources(&mut tx, *base_amount, 0).await?,
            None => wallet.add_fee_resources(&mut tx, 0, 0).await?,
        }
        self.wallet.sign_transaction(&mut tx).await.unwrap();
        Ok(())
    }


//     pub async fn prepare_inputs_outputs(
//         script: &mut PrepareExecutableFuelCall,
//     ) -> Result<(), Error> {
//         let mut spendable_resources = vec![];
//
//         let script_inputs = script
//             .inputs
//             .iter()
//             .filter(|input| !matches!(input, Input::Contract { .. }))
//             .map(|values| (*values.asset_id().unwrap(), values.amount().unwrap()))
//             .collect::<Vec<_>>();
//
//         let (script_message_output, script_coin_output): (Vec<_>, Vec<_>) = script
//             .outputs
//             .iter()
//             .cloned()
//             .partition(|input| matches!(input, Output::Message { .. }));
//
//         let merged_inputs = sum_up_amounts_for_each_asset_id(
//             chain!(script.calls.required_asset_amounts.clone(), script_inputs).collect::<Vec<_>>(),
//         );
//
//         for (asset_id, amount) in &merged_inputs {
//             let resources = script
//                 .wallet
//                 .get_spendable_resources(*asset_id, *amount)
//                 .await?;
//             spendable_resources.extend(resources);
//         }
//
//         let asset_ids = extract_unique_asset_ids(&spendable_resources);
//         *script.tx.inputs_mut() = chain!(
//             generate_contract_inputs(script.calls.calls_contract_ids.clone()),
//             convert_to_signed_resources(spendable_resources),
//         )
//             .collect::<Vec<Input>>();
//
//         // Note the contract_outputs need to come first since the
//         // contract_inputs are referencing them via `output_index`. The node
//         // will, upon receiving our request, use `output_index` to index the
//         // `inputs` array we've sent over.
//         *script.tx.outputs_mut() = chain!(
//             generate_contract_outputs(script.calls.calls_contract_ids.len()),
//             generate_asset_change_outputs(script.wallet.address(), asset_ids),
//             chain!(
//                 script.calls.calls_variable_outputs.clone(),
//                 script_coin_output
//             ),
//             chain!(
//                 script.calls.calls_message_outputs.clone(),
//                 script_message_output
//             ),
//         )
//             .collect::<Vec<Output>>();
//
//         let base_asset_amount = merged_inputs
//             .iter()
//             .find(|(asset_id, _)| *asset_id == AssetId::default())
//             .map(|(_, amount)| *amount)
//             .unwrap_or(0);
//
//         script
//             .wallet
//             .add_fee_resources(&mut script.tx, base_asset_amount, 0)
//             .await?;
//
//         script
//             .wallet
//             .sign_transaction(&mut script.tx)
//             .await
//             .unwrap();
//
//         Ok(())
//     }
// }

/// Execute the transaction in a state-modifying manner.
pub async fn execute(self, provider: &Provider) -> Result<Vec<Receipt>, Error> {

    self.borrow().prepare();
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
