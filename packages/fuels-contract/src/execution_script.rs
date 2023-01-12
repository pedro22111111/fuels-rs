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

impl ExecutableFuelCall {
    pub fn from_script(tx: fuels_core::tx::Script) -> Self {
         Self { 
            calls: vec![], 
            tx_parameters: Default::default(), 
            wallet: Default::default(), 
            tx 
        }
    }

    /// Creates a [`TransactionExecution`] from contract calls. The internal [`Transaction`] is
    /// initialized with the actual script instructions, script data needed to perform the call and
    /// transaction inputs/outputs consisting of assets and contracts.
    pub async fn from_contract_calls(
        calls: Vec<ContractCall>,
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
            build_script_data_from_contract_calls(&self.calls, data_offset, self.tx_parameters.gas_limit);

        let script = get_instructions(&self.calls, call_param_offsets);

        let required_asset_amounts = calculate_required_asset_amounts(&self.calls);
        let mut spendable_resources = vec![];

        // Find the spendable resources required for those calls
        for (asset_id, amount) in &required_asset_amounts {
            let resources = self.wallet.get_spendable_resources(*asset_id, *amount).await?;
            spendable_resources.extend(resources);
        }

        let (inputs, outputs) =
            get_transaction_inputs_outputs(&self.calls, self.wallet.address(), spendable_resources);

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
            None => self.wallet.add_fee_resources(&mut tx, 0, 0).await?,
        }
        self.wallet.sign_transaction(&mut tx).await.unwrap();

        self.tx = tx;

        Ok(())
    }

/// Execute the transaction in a state-modifying manner.
pub async fn execute(mut self, provider: &Provider) -> Result<Vec<Receipt>, Error> {
    self.prepare();

    let chain_info = provider.chain_info().await?;
    self.tx.check_without_signatures(
        chain_info.latest_block.header.height,
        &chain_info.consensus_parameters,
    )?;

    provider.send_transaction(&self.tx).await
}

/// Execute the transaction in a simulated manner, not modifying blockchain state
pub async fn simulate(mut self, provider: &Provider) -> Result<Vec<Receipt>, Error> {
    self.prepare();

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
