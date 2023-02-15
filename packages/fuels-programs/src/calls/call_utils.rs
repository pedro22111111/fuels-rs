use std::collections::HashSet;

use fuel_tx::{
    AssetId, Bytes32, ContractId, Input, Output, Receipt, ScriptExecutionResult, TxPointer, UtxoId,
};

use fuels_core::abi_decoder::ABIDecoder;
use fuels_signers::provider::Provider;
use fuels_types::errors::Error;
use fuels_types::transaction::Transaction;
use fuels_types::{
    bech32::Bech32ContractId,
    constants::BASE_ASSET_ID,
    errors::Result,
    param_types::{ParamType, ReturnLocation},
    Token,
    {bech32::Bech32Address, resource::Resource},
};
use itertools::Itertools;

/// Based on the receipts returned by the call, the contract ID (which is null in the case of a
/// script), and the output param, decode the values and return them.
pub(crate) fn get_decoded_output(
    receipts: &[Receipt],
    contract_id: Option<&Bech32ContractId>,
    output_param: &ParamType,
) -> Result<Token> {
    // Multiple returns are handled as one `Tuple` (which has its own `ParamType`)
    let contract_id: ContractId = match contract_id {
        Some(contract_id) => contract_id.into(),
        // During a script execution, the script's contract id is the **null** contract id
        None => ContractId::new([0u8; 32]),
    };
    let encoded_value = match output_param.get_return_location() {
        ReturnLocation::ReturnData => receipts
            .iter()
            .find(|receipt| {
                matches!(receipt,
                    Receipt::ReturnData { id, data, .. } if *id == contract_id && !data.is_empty())
            })
            .map(|receipt| {
                receipt
                    .data()
                    .expect("ReturnData should have data")
                    .to_vec()
            }),
        ReturnLocation::Return => receipts
            .iter()
            .find(|receipt| {
                matches!(receipt,
                    Receipt::Return { id, ..} if *id == contract_id)
            })
            .map(|receipt| {
                receipt
                    .val()
                    .expect("Return should have val")
                    .to_be_bytes()
                    .to_vec()
            }),
    }
    .unwrap_or_default();

    let decoded_value = ABIDecoder::decode_single(output_param, &encoded_value)?;
    Ok(decoded_value)
}

/// Execute the transaction in a simulated manner, not modifying blockchain state
pub async fn simulate_and_check_success<T: Transaction + Clone>(
    provider: &Provider,
    tx: &T,
) -> Result<Vec<Receipt>> {
    let receipts = provider.dry_run(tx).await?;
    has_script_succeeded(&receipts)?;

    Ok(receipts)
}

fn has_script_succeeded(receipts: &[Receipt]) -> Result<()> {
    receipts
        .iter()
        .find_map(|receipt| match receipt {
            Receipt::ScriptResult { result, .. } if *result != ScriptExecutionResult::Success => {
                Some(format!("{result:?}"))
            }
            _ => None,
        })
        .map(|error_message| {
            Err(Error::RevertTransactionError {
                reason: error_message,
                revert_id: 0,
                receipts: receipts.to_owned(),
            })
        })
        .unwrap_or(Ok(()))
}

/// Sum up the amounts required in each call for each asset ID, so you can get a total for each
/// asset over all calls.
pub(crate) fn sum_up_amounts_for_each_asset_id(
    amounts_per_asset_id: Vec<(AssetId, u64)>,
) -> Vec<(AssetId, u64)> {
    amounts_per_asset_id
        .into_iter()
        .sorted_by_key(|(asset_id, _)| *asset_id)
        .group_by(|(asset_id, _)| *asset_id)
        .into_iter()
        .map(|(asset_id, groups_w_same_asset_id)| {
            let total_amount_in_group = groups_w_same_asset_id.map(|(_, amount)| amount).sum();
            (asset_id, total_amount_in_group)
        })
        .collect()
}

pub(crate) fn extract_unique_asset_ids(spendable_coins: &[Resource]) -> HashSet<AssetId> {
    spendable_coins
        .iter()
        .map(|resource| match resource {
            Resource::Coin(coin) => coin.asset_id,
            Resource::Message(_) => BASE_ASSET_ID,
        })
        .collect()
}

pub(crate) fn generate_asset_change_outputs(
    wallet_address: &Bech32Address,
    asset_ids: HashSet<AssetId>,
) -> Vec<Output> {
    asset_ids
        .into_iter()
        .map(|asset_id| Output::change(wallet_address.into(), 0, asset_id))
        .collect()
}

pub(crate) fn generate_contract_outputs(num_of_contracts: usize) -> Vec<Output> {
    (0..num_of_contracts)
        .map(|idx| Output::contract(idx as u8, Bytes32::zeroed(), Bytes32::zeroed()))
        .collect()
}

pub(crate) fn convert_to_signed_resources(spendable_resources: Vec<Resource>) -> Vec<Input> {
    spendable_resources
        .into_iter()
        .map(|resource| match resource {
            Resource::Coin(coin) => Input::coin_signed(
                coin.utxo_id,
                coin.owner.into(),
                coin.amount,
                coin.asset_id,
                TxPointer::default(),
                0,
                coin.maturity,
            ),
            Resource::Message(message) => Input::message_signed(
                message.message_id(),
                message.sender.into(),
                message.recipient.into(),
                message.amount,
                message.nonce,
                0,
                message.data,
            ),
        })
        .collect()
}

pub(crate) fn generate_contract_inputs(contract_ids: HashSet<ContractId>) -> Vec<Input> {
    contract_ids
        .into_iter()
        .enumerate()
        .map(|(idx, contract_id)| {
            Input::contract(
                UtxoId::new(Bytes32::zeroed(), idx as u8),
                Bytes32::zeroed(),
                Bytes32::zeroed(),
                TxPointer::default(),
                contract_id,
            )
        })
        .collect()
}