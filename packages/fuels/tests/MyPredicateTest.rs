#[allow(clippy::too_many_arguments)]
#[no_implicit_prelude]
pub mod abigen_bindings {
    #[allow(clippy::too_many_arguments)]
    #[no_implicit_prelude]
    pub mod my_predicate_test_mod {
        use ::std::boxed::Box;
        use ::std::{
            clone::Clone,
            convert::{From, Into, TryFrom},
            format,
            iter::IntoIterator,
            iter::Iterator,
            marker::Sized,
            panic,
            string::ToString,
            vec,
        };
        #[cfg_attr(not(target_arch = "wasm32"), ::async_trait::async_trait)]
        impl ::fuels::signers::Account for MyPredicateTest {
            fn address(&self) -> &::fuels::types::bech32::Bech32Address {
                &self.address
            }
            fn get_provider(
                &self,
            ) -> ::fuels::types::errors::Result<&::fuels::signers::provider::Provider> {
                self.provider()
            }
            fn set_provider(&mut self, provider: ::fuels::signers::provider::Provider) {
                self.set_provider(::std::option::Option::Some(provider))
            }
            async fn get_spendable_resources(
                &self,
                asset_id: ::fuels::tx::AssetId,
                amount: u64,
            ) -> ::fuels::types::errors::Result<::std::vec::Vec<::fuels::types::resource::Resource>>
            {
                self.provider()?
                    .get_spendable_resources(&self.address, asset_id, amount)
                    .await
                    .map_err(::std::convert::Into::into)
            }
        }
        #[cfg_attr(not(target_arch = "wasm32"), ::async_trait::async_trait)]
        impl ::fuels::signers::PayFee for MyPredicateTest {
            type Error = ::fuels::types::errors::Error;
            fn address(&self) -> &::fuels::prelude::Bech32Address {
                &self.address
            }
            async fn pay_fee_resources<
                'a_t,
                Tx: ::fuels::tx::Chargeable
                    + ::fuels::tx::field::Inputs
                    + ::fuels::tx::field::Outputs
                    + ::std::marker::Send
                    + ::fuels::tx::Cacheable
                    + ::fuels::tx::UniqueIdentifier
                    + ::fuels::tx::field::Witnesses,
            >(
                &'a_t self,
                tx: &'a_t mut Tx,
                previous_base_amount: u64,
                witness_index: u8,
            ) -> ::fuels::types::errors::Result<()> {
                let consensus_parameters = self
                    .get_provider()?
                    .chain_info()
                    .await?
                    .consensus_parameters;
                let transaction_fee =
                    ::fuels::tx::TransactionFee::checked_from_tx(&consensus_parameters, tx)
                        .expect("Error calculating TransactionFee");
                let (base_asset_inputs , remaining_inputs) : (:: std :: vec :: Vec < _ > , :: std :: vec :: Vec < _ >) = tx . inputs () . iter () . cloned () . partition (| input | { :: std :: matches ! (input , :: fuels :: tx :: Input :: MessageSigned { .. }) || :: std :: matches ! (input , :: fuels :: tx :: Input :: CoinSigned { asset_id , .. } if asset_id == & :: fuels :: core :: constants :: BASE_ASSET_ID) }) ;
                let base_inputs_sum: u64 = base_asset_inputs
                    .iter()
                    .map(|input| input.amount().unwrap())
                    .sum();
                if base_inputs_sum < previous_base_amount {
                    return ::std::result::Result::Err(::fuels::types::errors::Error::WalletError(
                        ::std::format!(
                            "The provided base asset amount is less than the present input coins"
                        ),
                    ));
                }
                let mut new_base_amount = transaction_fee.total() + previous_base_amount;
                let is_consuming_utxos = tx
                    .inputs()
                    .iter()
                    .any(|input| !::std::matches!(input, ::fuels::tx::Input::Contract { .. }));
                const MIN_AMOUNT: u64 = 1;
                if !is_consuming_utxos && new_base_amount == 0 {
                    new_base_amount = MIN_AMOUNT;
                }
                let new_base_inputs = self
                    .get_asset_inputs_for_amount(
                        ::fuels::core::constants::BASE_ASSET_ID,
                        new_base_amount,
                        witness_index,
                    )
                    .await?;
                let adjusted_inputs: ::std::vec::Vec<_> = remaining_inputs
                    .into_iter()
                    .chain(new_base_inputs.into_iter())
                    .collect();
                *tx.inputs_mut() = adjusted_inputs;
                let is_base_change_present = tx . outputs () . iter () . any (| output | { :: std :: matches ! (output , :: fuels :: tx :: Output :: Change { asset_id , .. } if asset_id == & :: fuels :: core :: constants :: BASE_ASSET_ID) }) ;
                if !is_base_change_present && new_base_amount != 0 {
                    tx.outputs_mut().push(::fuels::tx::Output::change(
                        self.address().into(),
                        0,
                        ::fuels::core::constants::BASE_ASSET_ID,
                    ));
                }
                ::std::result::Result::Ok(())
            }
            fn get_provider(
                &self,
            ) -> ::fuels::types::errors::Result<&::fuels::signers::provider::Provider> {
                self.provider()
            }
        }
        #[derive(Debug, Clone)]
        pub struct MyPredicateTest {
            address: ::fuels::types::bech32::Bech32Address,
            code: ::std::vec::Vec<u8>,
            data: ::fuels::core::abi_encoder::UnresolvedBytes,
            provider: ::std::option::Option<::fuels::prelude::Provider>,
        }
        impl MyPredicateTest {
            pub fn new(code: ::std::vec::Vec<u8>) -> Self {
                let address: ::fuels::types::Address =
                    (*::fuels::tx::Contract::root_from_code(&code)).into();
                Self {
                    address: address.clone().into(),
                    code,
                    data: ::fuels::core::abi_encoder::UnresolvedBytes::new(),
                    provider: ::std::option::Option::None,
                }
            }
            pub fn load_from(file_path: &str) -> ::fuels::types::errors::Result<Self> {
                ::std::result::Result::Ok(Self::new(::std::fs::read(file_path)?))
            }
            pub fn address(&self) -> &::fuels::types::bech32::Bech32Address {
                &self.address
            }
            pub fn code(&self) -> ::std::vec::Vec<u8> {
                self.code.clone()
            }
            pub fn provider(
                &self,
            ) -> ::fuels::types::errors::Result<&::fuels::signers::provider::Provider> {
                self.provider
                    .as_ref()
                    .ok_or(::fuels::types::errors::Error::from(
                        ::fuels::signers::wallet::WalletError::NoProvider,
                    ))
            }
            pub fn set_provider(
                &mut self,
                provider: ::std::option::Option<::fuels::prelude::Provider>,
            ) {
                self.provider = provider
            }
            pub fn data(&self) -> ::fuels::core::abi_encoder::UnresolvedBytes {
                self.data.clone()
            }
            pub async fn receive(
                &self,
                from: &::fuels::signers::wallet::WalletUnlocked,
                amount: u64,
                asset_id: ::fuels::types::AssetId,
                tx_parameters: ::std::option::Option<::fuels::core::parameters::TxParameters>,
            ) -> ::fuels::types::errors::Result<(
                ::std::string::String,
                ::std::vec::Vec<::fuels::tx::Receipt>,
            )> {
                let tx_parameters = tx_parameters.unwrap_or_default();
                from.transfer(self.address(), amount, asset_id, tx_parameters)
                    .await
            }
            pub async fn spend(
                &self,
                to: &::fuels::signers::wallet::WalletUnlocked,
                amount: u64,
                asset_id: ::fuels::types::AssetId,
                tx_parameters: ::std::option::Option<::fuels::core::parameters::TxParameters>,
            ) -> ::fuels::types::errors::Result<::std::vec::Vec<::fuels::tx::Receipt>> {
                let tx_parameters = tx_parameters.unwrap_or_default();
                to.receive_from_predicate(
                    self.address(),
                    self.code(),
                    amount,
                    asset_id,
                    self.data(),
                    tx_parameters,
                )
                .await
            }
            pub async fn get_asset_inputs_for_amount(
                &self,
                asset_id: ::fuels::types::AssetId,
                amount: u64,
                witness_index: u8,
            ) -> ::fuels::types::errors::Result<::std::vec::Vec<::fuels::tx::Input>> {
                ::std::result::Result::Ok(
                    self.get_spendable_resources(asset_id, amount)
                        .await?
                        .into_iter()
                        .map(|resource| match resource {
                            ::fuels::types::resource::Resource::Coin(coin) => {
                                self.create_coin_input(coin, asset_id, witness_index)
                            }
                            ::fuels::types::resource::Resource::Message(message) => {
                                self.create_message_input(message, witness_index)
                            }
                        })
                        .collect::<::std::vec::Vec<::fuels::tx::Input>>(),
                )
            }
            pub async fn get_spendable_resources(
                &self,
                asset_id: ::fuels::types::AssetId,
                amount: u64,
            ) -> ::fuels::types::errors::Result<::std::vec::Vec<::fuels::types::resource::Resource>>
            {
                self.provider()?
                    .get_spendable_resources(&self.address, asset_id, amount)
                    .await
                    .map_err(::std::convert::Into::into)
            }
            fn create_coin_input(
                &self,
                coin: ::fuels::types::coin::Coin,
                asset_id: ::fuels::types::AssetId,
                witness_index: u8,
            ) -> ::fuels::tx::Input {
                ::fuels::tx::Input::coin_signed(
                    coin.utxo_id,
                    coin.owner.into(),
                    coin.amount,
                    asset_id,
                    ::fuels::tx::TxPointer::new(0, 0),
                    witness_index,
                    0,
                )
            }
            fn create_message_input(
                &self,
                message: ::fuels::types::message::Message,
                witness_index: u8,
            ) -> ::fuels::tx::Input {
                ::fuels::tx::Input::message_signed(
                    message.message_id(),
                    message.sender.into(),
                    message.recipient.into(),
                    message.amount,
                    message.nonce,
                    witness_index,
                    message.data,
                )
            }
            #[doc = "Run the predicate's encode function with the provided arguments"]
            pub fn encode_data(&self, signatures: [::fuels::types::B512; 3usize]) -> Self {
                let data = ::fuels::core::abi_encoder::ABIEncoder::encode(&[
                    ::fuels::types::traits::Tokenizable::into_token(signatures),
                ])
                .expect("Cannot encode predicate data");
                Self {
                    address: self.address.clone(),
                    code: self.code.clone(),
                    data,
                    provider: self.provider.clone(),
                }
            }
        }
    }
}
pub use abigen_bindings::my_predicate_test_mod::MyPredicateTest;
