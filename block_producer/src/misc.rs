use std::sync::Arc;

use anyhow::Result;
use eth1_api::{ClientCode, ClientVersionV1, ClientVersions};
use execution_engine::PayloadId;
use grandine_version::{APPLICATION_NAME_WITH_VERSION, APPLICATION_NAME_WITH_VERSION_AND_COMMIT};
use serde::{Deserialize, Serialize};
use ssz::{Size, SszHash, SszSize, SszWrite, WriteError};
use typenum::U1;
use types::{
    combined::{BeaconBlock, BlindedBeaconBlock},
    nonstandard::Phase,
    phase0::primitives::{ExecutionAddress, H256, ValidatorIndex},
    preset::Preset,
    traits::BeaconBlock as _,
};

#[derive(Clone, Copy, Debug)]
pub enum PayloadIdEntry {
    Cached(PayloadId),
    Live(PayloadId),
}

impl PayloadIdEntry {
    #[must_use]
    pub const fn id(self) -> PayloadId {
        match self {
            Self::Cached(payload_id) | Self::Live(payload_id) => payload_id,
        }
    }
}

#[derive(Deserialize)]
pub struct ProposerData {
    #[serde(with = "serde_utils::string_or_native")]
    pub validator_index: ValidatorIndex,
    pub fee_recipient: ExecutionAddress,
}

#[derive(Clone, Serialize)]
#[serde(bound = "", untagged)]
pub enum ValidatorBlindedBlock<P: Preset> {
    BlindedBeaconBlock(BlindedBeaconBlock<P>),
    BeaconBlock(BeaconBlock<P>),
}

impl<P: Preset> SszSize for ValidatorBlindedBlock<P> {
    // The const parameter should be `Self::VARIANT_COUNT`, but `Self` refers to a generic type.
    // Type parameters cannot be used in `const` contexts until `generic_const_exprs` is stable.
    const SIZE: Size =
        Size::for_untagged_union([BlindedBeaconBlock::<P>::SIZE, BeaconBlock::<P>::SIZE]);
}

impl<P: Preset> SszHash for ValidatorBlindedBlock<P> {
    type PackingFactor = U1;

    fn hash_tree_root(&self) -> H256 {
        match self {
            Self::BlindedBeaconBlock(blinded_block) => blinded_block.hash_tree_root(),
            Self::BeaconBlock(block) => block.hash_tree_root(),
        }
    }
}

impl<P: Preset> SszWrite for ValidatorBlindedBlock<P> {
    fn write_variable(&self, bytes: &mut Vec<u8>) -> Result<(), WriteError> {
        match self {
            Self::BlindedBeaconBlock(blinded_block) => blinded_block.write_variable(bytes),
            Self::BeaconBlock(block) => block.write_variable(bytes),
        }
    }
}

impl<P: Preset> ValidatorBlindedBlock<P> {
    #[must_use]
    pub fn into_blinded(self) -> Self {
        let Self::BeaconBlock(block) = self else {
            return self;
        };

        if block.body().with_execution_payload().is_none() {
            return Self::BeaconBlock(block);
        }

        let blinded_block = block
            .try_into()
            .expect("post-Bellatrix block can be converted to a blinded block");

        Self::BlindedBeaconBlock(blinded_block)
    }

    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self {
            Self::BlindedBeaconBlock(blinded_block) => blinded_block.phase(),
            Self::BeaconBlock(block) => block.phase(),
        }
    }

    #[must_use]
    pub const fn is_blinded(&self) -> bool {
        matches!(self, Self::BlindedBeaconBlock(_))
    }
}

pub fn build_graffiti(
    graffiti: Option<H256>,
    client_versions: Option<Arc<ClientVersions>>,
) -> H256 {
    let mut graffiti = graffiti.unwrap_or_default();

    if let Some(client_versions) = client_versions
        && client_versions.len() == 1
        && let Some(finger_print_graffiti) = client_versions
            .first()
            .map(ClientVersionV1::graffiti_string)
    {
        append_to_graffiti(&mut graffiti, &finger_print_graffiti);
    }

    if !append_to_graffiti(&mut graffiti, APPLICATION_NAME_WITH_VERSION_AND_COMMIT) {
        append_to_graffiti(&mut graffiti, APPLICATION_NAME_WITH_VERSION);
    }

    graffiti
}

pub fn build_client_data(client_versions: Option<&ClientVersions>) -> H256 {
    const FIELD_VERSION: u8 = 1;
    const SETUP_SIMPLE: u8 = 3;
    const THRESHOLD_SINGLE_CLIENT: u8 = 1;

    let mut report = [0; H256::len_bytes()];
    report[0] = FIELD_VERSION;
    report[1] = (SETUP_SIMPLE << 3) | THRESHOLD_SINGLE_CLIENT;

    if let Some(client_versions) = client_versions {
        for (index, client_version) in client_versions.iter().take(14).enumerate() {
            report[2 + index] = (consensus_client_code_value(&ClientCode::Grandine) << 4)
                | execution_client_code_value(&client_version.code);
        }
    }

    report.into()
}

fn consensus_client_code_value(client_code: &ClientCode) -> u8 {
    match client_code {
        ClientCode::Caplin => 3,
        ClientCode::Grandine => 4,
        ClientCode::Lighthouse => 5,
        ClientCode::Lodestar => 6,
        ClientCode::Nimbus => 7,
        ClientCode::Teku => 8,
        ClientCode::Prysm => 9,
        ClientCode::Unknown(_) => 1,
        _ => 2,
    }
}

fn execution_client_code_value(client_code: &ClientCode) -> u8 {
    match client_code {
        ClientCode::Besu => 3,
        ClientCode::Erigon => 4,
        ClientCode::Ethrex => 5,
        ClientCode::GoEthereum => 6,
        ClientCode::Nethermind => 7,
        ClientCode::Nimbus => 8,
        ClientCode::Reth => 9,
        ClientCode::Unknown(_) => 1,
        _ => 2,
    }
}

fn append_to_graffiti(graffiti: &mut H256, data: &str) -> bool {
    let trailing_zero_bytes = count_trailing_zero_bytes(*graffiti);

    if trailing_zero_bytes > data.len() {
        let mut first_trailing_position = H256::len_bytes().saturating_sub(trailing_zero_bytes);

        if first_trailing_position != 0 {
            graffiti[first_trailing_position..=first_trailing_position].copy_from_slice(b" ");
            first_trailing_position = first_trailing_position.saturating_add(1);
        }

        graffiti[first_trailing_position..first_trailing_position.saturating_add(data.len())]
            .copy_from_slice(data.as_bytes());

        return true;
    }

    false
}

fn count_trailing_zero_bytes(graffiti: H256) -> usize {
    graffiti
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == 0)
        .count()
}

#[cfg(test)]
#[cfg(feature = "stub-grandine-version")]
mod tests {
    use super::*;

    use eth1_api::ClientCode;
    use helper_functions::misc;
    use hex_literal::hex;
    use test_case::test_case;
    use types::phase0::primitives::H32;

    fn unknown_client_version() -> ClientVersionV1 {
        ClientVersionV1 {
            code: ClientCode::Unknown("UNKNOWN".to_owned()),
            name: "Unknown".to_owned(),
            version: "1.0.0+20130313144700".to_owned(),
            commit: H32(hex!("61adad94")),
        }
    }

    fn known_client_version() -> ClientVersionV1 {
        ClientVersionV1 {
            code: ClientCode::Besu,
            name: "Besu".to_owned(),
            version: "25.7.0".to_owned(),
            commit: H32(hex!("4e2efab6")),
        }
    }

    #[test_case(None, None => "Grandine/1.2.3-6a37d7fa\0\0\0\0\0\0\0\0\0")]
    #[test_case(None, Some(vec![unknown_client_version()].into()) => "UN61adGR6a37 Grandine/1.2.3\0\0\0\0\0")]
    #[test_case(
        None,
        Some(vec![unknown_client_version(), known_client_version()].into()) => "Grandine/1.2.3-6a37d7fa\0\0\0\0\0\0\0\0\0";
        "blockprint graffiti is not available when using a multiplexer"
    )]
    #[test_case(
        Some(misc::parse_graffiti("test").expect("user graffiti is valid")),
        None => "test Grandine/1.2.3-6a37d7fa\0\0\0\0"
    )]
    #[test_case(
        Some(misc::parse_graffiti("test").expect("user graffiti is valid")),
        Some(vec![known_client_version()].into()) => "test BU4e2eGR6a37 Grandine/1.2.3"
    )]
    #[test_case(
        Some(misc::parse_graffiti("test1").expect("user graffiti is valid")),
        Some(vec![known_client_version()].into()) => "test1 BU4e2eGR6a37\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
    )]
    fn test_build_graffiti(
        user_graffiti: Option<H256>,
        client_versions: Option<Arc<ClientVersions>>,
    ) -> String {
        let graffiti = build_graffiti(user_graffiti, client_versions);

        core::str::from_utf8(graffiti.as_bytes())
            .expect("build a valid utf-8 graffiti")
            .to_owned()
    }
}
