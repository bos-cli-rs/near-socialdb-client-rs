use std::str::FromStr;

use color_eyre::eyre::WrapErr;

const ONE_NEAR: u128 = 10u128.pow(24);

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd)]
pub struct NearBalance {
    pub yoctonear_amount: u128,
}

impl NearBalance {
    pub fn from_yoctonear(yoctonear_amount: u128) -> Self {
        Self { yoctonear_amount }
    }

    pub fn to_yoctonear(&self) -> u128 {
        self.yoctonear_amount
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::from_str("0 NEAR").unwrap()
    }
}

impl std::fmt::Display for NearBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.yoctonear_amount == 0 {
            write!(f, "0 NEAR")
        } else if self.yoctonear_amount % ONE_NEAR == 0 {
            write!(f, "{} NEAR", self.yoctonear_amount / ONE_NEAR,)
        } else {
            write!(
                f,
                "{}.{} NEAR",
                self.yoctonear_amount / ONE_NEAR,
                format!("{:0>24}", (self.yoctonear_amount % ONE_NEAR)).trim_end_matches('0')
            )
        }
    }
}

impl std::str::FromStr for NearBalance {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let num = s.trim().trim_end_matches(char::is_alphabetic).trim();
        let currency = s.trim().trim_start_matches(num).trim().to_uppercase();
        let yoctonear_amount = match currency.as_str() {
            "N" | "NEAR" => {
                let res_split: Vec<&str> = num.split('.').collect();
                match res_split.len() {
                    2 => {
                        let num_int_yocto = res_split[0]
                            .parse::<u128>()
                            .map_err(|err| format!("Near Balance: {}", err))?
                            .checked_mul(10u128.pow(24))
                            .ok_or("Near Balance: underflow or overflow happens")?;
                        let len_fract = res_split[1].len() as u32;
                        let num_fract_yocto = if len_fract <= 24 {
                            res_split[1]
                                .parse::<u128>()
                                .map_err(|err| format!("Near Balance: {}", err))?
                                .checked_mul(10u128.pow(24 - res_split[1].len() as u32))
                                .ok_or("Near Balance: underflow or overflow happens")?
                        } else {
                            return Err(
                                "Near Balance: too large fractional part of a number".to_string()
                            );
                        };
                        num_int_yocto
                            .checked_add(num_fract_yocto)
                            .ok_or("Near Balance: underflow or overflow happens")?
                    }
                    1 => {
                        if res_split[0].starts_with('0') && res_split[0] != "0" {
                            return Err("Near Balance: incorrect number entered".to_string());
                        };
                        res_split[0]
                            .parse::<u128>()
                            .map_err(|err| format!("Near Balance: {}", err))?
                            .checked_mul(10u128.pow(24))
                            .ok_or("Near Balance: underflow or overflow happens")?
                    }
                    _ => return Err("Near Balance: incorrect number entered".to_string()),
                }
            }
            "YN" | "YNEAR" | "YOCTONEAR" | "YOCTON" => num
                .parse::<u128>()
                .map_err(|err| format!("Near Balance: {}", err))?,
            _ => return Err("Near Balance: incorrect currency value entered".to_string()),
        };
        Ok(NearBalance { yoctonear_amount })
    }
}

impl interactive_clap::ToCli for NearBalance {
    type CliVariant = NearBalance;
}

use serde::de::{Deserialize, Deserializer};

#[derive(Debug, Clone, serde::Deserialize)]
pub struct StorageBalance {
    #[serde(deserialize_with = "parse_u128_string")]
    pub available: u128,
    #[serde(deserialize_with = "parse_u128_string")]
    pub total: u128,
}

fn parse_u128_string<'de, D>(deserializer: D) -> color_eyre::eyre::Result<u128, D::Error>
where
    D: Deserializer<'de>,
{
    <std::string::String as Deserialize>::deserialize(deserializer)?
        .parse::<u128>()
        .map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PermissionKey {
    #[serde(rename = "predecessor_id")]
    PredecessorId(near_primitives::types::AccountId),
    #[serde(rename = "public_key")]
    PublicKey(near_crypto::PublicKey),
}

impl From<near_primitives::types::AccountId> for PermissionKey {
    fn from(predecessor_id: near_primitives::types::AccountId) -> Self {
        Self::PredecessorId(predecessor_id)
    }
}

impl From<near_crypto::PublicKey> for PermissionKey {
    fn from(public_key: near_crypto::PublicKey) -> Self {
        Self::PublicKey(public_key)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IsWritePermissionGrantedInputArgs {
    key: String,
    #[serde(flatten)]
    permission_key: PermissionKey,
}

pub async fn is_write_permission_granted<P: Into<PermissionKey>>(
    json_rpc_client: &near_jsonrpc_client::JsonRpcClient,
    near_social_account_id: &near_primitives::types::AccountId,
    permission_key: P,
    key: String,
) -> color_eyre::eyre::Result<bool> {
    let function_args = serde_json::to_string(&IsWritePermissionGrantedInputArgs {
        key,
        permission_key: permission_key.into(),
    })
    .wrap_err("Internal error: could not serialize `is_write_permission_granted` input args")?;
    let call_result = match json_rpc_client
        .call(near_jsonrpc_client::methods::query::RpcQueryRequest {
            block_reference: near_primitives::types::Finality::Final.into(),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: near_social_account_id.clone(),
                method_name: "is_write_permission_granted".to_string(),
                args: near_primitives::types::FunctionArgs::from(function_args.into_bytes()),
            },
        })
        .await
        .wrap_err_with(|| "Failed to fetch query for view method: 'is_write_permission_granted'")?
        .kind
    {
        near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(call_result) => {
            call_result
        }
        _ => color_eyre::eyre::bail!("ERROR: unexpected response type from JSON RPC client"),
    };

    let serde_call_result: serde_json::Value = serde_json::from_slice(&call_result.result)
        .wrap_err_with(|| {
            format!(
                "Failed to parse view-function call return value: {}",
                String::from_utf8_lossy(&call_result.result)
            )
        })?;
    let result = serde_call_result.as_bool().expect("Unexpected response");
    Ok(result)
}

pub fn is_signer_access_key_function_call_access_can_call_set_on_social_db_account(
    near_social_account_id: &near_primitives::types::AccountId,
    access_key_permission: &near_primitives::views::AccessKeyPermissionView,
) -> color_eyre::eyre::Result<bool> {
    if let near_primitives::views::AccessKeyPermissionView::FunctionCall {
        allowance: _,
        receiver_id,
        method_names,
    } = access_key_permission
    {
        Ok(receiver_id == &near_social_account_id.to_string()
            && (method_names.contains(&"set".to_string()) || method_names.is_empty()))
    } else {
        Ok(false)
    }
}

pub async fn get_access_key_permission(
    json_rpc_client: &near_jsonrpc_client::JsonRpcClient,
    account_id: &near_primitives::types::AccountId,
    public_key: &near_crypto::PublicKey,
) -> color_eyre::eyre::Result<near_primitives::views::AccessKeyPermissionView> {
    let permission = match json_rpc_client
        .call(near_jsonrpc_client::methods::query::RpcQueryRequest {
            block_reference: near_primitives::types::Finality::Final.into(),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: account_id.clone(),
                public_key: public_key.clone(),
            },
        })
        .await
        .wrap_err_with(|| format!("Failed to fetch query 'view access key' for <{public_key}>",))?
        .kind
        {
            near_jsonrpc_primitives::types::query::QueryResponseKind::AccessKey(
                access_key_view,
            ) => access_key_view.permission,
            _ => color_eyre::eyre::bail!(
                "Internal error: Received unexpected query kind in response to a View Access Key query call",
            )
        };

    Ok(permission)
}

pub async fn get_deposit(
    json_rpc_client: &near_jsonrpc_client::JsonRpcClient,
    signer_account_id: &near_primitives::types::AccountId,
    signer_public_key: &near_crypto::PublicKey,
    account_id: &near_primitives::types::AccountId,
    key: &str,
    near_social_account_id: &near_primitives::types::AccountId,
    required_deposit: NearBalance,
) -> color_eyre::eyre::Result<NearBalance> {
    let signer_access_key_permission =
        get_access_key_permission(json_rpc_client, signer_account_id, signer_public_key).await?;

    let is_signer_access_key_full_access = matches!(
        signer_access_key_permission,
        near_primitives::views::AccessKeyPermissionView::FullAccess
    );

    let is_write_permission_granted_to_public_key = is_write_permission_granted(
        json_rpc_client,
        near_social_account_id,
        signer_public_key.clone(),
        format!("{account_id}/{key}"),
    )
    .await?;

    let is_write_permission_granted_to_signer = is_write_permission_granted(
        json_rpc_client,
        near_social_account_id,
        signer_account_id.clone(),
        format!("{account_id}/{key}"),
    )
    .await?;

    let deposit = if is_signer_access_key_full_access
        || is_signer_access_key_function_call_access_can_call_set_on_social_db_account(
            near_social_account_id,
            &signer_access_key_permission,
        )? {
        if is_write_permission_granted_to_public_key || is_write_permission_granted_to_signer {
            if required_deposit.is_zero() {
                NearBalance::from_str("0 NEAR").unwrap()
            } else if is_signer_access_key_full_access {
                required_deposit
            } else {
                color_eyre::eyre::bail!("ERROR: Social DB requires more storage deposit, but we cannot cover it when signing transaction with a Function Call only access key")
            }
        } else if signer_account_id == account_id {
            if is_signer_access_key_full_access {
                if required_deposit.is_zero() {
                    NearBalance::from_str("1 yoctoNEAR").unwrap()
                } else {
                    required_deposit
                }
            } else {
                color_eyre::eyre::bail!("ERROR: Social DB requires more storage deposit, but we cannot cover it when signing transaction with a Function Call only access key")
            }
        } else {
            color_eyre::eyre::bail!(
                "ERROR: the signer is not allowed to modify the components of this account_id."
            )
        }
    } else {
        color_eyre::eyre::bail!("ERROR: signer access key cannot be used to sign a transaction to update components in Social DB.")
    };
    Ok(deposit)
}

pub async fn required_deposit(
    json_rpc_client: &near_jsonrpc_client::JsonRpcClient,
    near_social_account_id: &near_primitives::types::AccountId,
    account_id: &near_primitives::types::AccountId,
    data: &serde_json::Value,
    prev_data: Option<&serde_json::Value>,
) -> color_eyre::eyre::Result<NearBalance> {
    const STORAGE_COST_PER_BYTE: i128 = 10i128.pow(19);
    const MIN_STORAGE_BALANCE: u128 = STORAGE_COST_PER_BYTE as u128 * 2000;
    const INITIAL_ACCOUNT_STORAGE_BALANCE: i128 = STORAGE_COST_PER_BYTE * 500;
    const EXTRA_STORAGE_BALANCE: i128 = STORAGE_COST_PER_BYTE * 5000;

    let call_result_storage_balance = match json_rpc_client
        .call(near_jsonrpc_client::methods::query::RpcQueryRequest {
            block_reference: near_primitives::types::Finality::Final.into(),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: near_social_account_id.clone(),
                method_name: "storage_balance_of".to_string(),
                args: near_primitives::types::FunctionArgs::from(
                    serde_json::json!({
                        "account_id": account_id,
                    })
                    .to_string()
                    .into_bytes(),
                ),
            },
        })
        .await
        .wrap_err_with(|| "Failed to fetch query for view method: 'storage_balance_of'")?
        .kind
    {
        near_jsonrpc_primitives::types::query::QueryResponseKind::CallResult(call_result) => {
            call_result
        }
        _ => color_eyre::eyre::bail!("ERROR: unexpected response type from JSON RPC client"),
    };

    let storage_balance_result: color_eyre::eyre::Result<StorageBalance> =
        serde_json::from_slice(&call_result_storage_balance.result).wrap_err_with(|| {
            format!(
                "Failed to parse view-function call return value: {}",
                String::from_utf8_lossy(&call_result_storage_balance.result)
            )
        });

    let (available_storage, initial_account_storage_balance, min_storage_balance) =
        if let Ok(storage_balance) = storage_balance_result {
            (storage_balance.available, 0, 0)
        } else {
            (0, INITIAL_ACCOUNT_STORAGE_BALANCE, MIN_STORAGE_BALANCE)
        };

    let estimated_storage_balance = u128::try_from(
        STORAGE_COST_PER_BYTE * estimate_data_size(data, prev_data) as i128
            + initial_account_storage_balance
            + EXTRA_STORAGE_BALANCE,
    )
    .unwrap_or(0)
    .saturating_sub(available_storage);
    Ok(NearBalance::from_yoctonear(std::cmp::max(
        estimated_storage_balance,
        min_storage_balance,
    )))
}

/// https://github.com/NearSocial/VM/blob/24055641b53e7eeadf6efdb9c073f85f02463798/src/lib/data/utils.js#L182-L198
fn estimate_data_size(data: &serde_json::Value, prev_data: Option<&serde_json::Value>) -> isize {
    const ESTIMATED_KEY_VALUE_SIZE: isize = 40 * 3 + 8 + 12;
    const ESTIMATED_NODE_SIZE: isize = 40 * 2 + 8 + 10;

    match data {
        serde_json::Value::Object(data) => {
            let inner_data_size = data
                .iter()
                .map(|(key, value)| {
                    let prev_value = if let Some(serde_json::Value::Object(prev_data)) = prev_data {
                        prev_data.get(key)
                    } else {
                        None
                    };
                    if prev_value.is_some() {
                        estimate_data_size(value, prev_value)
                    } else {
                        key.len() as isize * 2
                            + estimate_data_size(value, None)
                            + ESTIMATED_KEY_VALUE_SIZE
                    }
                })
                .sum();
            if prev_data.map(serde_json::Value::is_object).unwrap_or(false) {
                inner_data_size
            } else {
                ESTIMATED_NODE_SIZE + inner_data_size
            }
        }
        serde_json::Value::String(data) => {
            data.len().max(8) as isize
                - prev_data
                    .and_then(serde_json::Value::as_str)
                    .map(str::len)
                    .unwrap_or(0) as isize
        }
        _ => {
            unreachable!("estimate_data_size expects only Object or String values");
        }
    }
}

/// Helper function that marks SocialDB values to be deleted by setting `null` to the values
pub fn mark_leaf_values_as_null(data: &mut serde_json::Value) {
    match data {
        serde_json::Value::Object(object_data) => {
            for value in object_data.values_mut() {
                mark_leaf_values_as_null(value);
            }
        }
        data => {
            *data = serde_json::Value::Null;
        }
    }
}

pub fn social_db_data_from_key(full_key: &str, data_to_set: &mut serde_json::Value) {
    if let Some((prefix, key)) = full_key.rsplit_once('/') {
        *data_to_set = serde_json::json!({ key: data_to_set });
        social_db_data_from_key(prefix, data_to_set)
    } else {
        *data_to_set = serde_json::json!({ full_key: data_to_set });
    }
}
