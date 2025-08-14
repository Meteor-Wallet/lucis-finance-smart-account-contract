use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::U128;
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::AccountId;

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub struct WhitelistedFunctionCall {
    pub rules_id: u16,
    pub rules_name: String,
    pub description: String,
    pub operator_id: AccountId,
    pub contract_id: AccountId,
    pub method_name: String,
    pub param_rule_expr: ParamRuleExpr,
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(crate = "near_sdk::serde")]
pub enum ParamRuleExpr {
    /// Operators for combining multiple expressions
    And(Vec<ParamRuleExpr>),
    Or(Vec<ParamRuleExpr>),
    /// Key Reserved Characters:
    /// Key are not allowed to contain dots ("."), or empty brackets ("()")
    ///
    /// Key Special Functions:
    /// the dot "." is used to split the key into parts
    /// json() means the key before it is a JSON object
    /// array_first() means the key before it is an array, and the rules apply to the first element of the array
    /// array_last() means the key before it is an array, and the rules apply to the last element of the array
    /// array_foreach() means the key before it is an array, and the rules apply to all elements of the array
    /// key() means we want to get the first key of the object instead of the value (useful for rust enum variants)
    ///
    /// Example:
    /// msg.json().Execute.actions.array_foreach().key()
    /// means we want to get the first key of the first matched element in the actions array of the Execute object in the JSON message.
    ///
    /// msg.json().actions.array_first().pool_id
    /// means we want to get the pool_id value of the first matched element in the actions array of the JSON message.
    ///
    /// msg.json().actions.array_last().token_out
    /// means we want to get the token_out value of the last matched element in the actions array of the JSON message.
    StringEqual {
        key: String,
        value: String,
    },
    StringNotEqual {
        key: String,
        value: String,
    },
    NumericEqual {
        key: String,
        value: U128,
    },
    NumericNotEqual {
        key: String,
        value: U128,
    },
    GreaterThan {
        key: String,
        value: U128,
    },
    LessThan {
        key: String,
        value: U128,
    },
    GreaterThanOrEqualTo {
        key: String,
        value: U128,
    },
    LessThanOrEqualTo {
        key: String,
        value: U128,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::serde_json;

    #[test]
    fn test_json_roundtrip() {
        // Create a sample struct
        let original = WhitelistedFunctionCall {
            rules_id: 1,
            rules_name: "Swap Farm Rewards into Interest for Repaying".to_string(),
            description: "RHEA lending will charge us for higher borrow interest compared to the \
                   supply interest. So we will owe USDT and USDC over time, \
                   but we earned wrap.near due to the farm rewards. \
                   We need to swap some of the wNEAR to USDT / USDC in order to repay the interest"
                .to_string(),
            operator_id: "trent.near".parse().unwrap(),
            contract_id: "wrap.near".parse().unwrap(),
            method_name: "ft_transfer_call".to_string(),
            param_rule_expr: ParamRuleExpr::And(vec![
                ParamRuleExpr::LessThanOrEqualTo {
                    key: "amount".to_string(),
                    value: U128(10 * 10u128.pow(24)),
                },
                ParamRuleExpr::StringEqual {
                    key: "receiver_id".to_string(),
                    value: "v2.ref-finance.near".to_string(),
                },
                ParamRuleExpr::Or(vec![
                    ParamRuleExpr::StringEqual {
                        key: "msg.json().actions.array_last().token_out".to_string(),
                        value: "usdt.tether-token.near".to_string(),
                    },
                    ParamRuleExpr::StringEqual {
                        key: "msg.json().actions.array_last().token_out".to_string(),
                        value: "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1"
                            .to_string(),
                    },
                ]),
            ]),
        };

        // Serialize to JSON
        let json_str = serde_json::to_string(&original).unwrap();
        println!("Serialized JSON:\n{}", json_str);

        // Deserialize back
        let deserialized: WhitelistedFunctionCall = serde_json::from_str(&json_str).unwrap();

        // Assert equality
        assert_eq!(original, deserialized);
    }
}
