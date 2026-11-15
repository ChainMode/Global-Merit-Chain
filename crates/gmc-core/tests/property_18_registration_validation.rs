//! Property 18 — 登记申请字段校验 (registration application field validation).
//!
//! This is the dedicated property-based test for **Property 18** of the
//! `gmc-core-protocol` design's *Correctness Properties* section (task 11.4).
//!
//! > **Property 18: 登记申请字段校验** — 对任意 功勋登记申请，当且仅当其包含贡献者标识、
//! > 所属功勋链标识、登记时间且预期贡献描述长度不超过 2000 字时被接受并创建初始状态为
//! > "有效"的登记记录；否则申请被拒绝且不创建任何登记记录。
//!
//! **Validates: Requirements 9.1, 9.2**
//!
//! Per the harness convention (`tests/common/mod.rs`), the single proptest below is
//! labelled `Feature: gmc-core-protocol, Property 18: ...` and runs with `>= 100`
//! random iterations.
//!
//! ## Modelling the "required fields" space
//!
//! [`RegistrationApplication`] carries four fields. Three are string-/value-typed and
//! can be exercised for presence/absence:
//!
//! - `contributor_id` ([`FayID`]) — "present" iff non-empty;
//! - `chain_id` ([`ChainId`]) — "present" iff non-empty;
//! - `description` ([`String`]) — must be ≤ [`MAX_DESCRIPTION_CHARS`] *Unicode
//!   characters* ("字" = chars, not bytes); and
//! - `registered_at` ([`Timestamp`]) — a value type that is **always present by
//!   construction**, so the "包含登记时间" clause is satisfied for every application
//!   the API can express. It is still varied across iterations and asserted to be
//!   preserved on the created record.
//!
//! The generator therefore samples empty/non-empty contributor & chain ids and
//! descriptions whose character counts straddle the 2000 boundary (in both ASCII and
//! multi-byte CJK, to catch any bytes-vs-chars mistake). The acceptance oracle is the
//! exact conjunction from Requirements 9.1 / 9.2:
//!
//! ```text
//! accept  <=>  contributor_id non-empty
//!          &&  chain_id non-empty
//!          &&  description.chars().count() <= 2000
//! ```

use gmc_core::error::GmcError;
use gmc_core::registration::{
    RegistrationApplication, RegistrationService, RegistrationStatus, MAX_DESCRIPTION_CHARS,
};
use gmc_core::types::{ChainId, FayID, Timestamp};
use proptest::prelude::*;

/// An identifier that is either absent (empty string) or present (non-empty), so both
/// the missing-field rejection and the accepted paths arise.
fn id_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        1 => Just(String::new()),
        4 => (0u32..8).prop_map(|n| format!("id-{n}")),
    ]
}

/// A description whose **character count** straddles the [`MAX_DESCRIPTION_CHARS`]
/// boundary, built from either an ASCII or a multi-byte CJK character. The CJK case
/// makes the byte length far exceed the character count, so the test fails loudly if
/// the bound were ever measured in bytes instead of characters.
fn description_strategy() -> impl Strategy<Value = String> {
    let counts = prop_oneof![
        2 => 0usize..=64,                                  // comfortably within bound
        5 => (MAX_DESCRIPTION_CHARS - 5)..=(MAX_DESCRIPTION_CHARS + 5), // around the edge
        2 => (MAX_DESCRIPTION_CHARS + 1)..=(MAX_DESCRIPTION_CHARS + 80), // clearly over
    ];
    let fill = prop_oneof![Just('a'), Just('字')];
    (counts, fill).prop_map(|(n, ch)| std::iter::repeat_n(ch, n).collect::<String>())
}

proptest! {
    // Run the numbered property with >= 100 random iterations.
    #![proptest_config(ProptestConfig::with_cases(200))]

    // Feature: gmc-core-protocol, Property 18: 登记申请字段校验
    #[test]
    fn property_18_registration_field_validation(
        contributor in id_strategy(),
        chain in id_strategy(),
        description in description_strategy(),
        registered_secs in 0u64..=4_000_000_000u64,
    ) {
        let registered_at = Timestamp::from_secs(registered_secs);
        let app = RegistrationApplication::new(
            FayID::new(contributor.clone()),
            ChainId::new(chain.clone()),
            description.clone(),
            registered_at,
        );

        // Acceptance oracle (Requirements 9.1 / 9.2): all required fields present and
        // the description within the 2000-character bound. `registered_at` is a value
        // type and so is always present by construction.
        let description_chars = description.chars().count();
        let expect_accept = !contributor.is_empty()
            && !chain.is_empty()
            && description_chars <= MAX_DESCRIPTION_CHARS;

        let mut svc = RegistrationService::new();
        let result = svc.register(app);

        if expect_accept {
            // Accepted: exactly one registration created, in the initial "Valid" state,
            // preserving every submitted field.
            let id = result.expect("a complete, in-bounds application must be accepted");
            prop_assert_eq!(svc.len(), 1);

            let reg = svc.get(&id).expect("the accepted registration is stored");
            prop_assert_eq!(reg.status(), RegistrationStatus::Valid);
            prop_assert!(reg.is_valid());
            prop_assert_eq!(reg.contributor_id(), &FayID::new(contributor));
            prop_assert_eq!(reg.chain_id(), &ChainId::new(chain));
            prop_assert_eq!(reg.description(), description.as_str());
            prop_assert_eq!(reg.description().chars().count(), description_chars);
            prop_assert_eq!(reg.registered_at(), registered_at);
        } else {
            // Rejected: a field-validation error and no record created (no partial write).
            prop_assert_eq!(result, Err(GmcError::FieldValidation));
            prop_assert!(svc.is_empty());
        }
    }
}
