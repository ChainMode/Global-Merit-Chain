//! Cold-Start Decaying Bootstrap Parameters & Natural-Person Governance Weight
//! Normalization conformance tests (`define-decaying-bootstrap-parameters` + ADR 0001).

use gmc_core::bootstrap::{
    compute_normalized_governance_weight, BootstrapConfig, BootstrapMintRequest,
    BootstrapMintService, MeritBatchOrigin, VoterIdentitySlice,
};
use gmc_core::error::GmcError;
use gmc_core::gmc_base::{GmcBase, MonetaryRequest};
use gmc_core::merit::{MeritBatch, MeritPocket, E};
use gmc_core::types::{ChainId, Decimal, FayID, Timestamp};
use proptest::prelude::*;

#[test]
fn gmc_base_baseline_monetary_rejection_remains_unconditional() {
    let base = GmcBase::new();
    assert_eq!(
        base.reject_monetary_request(&MonetaryRequest::fund_for_meritoken("gmc-base", "100 USD")),
        Err(GmcError::OperationNotAllowed)
    );
    assert_eq!(
        base.reject_monetary_request(&MonetaryRequest::purchase_recognition(
            "gmc-base", "100 USD"
        )),
        Err(GmcError::OperationNotAllowed)
    );
}

#[test]
fn bootstrap_presets_enforce_faster_decay_and_reject_weak_multiplier() {
    let conservative = BootstrapConfig::conservative_baseline();
    assert!(conservative.validate().is_ok());
    assert!(conservative.decay_multiplier >= 3);

    let neutral = BootstrapConfig::neutral_baseline();
    assert!(neutral.validate().is_ok());
    assert!(neutral.decay_multiplier >= 2);

    let mut invalid = neutral.clone();
    invalid.decay_multiplier = 1;
    assert_eq!(invalid.validate(), Err(GmcError::BootstrapConfigInvalid));
}

#[test]
fn bootstrap_mint_enforces_zero_floor_caps_cooldown_and_one_way_lock() {
    let cfg = BootstrapConfig::neutral_baseline(); // e.g. 200 mu lifetime, 100 mu single, 365d cooldown, 2x decay
    let mut svc = BootstrapMintService::new(cfg.clone()).expect("valid config");
    let mut pocket = MeritPocket::new(FayID::new("ifay_buyer1"));
    let opaque_ref = "gmcref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let t0 = Timestamp::from_secs(1_700_000_000);

    // 1. Grant within single cap succeeds with B_i == 0 and leaves min_merit untouched (== E)
    let receipt = svc
        .grant_initial_merit(
            &mut pocket,
            BootstrapMintRequest {
                batch_id: "boot-1".into(),
                opaque_ref: opaque_ref.into(),
                amount: Decimal::from_int(50),
                base_influence_duration_secs: 90 * 86_400,
                acquired_at: t0,
                source_chain_id: ChainId::new("gmc-base"),
            },
        )
        .expect("first bootstrap grant succeeds");

    assert_eq!(receipt.origin, MeritBatchOrigin::BootstrapPurchased);
    assert_eq!(pocket.min_merit(), E, "bootstrap MUST NOT raise min_merit");
    assert_eq!(pocket.batches.len(), 1);
    assert_eq!(pocket.batches[0].b, Decimal::ZERO, "B_i MUST be strictly 0");

    // 2. Re-purchasing during cooldown -> rejected
    let err_cooldown = svc
        .grant_initial_merit(
            &mut pocket,
            BootstrapMintRequest {
                batch_id: "boot-2".into(),
                opaque_ref: opaque_ref.into(),
                amount: Decimal::from_int(10),
                base_influence_duration_secs: 90 * 86_400,
                acquired_at: Timestamp::from_secs(t0.as_secs() + 60),
                source_chain_id: ChainId::new("gmc-base"),
            },
        )
        .unwrap_err();
    assert_eq!(err_cooldown, GmcError::BootstrapCooldownActive);

    // 3. Exceeding lifetime cap even from a DIFFERENT iFay under the SAME opaqueRef -> rejected
    let mut second_ifay_pocket = MeritPocket::new(FayID::new("ifay_buyer2"));
    let err_cap = svc
        .grant_initial_merit(
            &mut second_ifay_pocket,
            BootstrapMintRequest {
                batch_id: "boot-3".into(),
                opaque_ref: opaque_ref.into(),
                amount: cfg.lifetime_cap, // 50 + lifetime_cap > lifetime_cap
                base_influence_duration_secs: 90 * 86_400,
                acquired_at: Timestamp::from_secs(t0.as_secs() + cfg.cooldown_secs + 1),
                source_chain_id: ChainId::new("gmc-base"),
            },
        )
        .unwrap_err();
    assert_eq!(err_cap, GmcError::BootstrapCapExceeded);

    // 4. Explicit one-way enforcement: transfer & fiat redemption unconditionally rejected
    assert_eq!(
        svc.reject_redemption("boot-1"),
        Err(GmcError::OperationNotAllowed)
    );
    assert_eq!(
        svc.reject_transfer("boot-1", "ifay_other"),
        Err(GmcError::OperationNotAllowed)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_steady_state_buyer_never_exceeds_equal_contributor_floor(
        boot_amount in 1i64..=50,
        earned_amount in 1i64..=200,
    ) {
        let cfg = BootstrapConfig::conservative_baseline();
        let mut svc = BootstrapMintService::new(cfg).unwrap();
        let t0 = Timestamp::from_secs(1_000_000);
        let chain = ChainId::new("gmc-base");
        let dur = Decimal::from_int(86_400);

        let mut buyer = MeritPocket::new(FayID::new("ifay_buyer"));
        let mut non_buyer = MeritPocket::new(FayID::new("ifay_peer"));

        // Buyer purchases bootstrap merit at t0
        svc.grant_initial_merit(
            &mut buyer,
            BootstrapMintRequest {
                batch_id: "boot".into(),
                opaque_ref: "gmcref_buyer0000000000000000000000000000000000000000000".into(),
                amount: Decimal::from_int(boot_amount),
                base_influence_duration_secs: 86_400,
                acquired_at: t0,
                source_chain_id: chain.clone(),
            },
        ).unwrap();

        // Both make an identical earned contribution at t0 + 100
        let t_earn = Timestamp::from_secs(1_000_100);
        let v = Decimal::from_int(earned_amount);
        let b_contrib = Decimal::from_raw(earned_amount as i128 * 10_000); // 0.01 * V
        for pocket in [&mut buyer, &mut non_buyer] {
            let m_before = pocket.cur_merit(t_earn);
            let batch = MeritBatch::with_influence_duration(
                "earned-1",
                v,
                b_contrib,
                dur,
                t_earn,
                chain.clone(),
            ).unwrap();
            pocket.add_batch(batch);
            // Note: update_min_merit uses pre-mint curMerit M; for buyer with higher temporary M,
            // B' = B * (1 + x / M) is <= non-buyer's B' (never higher!).
            let m_eff = if m_before < pocket.min_merit() { pocket.min_merit() } else { m_before };
            pocket.update_min_merit(v, m_eff).unwrap();
        }

        // Far in the future (after decay completes: y >= 30 -> factor == 0):
        let t_inf = Timestamp::from_secs(1_000_000 + 100 * 86_400);
        prop_assert!(
            buyer.cur_merit(t_inf) <= non_buyer.cur_merit(t_inf),
            "buyer steady-state curMerit ({}) must never exceed non-buyer ({})",
            buyer.cur_merit(t_inf),
            non_buyer.cur_merit(t_inf)
        );
        prop_assert!(
            buyer.min_merit() <= non_buyer.min_merit(),
            "buyer minMerit ({}) must never exceed non-buyer ({})",
            buyer.min_merit(),
            non_buyer.min_merit()
        );
    }

    #[test]
    fn prop_normalized_voting_weight_prevents_multi_ifay_sybil_amplification(
        slices in proptest::collection::vec(1i64..=500, 2..=6),
    ) {
        let opaque = "gmcref_samehuman000000000000000000000000000000000000000";
        let total: i64 = slices.iter().sum();

        let split_inputs: Vec<VoterIdentitySlice> = slices
            .iter()
            .enumerate()
            .map(|(idx, &amt)| VoterIdentitySlice {
                ifay_id: format!("ifay_clone{idx}"),
                opaque_ref: opaque.into(),
                effective_merit: Decimal::from_int(amt),
            })
            .collect();

        let single_input = vec![VoterIdentitySlice {
            ifay_id: "ifay_consolidated".into(),
            opaque_ref: opaque.into(),
            effective_merit: Decimal::from_int(total),
        }];

        let split_weights = compute_normalized_governance_weight(&split_inputs).unwrap();
        let single_weights = compute_normalized_governance_weight(&single_input).unwrap();

        let split_sum = split_weights.get(opaque).copied().unwrap_or(Decimal::ZERO);
        let consolidated = single_weights.get(opaque).copied().unwrap_or(Decimal::ZERO);

        prop_assert_eq!(
            split_sum,
            consolidated,
            "splitting merit across multiple iFays under one opaqueRef MUST equal consolidated weight"
        );
    }
}
