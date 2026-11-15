//! Property tests and JSON vector conformance tests for `relationship` (Blueprint Ch. 7,
//! Ch. 10.2–10.6, Ch. 11.3) and `penalty` (Blueprint Ch. 9).

use gmc_core::antifraud::{select_voters, Stakeholder};
use gmc_core::error::GmcError;
use gmc_core::merit::{MeritBatch, MeritPocket};
use gmc_core::penalty::{
    AppealOutcome, Complaint, PenaltyBallot, PenaltyEngine, PenaltySeverity,
};
use gmc_core::relationship::{
    apply_inheritance_to_pocket, compute_inheritance, compute_intimacy, should_exclude_voter,
    PrivacyTier, RelationshipEdge, RelationshipGraph, RelationshipType,
    INTERACTION_WINDOW_SECS,
};
use gmc_core::types::{ChainId, Decimal, FayID, Ratio, Timestamp};
use proptest::prelude::*;

fn ratio_raw(raw: i128) -> Ratio {
    Ratio::new(Decimal::from_raw(raw)).unwrap()
}

fn extract_str<'a>(obj: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let pos = obj.find(&needle)?;
    let rest = &obj[pos + needle.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let inner = &after_colon[1..];
    let end = inner.find('"')?;
    Some(&inner[..end])
}

fn extract_i64(obj: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\"");
    let pos = obj.find(&needle)?;
    let rest = &obj[pos + needle.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    let token: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    token.parse::<i64>().ok()
}

fn parse_rel_type(s: &str) -> RelationshipType {
    match s {
        "Kinship" => RelationshipType::Kinship,
        "Legal" => RelationshipType::Legal,
        "Social" => RelationshipType::Social,
        "Organizational" => RelationshipType::Organizational,
        other => panic!("unknown RelationshipType: {other}"),
    }
}

fn parse_severity(s: &str) -> PenaltySeverity {
    match s {
        "Minor" => PenaltySeverity::Minor,
        "Moderate" => PenaltySeverity::Moderate,
        "Severe" => PenaltySeverity::Severe,
        "Critical" => PenaltySeverity::Critical,
        other => panic!("unknown PenaltySeverity: {other}"),
    }
}

#[test]
fn relationship_and_inheritance_json_vectors_pass() {
    let raw_json =
        include_str!("../../../vectors/relationship/relationship-intimacy-vectors.json");
    let mut executed = 0usize;

    for chunk in raw_json.split('{').skip(1) {
        let Some(body) = chunk.split('}').next() else {
            continue;
        };
        let Some(vec_id) = extract_str(body, "id") else {
            continue;
        };
        let kind = extract_str(body, "kind").expect("kind");
        let expect_status = extract_str(body, "expect_status").expect("expect_status");

        match kind {
            "intimacy" => {
                let rel_type =
                    parse_rel_type(extract_str(body, "relationship_type").expect("rel_type"));
                let registered_at = Timestamp::from_secs(
                    extract_i64(body, "registered_at").expect("registered_at") as u64,
                );
                let event_at =
                    Timestamp::from_secs(extract_i64(body, "event_at").expect("event_at") as u64);
                let pairs = extract_i64(body, "bilateral_pairs").expect("pairs") as u64;
                let depth = ratio_raw(extract_i64(body, "depth_raw").expect("depth") as i128);
                let coparts =
                    extract_i64(body, "co_participations").expect("co_participations") as u64;

                let a = FayID::new("ifay:ed25519:aaaa");
                let b = FayID::new("ifay:ed25519:bbbb");
                let mut graph = RelationshipGraph::new();
                graph
                    .register_bilateral(
                        a.clone(),
                        b.clone(),
                        rel_type,
                        PrivacyTier::ExistencePublic,
                        registered_at,
                    )
                    .unwrap();

                for i in 0..pairs {
                    let ts = Timestamp::from_secs(
                        registered_at.as_secs() + (i / 10) * INTERACTION_WINDOW_SECS,
                    );
                    graph.record_interaction(&a, &b, depth, ts).unwrap();
                    graph.record_interaction(&b, &a, depth, ts).unwrap();
                }
                if coparts > 0 {
                    graph
                        .get_edge_mut(&a, &b)
                        .unwrap()
                        .record_co_participation(coparts, registered_at)
                        .unwrap();
                }

                let res = graph.verify_and_compute_intimacy(&a, &b, event_at);
                if expect_status == "ok" {
                    let expected_raw =
                        extract_i64(body, "expected_intimacy_raw").expect("expected_intimacy_raw")
                            as i128;
                    let actual = res.unwrap_or_else(|e| panic!("vector {vec_id} failed: {e:?}"));
                    assert_eq!(actual.value().raw(), expected_raw, "vector {vec_id}");
                } else {
                    let expected_err = extract_str(body, "expected_error").expect("expected_error");
                    let err = res.expect_err(&format!("vector {vec_id} should fail"));
                    assert_eq!(err.code(), expected_err, "vector {vec_id}");
                }
            }
            "inheritance" => {
                let cur = Decimal::from_raw(
                    extract_i64(body, "cur_merit_raw").expect("cur_merit_raw") as i128,
                );
                let floor = Decimal::from_raw(
                    extract_i64(body, "min_merit_raw").expect("min_merit_raw") as i128,
                );
                let intimacy =
                    ratio_raw(extract_i64(body, "intimacy_raw").expect("intimacy_raw") as i128);
                let is_cofay = extract_i64(body, "is_cofay_role").expect("is_cofay_role") != 0;

                let res = compute_inheritance(cur, floor, intimacy, is_cofay);
                if expect_status == "ok" {
                    let out = res.unwrap_or_else(|e| panic!("vector {vec_id} failed: {e:?}"));
                    assert_eq!(
                        out.retention_ratio.value().raw(),
                        extract_i64(body, "expected_retention_raw").unwrap() as i128,
                        "vector {vec_id}"
                    );
                    assert_eq!(
                        out.inherited_cur_merit.raw(),
                        extract_i64(body, "expected_inherited_cur_raw").unwrap() as i128,
                        "vector {vec_id}"
                    );
                    assert_eq!(
                        out.min_merit_lift.raw(),
                        extract_i64(body, "expected_min_lift_raw").unwrap() as i128,
                        "vector {vec_id}"
                    );
                } else {
                    let expected_err = extract_str(body, "expected_error").expect("expected_error");
                    let err = res.expect_err(&format!("vector {vec_id} should fail"));
                    assert_eq!(err.code(), expected_err, "vector {vec_id}");
                }
            }
            other => panic!("unknown vector kind: {other}"),
        }
        executed += 1;
    }
    assert_eq!(executed, 8);
}

#[test]
fn penalty_and_appeal_json_vectors_pass() {
    let raw_json = include_str!("../../../vectors/penalty/penalty-appeal-vectors.json");
    let mut executed = 0usize;

    for chunk in raw_json.split('{').skip(1) {
        let Some(body) = chunk.split('}').next() else {
            continue;
        };
        let Some(vec_id) = extract_str(body, "id") else {
            continue;
        };
        let batch_id = extract_str(body, "batch_id").expect("batch_id");
        let evidence_hash = extract_str(body, "evidence_hash").expect("evidence_hash");
        let severity = parse_severity(extract_str(body, "severity").expect("severity"));
        let adm_yes = extract_i64(body, "admissibility_approve_raw").unwrap() as i128;
        let adm_tot = extract_i64(body, "admissibility_total_raw").unwrap() as i128;
        let pen_yes = extract_i64(body, "penalty_approve_raw").unwrap() as i128;
        let pen_tot = extract_i64(body, "penalty_total_raw").unwrap() as i128;
        let run_appeal = extract_i64(body, "run_appeal").unwrap() != 0;
        let expect_status = extract_str(body, "expect_status").unwrap();

        let complainant = FayID::new("ifay:ed25519:complainant");
        let respondent = FayID::new("ifay:ed25519:respondent");
        let ts = Timestamp::from_secs(1_000);
        let mut pocket = MeritPocket::new(respondent.clone());
        pocket.add_batch(
            MeritBatch::with_influence_duration(
                "batch-001",
                Decimal::from_int(100),
                Decimal::from_int(20),
                Decimal::from_int(86_400 * 365),
                ts,
                ChainId::new("gmc"),
            )
            .unwrap(),
        );
        pocket.min_merit = Decimal::from_int(20);

        let mut engine = PenaltyEngine::default();
        let res = (|| -> Result<(), GmcError> {
            engine.file_complaint(
                Complaint {
                    complaint_id: vec_id.to_string(),
                    complainant: complainant.clone(),
                    respondent: respondent.clone(),
                    batch_id: batch_id.to_string(),
                    evidence_hash: evidence_hash.to_string(),
                    severity,
                    filed_at: ts,
                },
                Decimal::from_int(50),
                &pocket,
            )?;

            let adm_ballots = vec![
                PenaltyBallot {
                    voter: FayID::new("ifay:ed25519:v1"),
                    cur_merit: Decimal::from_raw(adm_yes),
                    approve: true,
                },
                PenaltyBallot {
                    voter: FayID::new("ifay:ed25519:v2"),
                    cur_merit: Decimal::from_raw(adm_tot - adm_yes),
                    approve: false,
                },
            ];
            if !engine.resolve_admissibility(vec_id, &adm_ballots)? {
                return Err(GmcError::AdmissibilityNotMet);
            }

            let pen_ballots = vec![
                PenaltyBallot {
                    voter: FayID::new("ifay:ed25519:v1"),
                    cur_merit: Decimal::from_raw(pen_yes),
                    approve: true,
                },
                PenaltyBallot {
                    voter: FayID::new("ifay:ed25519:v2"),
                    cur_merit: Decimal::from_raw(pen_tot - pen_yes),
                    approve: false,
                },
            ];
            engine.execute_penalty(vec_id, &mut pocket, &pen_ballots, ts)?;

            if run_appeal {
                let app_yes = extract_i64(body, "appeal_approve_raw").unwrap() as i128;
                let app_tot = extract_i64(body, "appeal_total_raw").unwrap() as i128;
                engine.submit_appeal(vec_id, evidence_hash, ts)?;
                let wider = vec![
                    PenaltyBallot {
                        voter: FayID::new("ifay:ed25519:w1"),
                        cur_merit: Decimal::from_raw(app_yes / 2),
                        approve: true,
                    },
                    PenaltyBallot {
                        voter: FayID::new("ifay:ed25519:w2"),
                        cur_merit: Decimal::from_raw(app_yes - app_yes / 2),
                        approve: true,
                    },
                    PenaltyBallot {
                        voter: FayID::new("ifay:ed25519:w3"),
                        cur_merit: Decimal::from_raw(app_tot - app_yes),
                        approve: false,
                    },
                ];
                let out = engine.resolve_appeal(vec_id, &mut pocket, &wider, ts)?;
                assert!(matches!(out, AppealOutcome::Overturned { .. }));
            }
            Ok(())
        })();

        if expect_status == "ok" {
            res.unwrap_or_else(|e| panic!("vector {vec_id} failed: {e:?}"));
            assert_eq!(
                pocket.cur_merit(ts).raw(),
                extract_i64(body, "expected_cur_after_raw").unwrap() as i128,
                "vector {vec_id} cur_merit"
            );
            assert_eq!(
                pocket.min_merit.raw(),
                extract_i64(body, "expected_min_after_raw").unwrap() as i128,
                "vector {vec_id} min_merit"
            );
        } else {
            let expected_err = extract_str(body, "expected_error").unwrap();
            let err = res.expect_err(&format!("vector {vec_id} should fail"));
            assert_eq!(err.code(), expected_err, "vector {vec_id}");
        }
        executed += 1;
    }
    assert_eq!(executed, 5);
}

#[test]
fn relationship_graph_integrates_seamlessly_with_antifraud_filter_voter_set() {
    let subject = FayID::new("ifay:ed25519:subject");
    let close_kin = FayID::new("ifay:ed25519:kin");
    let mut graph = RelationshipGraph::new();

    graph
        .register_bilateral(
            subject.clone(),
            close_kin.clone(),
            RelationshipType::Kinship,
            PrivacyTier::ExistencePublic,
            Timestamp::from_secs(100),
        )
        .unwrap();

    for day in 0..5u64 {
        let ts = Timestamp::from_secs(100 + day * INTERACTION_WINDOW_SECS);
        for _ in 0..10 {
            graph
                .record_interaction(&subject, &close_kin, Ratio::ONE, ts)
                .unwrap();
            graph
                .record_interaction(&close_kin, &subject, Ratio::ONE, ts)
                .unwrap();
        }
    }
    let vote_ts = Timestamp::from_secs(100 + 4 * INTERACTION_WINDOW_SECS);
    graph
        .get_edge_mut(&subject, &close_kin)
        .unwrap()
        .record_co_participation(15, vote_ts)
        .unwrap();

    let kin_intimacy = graph.voter_intimacy_at(&subject, &close_kin, vote_ts);
    assert!(should_exclude_voter(kin_intimacy));

    let mut candidates = vec![Stakeholder::new(close_kin.clone(), kin_intimacy)];
    for i in 0..8 {
        let vid = FayID::new(format!("ifay:ed25519:voter{i}"));
        candidates.push(Stakeholder::new(
            vid.clone(),
            graph.voter_intimacy_at(&subject, &vid, vote_ts),
        ));
    }

    let eligible = select_voters(&candidates, 8, 42).unwrap();
    assert_eq!(eligible.len(), 8);
    assert!(eligible.iter().all(|v| v != &close_kin));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_intimacy_bounded_symmetric_and_non_increasing_over_time(
        rel_idx in 0usize..4,
        pairs in 0u64..35,
        depth_raw in 1i128..=1_000_000,
        coparts in 0u64..20,
        dt1 in 0u64..20_000_000,
        dt2 in 0u64..20_000_000,
    ) {
        let rel_type = [
            RelationshipType::Kinship,
            RelationshipType::Legal,
            RelationshipType::Social,
            RelationshipType::Organizational,
        ][rel_idx];
        let a = FayID::new("ifay:ed25519:alpha");
        let b = FayID::new("ifay:ed25519:bravo");
        let reg_ts = Timestamp::from_secs(1_000);

        let mut ab = RelationshipEdge::new_bilateral(
            a.clone(),
            b.clone(),
            rel_type,
            PrivacyTier::ExistencePublic,
            reg_ts,
        ).unwrap();
        let mut ba = RelationshipEdge::new_bilateral(
            b.clone(),
            a.clone(),
            rel_type,
            PrivacyTier::ExistencePublic,
            reg_ts,
        ).unwrap();

        let depth = ratio_raw(depth_raw);
        for i in 0..pairs {
            let ts = Timestamp::from_secs(reg_ts.as_secs() + (i / 10) * INTERACTION_WINDOW_SECS);
            ab.record_interaction(&a, &b, depth, ts).unwrap();
            ab.record_interaction(&b, &a, depth, ts).unwrap();
            ba.record_interaction(&b, &a, depth, ts).unwrap();
            ba.record_interaction(&a, &b, depth, ts).unwrap();
        }
        if coparts > 0 {
            let ts = Timestamp::from_secs(reg_ts.as_secs() + (pairs / 10) * INTERACTION_WINDOW_SECS);
            ab.record_co_participation(coparts, ts).unwrap();
            ba.record_co_participation(coparts, ts).unwrap();
        }

        let base_ts = ab.last_bilateral_interaction_at.unwrap_or(reg_ts);
        let t_early = Timestamp::from_secs(base_ts.as_secs() + dt1.min(dt2));
        let t_late = Timestamp::from_secs(base_ts.as_secs() + dt1.max(dt2));

        let score_ab_early = compute_intimacy(&ab, t_early);
        let score_ba_early = compute_intimacy(&ba, t_early);
        let score_ab_late = compute_intimacy(&ab, t_late);

        prop_assert_eq!(score_ab_early, score_ba_early);
        prop_assert!(score_ab_early.value().raw() >= 0 && score_ab_early.value().raw() <= 1_000_000);
        prop_assert!(score_ab_late <= score_ab_early);
    }

    #[test]
    fn prop_inheritance_monotonic_and_preserves_pocket_invariant(
        cur_raw in 10_000_000i128..1_000_000_000,
        floor_frac in 100_000i128..=1_000_000,
        intimacy_a in 100_000i128..=1_000_000,
        intimacy_b in 100_000i128..=1_000_000,
    ) {
        let cur = Decimal::from_raw(cur_raw);
        let floor = Decimal::from_raw((cur_raw * floor_frac) / 1_000_000);
        let low_i = ratio_raw(intimacy_a.min(intimacy_b));
        let high_i = ratio_raw(intimacy_a.max(intimacy_b));

        let out_low = compute_inheritance(cur, floor, low_i, false).unwrap();
        let out_high = compute_inheritance(cur, floor, high_i, false).unwrap();
        prop_assert!(out_low.retention_ratio <= out_high.retention_ratio);
        prop_assert!(out_low.inherited_cur_merit <= out_high.inherited_cur_merit);
        prop_assert!(out_high.inherited_cur_merit < cur);

        let heir_id = FayID::new("ifay:ed25519:heir");
        let ts = Timestamp::from_secs(1_000);
        let mut heir_pocket = MeritPocket::new(heir_id);
        heir_pocket.add_batch(
            MeritBatch::with_influence_duration(
                "seed-batch",
                Decimal::from_int(10),
                Decimal::from_int(3),
                Decimal::from_int(86_400 * 30),
                ts,
                ChainId::new("gmc"),
            ).unwrap()
        );
        apply_inheritance_to_pocket(
            &mut heir_pocket,
            &out_high,
            "inh-batch",
            ChainId::new("gmc"),
            Decimal::from_int(86_400 * 365),
            ts,
        ).unwrap();
        prop_assert!(heir_pocket.invariant_holds(ts));
    }

    #[test]
    fn prop_penalty_preserves_floor_invariants_and_appeal_restores_exact_state(
        sev_idx in 0usize..4,
        v_int in 30i64..500,
        b_int in 5i64..30,
    ) {
        let severity = [
            PenaltySeverity::Minor,
            PenaltySeverity::Moderate,
            PenaltySeverity::Severe,
            PenaltySeverity::Critical,
        ][sev_idx];

        let complainant = FayID::new("ifay:ed25519:complainant");
        let respondent = FayID::new("ifay:ed25519:respondent");
        let ts = Timestamp::from_secs(1_000);
        let mut pocket = MeritPocket::new(respondent.clone());
        pocket.add_batch(
            MeritBatch::with_influence_duration(
                "b-target",
                Decimal::from_int(v_int),
                Decimal::from_int(b_int),
                Decimal::from_int(86_400 * 365),
                ts,
                ChainId::new("gmc"),
            ).unwrap()
        );
        pocket.min_merit = Decimal::from_int(b_int);

        let before_cur = pocket.cur_merit(ts);
        let before_min = pocket.min_merit;
        let hash: String = "f".repeat(64);

        let mut engine = PenaltyEngine::default();
        engine.file_complaint(
            Complaint {
                complaint_id: "prop-case".into(),
                complainant,
                respondent,
                batch_id: "b-target".into(),
                evidence_hash: hash.clone(),
                severity,
                filed_at: ts,
            },
            Decimal::from_int(50),
            &pocket,
        ).unwrap();

        let ballots = vec![
            PenaltyBallot {
                voter: FayID::new("ifay:ed25519:v1"),
                cur_merit: Decimal::from_int(80),
                approve: true,
            },
            PenaltyBallot {
                voter: FayID::new("ifay:ed25519:v2"),
                cur_merit: Decimal::from_int(20),
                approve: false,
            },
        ];
        prop_assert!(engine.resolve_admissibility("prop-case", &ballots).unwrap());
        let rec = engine.execute_penalty("prop-case", &mut pocket, &ballots, ts).unwrap();

        prop_assert!(pocket.invariant_holds(ts));
        prop_assert!(rec.cur_merit_after <= before_cur);
        if !severity.reduces_min_merit() {
            prop_assert_eq!(pocket.min_merit, before_min);
        } else {
            prop_assert!(pocket.min_merit <= before_min);
        }

        engine.submit_appeal("prop-case", hash, ts).unwrap();
        let wider = vec![
            PenaltyBallot {
                voter: FayID::new("ifay:ed25519:w1"),
                cur_merit: Decimal::from_int(100),
                approve: true,
            },
            PenaltyBallot {
                voter: FayID::new("ifay:ed25519:w2"),
                cur_merit: Decimal::from_int(100),
                approve: true,
            },
            PenaltyBallot {
                voter: FayID::new("ifay:ed25519:w3"),
                cur_merit: Decimal::from_int(50),
                approve: false,
            },
        ];
        engine.resolve_appeal("prop-case", &mut pocket, &wider, ts).unwrap();
        prop_assert_eq!(pocket.min_merit, before_min);
        prop_assert_eq!(pocket.cur_merit(ts), before_cur);
    }
}
