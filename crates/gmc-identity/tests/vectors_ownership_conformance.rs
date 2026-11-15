//! Executes normative JSON conformance vectors in `vectors/ownership/cofay-ownership-vectors.json`
//! against `gmc_identity::ownership::OwnershipRegistry` with zero external crates.

use gmc_identity::error::IdentityError;
use gmc_identity::identity_id::{derive_identity_id, IdentityId};
use gmc_identity::ownership::OwnershipRegistry;
use gmc_identity::scheme::SchemeRegistry;
use gmc_identity::types::{SchemeTag, VerifyingKey};

const OWNERSHIP_VECTORS_JSON: &str =
    include_str!("../../../vectors/ownership/cofay-ownership-vectors.json");

fn make_id(seed: u8) -> IdentityId {
    let bytes: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(seed))
        .collect();
    derive_identity_id(
        &SchemeRegistry::default(),
        &SchemeTag::ed25519(),
        &VerifyingKey::new(bytes),
    )
    .expect("valid ed25519 vk")
}

fn extract_str<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let idx = block.find(&needle)?;
    let rest = block[idx + needle.len()..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

fn extract_u8(block: &str, key: &str) -> Option<u8> {
    let needle = format!("\"{key}\":");
    let idx = block.find(&needle)?;
    let rest = block[idx + needle.len()..].trim_start();
    let digits_end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..digits_end].parse::<u8>().ok()
}

#[test]
fn all_ownership_json_vectors_match_runtime_behavior() {
    let arr_start = OWNERSHIP_VECTORS_JSON
        .find("\"vectors\"")
        .expect("vectors array present");
    let body = &OWNERSHIP_VECTORS_JSON[arr_start..];
    let mut count = 0usize;

    for raw_obj in body.split('{').skip(1) {
        let Some(end_brace) = raw_obj.find('}') else {
            continue;
        };
        let obj = &raw_obj[..end_brace];
        let id = extract_str(obj, "id").expect("vector id");
        let seed = extract_u8(obj, "cofaySeedByte").expect("cofaySeedByte");
        let owner_id = extract_str(obj, "ownerId").expect("ownerId");
        let owner_kind = extract_str(obj, "ownerKind").expect("ownerKind");
        let expected_outcome = extract_str(obj, "expectedOutcome").expect("expectedOutcome");

        let mut reg = OwnershipRegistry::new();
        let cofay = make_id(seed);
        let res = reg.set_owner_raw(cofay.clone(), owner_id, owner_kind);

        match expected_outcome {
            "allow" => {
                res.unwrap_or_else(|e| panic!("vector {id} expected allow, got {e:?}"));
                assert_eq!(reg.owner_of(&cofay).map(|o| o.id.as_str()), Some(owner_id));
            }
            "deny" => {
                let err = res.expect_err("vector expected deny");
                let expected_err = extract_str(obj, "expectedError").expect("expectedError");
                assert_eq!(expected_err, "OwnerTypeNotAllowed");
                assert_eq!(err, IdentityError::OwnerTypeNotAllowed, "vector {id}");
                assert!(reg.is_empty(), "vector {id} must leave registry unchanged");
            }
            other => panic!("unexpected expectedOutcome {other} in {id}"),
        }
        count += 1;
    }

    assert_eq!(count, 6, "expected 6 ownership vectors");
}
