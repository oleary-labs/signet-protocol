//! Reshare protocol cryptographic operations.
//!
//! Implements the Lagrange-weighted Feldman VSS redistribution protocol
//! (3-round). Generic over `frost_core::Ciphersuite` — works for any curve
//! supported by ZF FROST (secp256k1, Ed25519, etc.).
//!
//! The protocol only needs scalar field arithmetic and group operations, which
//! the `frost_core::Field` and `frost_core::Group` traits provide.

use frost_core::Ciphersuite;
use frost_core::{Field, Group};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Type aliases for readability.
type Scalar<C> = <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar;
type Element<C> = <<C as Ciphersuite>::Group as Group>::Element;
type FieldSer<C> = <<<C as Ciphersuite>::Group as Group>::Field as Field>::Serialization;
type GroupSer<C> = <<C as Ciphersuite>::Group as Group>::Serialization;

// ---------------------------------------------------------------------------
// Polynomial + Feldman helpers
// ---------------------------------------------------------------------------

/// A polynomial represented by its coefficients [a_0, a_1, ..., a_{d}].
/// f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_d*x^d
#[derive(Clone)]
pub struct Polynomial<C: Ciphersuite> {
    pub coeffs: Vec<Scalar<C>>,
}

impl<C: Ciphersuite> Polynomial<C> {
    /// Create a random polynomial with the given constant term and degree.
    pub fn random(constant: Scalar<C>, degree: usize, rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut coeffs = Vec::with_capacity(degree + 1);
        coeffs.push(constant);
        for _ in 0..degree {
            coeffs.push(<<C::Group as Group>::Field as Field>::random(rng));
        }
        Polynomial { coeffs }
    }

    /// Evaluate the polynomial at x using Horner's method.
    pub fn evaluate(&self, x: &Scalar<C>) -> Scalar<C> {
        let mut result = *self.coeffs.last().unwrap();
        for coeff in self.coeffs[..self.coeffs.len() - 1].iter().rev() {
            result = result * *x + *coeff;
        }
        result
    }

    /// Compute Feldman commitments: [a_i * G] for each coefficient.
    pub fn commitments(&self) -> Vec<Element<C>> {
        self.coeffs
            .iter()
            .map(|c| <C::Group as Group>::generator() * *c)
            .collect()
    }
}

/// Compute the Lagrange coefficient for `self_scalar` among `participants`.
/// λ_i = Π_{j≠i} (x_j / (x_j - x_i))
pub fn lagrange_coefficient<C: Ciphersuite>(self_scalar: &Scalar<C>, participants: &[Scalar<C>]) -> Scalar<C> {
    let mut numerator = <<C::Group as Group>::Field>::one();
    let mut denominator = <<C::Group as Group>::Field>::one();
    for xj in participants {
        if xj == self_scalar {
            continue;
        }
        numerator = numerator * *xj;
        denominator = denominator * (*xj - *self_scalar);
    }
    numerator * <<C::Group as Group>::Field>::invert(&denominator).expect("Lagrange denominator is zero")
}

/// Verify a sub-share against Feldman commitments.
/// Checks: sub_share * G == Σ_{k=0..d} commitment_k * (party_id^k)
pub fn verify_feldman<C: Ciphersuite>(
    party_scalar: &Scalar<C>,
    sub_share: &Scalar<C>,
    commitments: &[Element<C>],
) -> bool {
    // LHS: sub_share * G
    let lhs = <C::Group as Group>::generator() * *sub_share;

    // RHS: Σ commitment_k * party_id^k
    let mut rhs = <C::Group as Group>::identity();
    let mut x_power = <<C::Group as Group>::Field>::one();
    for commitment in commitments {
        rhs = rhs + *commitment * x_power;
        x_power = x_power * *party_scalar;
    }

    lhs == rhs
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a group element to bytes.
pub fn serialize_element<C: Ciphersuite>(element: &Element<C>) -> Result<Vec<u8>, String> {
    let ser = <C::Group as Group>::serialize(element)
        .map_err(|e| format!("serialize element: {e}"))?;
    Ok(ser.as_ref().to_vec())
}

/// Deserialize a group element from bytes.
pub fn deserialize_element<C: Ciphersuite>(bytes: &[u8]) -> Result<Element<C>, String> {
    let ser: GroupSer<C> = bytes.to_vec().try_into()
        .map_err(|_| format!("invalid element length: {}", bytes.len()))?;
    <C::Group as Group>::deserialize(&ser)
        .map_err(|e| format!("deserialize element: {e}"))
}

/// Serialize a scalar field element to bytes.
pub fn serialize_scalar<C: Ciphersuite>(s: &Scalar<C>) -> Vec<u8> {
    let ser = <<C::Group as Group>::Field as Field>::serialize(s);
    ser.as_ref().to_vec()
}

/// Deserialize a scalar field element from bytes.
pub fn deserialize_scalar<C: Ciphersuite>(bytes: &[u8]) -> Result<Scalar<C>, String> {
    let ser: FieldSer<C> = bytes.to_vec().try_into()
        .map_err(|_| format!("invalid scalar length: {}", bytes.len()))?;
    <<C::Group as Group>::Field as Field>::deserialize(&ser)
        .map_err(|e| format!("deserialize scalar: {e}"))
}

/// Convert a frost Identifier to its underlying scalar.
pub fn identifier_to_scalar<C: Ciphersuite>(id: &frost_core::Identifier<C>) -> Result<Scalar<C>, String> {
    let bytes = id.serialize();
    deserialize_scalar::<C>(bytes.as_ref())
}

/// Combine chain keys: SHA256(sorted chain keys concatenated).
/// Input must be sorted by party_id. Returns (combined_chain_key, rid).
pub fn combine_chain_keys(chain_keys: &[(String, Vec<u8>)]) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha256::new();
    for (_, ck) in chain_keys {
        h.update(ck);
    }
    let combined: [u8; 32] = h.finalize().into();
    let rid: [u8; 32] = Sha256::digest(&combined).into();
    (combined, rid)
}

// ---------------------------------------------------------------------------
// Message payloads (CBOR-encoded, matching Go wire format)
// ---------------------------------------------------------------------------

/// Round 1 broadcast from each old party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareR1Payload {
    /// Feldman commitments (serialized group elements).
    #[serde(rename = "c")]
    pub commitments: Vec<Vec<u8>>,
    /// 32-byte random chain key contribution.
    #[serde(rename = "k")]
    pub chain_key: Vec<u8>,
    /// Current generation from old config.
    #[serde(rename = "g")]
    pub generation: u64,
    /// Group verification key (so new-only parties learn it).
    #[serde(rename = "v")]
    pub group_key: Vec<u8>,
}

/// Round 2 unicast from old party to new party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareR2Payload {
    /// Scalar encoding of f_i(j).
    #[serde(rename = "s")]
    pub sub_share: Vec<u8>,
}

/// Round 3 broadcast from each new party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReshareR3Payload {
    /// Serialized verifying share (public key share).
    #[serde(rename = "p")]
    pub verifying_share: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Reshare parameters
// ---------------------------------------------------------------------------

/// Parameters for starting a reshare session.
#[derive(Debug, Clone, Deserialize)]
pub struct ReshareParams {
    pub group_id: String,
    pub key_id: String,
    pub party_id: String,
    pub old_party_ids: Vec<String>,
    pub new_party_ids: Vec<String>,
    pub new_threshold: u16,
    /// Curve for this reshare. Defaults to secp256k1 if absent.
    #[serde(default = "default_curve")]
    pub curve: crate::curve::Curve,
}

fn default_curve() -> crate::curve::Curve {
    crate::curve::Curve::Secp256k1
}

/// Decode CBOR bytes into reshare params.
pub fn decode_reshare_params(data: &[u8]) -> Result<ReshareParams, String> {
    ciborium::from_reader(data).map_err(|e| format!("decode reshare params: {e}"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Test using secp256k1 ciphersuite.
    type C = frost_secp256k1::Secp256K1Sha256;
    type F = <<frost_secp256k1::Secp256K1Sha256 as Ciphersuite>::Group as Group>::Field;

    #[test]
    fn test_polynomial_evaluate() {
        let _roundtrip = F::deserialize(&F::serialize(&F::one())).unwrap();
        let poly = Polynomial::<C> {
            coeffs: vec![scalar_from_u64::<C>(5), scalar_from_u64::<C>(3)],
        };
        let two = scalar_from_u64::<C>(2);
        let result = poly.evaluate(&two);
        assert_eq!(result, scalar_from_u64::<C>(11));
    }

    #[test]
    fn test_feldman_commitment_verification() {
        let mut rng = rand::thread_rng();
        let secret = F::random(&mut rng);
        let poly = Polynomial::<C>::random(secret, 2, &mut rng);
        let commitments = poly.commitments();

        let party_id = scalar_from_u64::<C>(3);
        let sub_share = poly.evaluate(&party_id);

        assert!(verify_feldman::<C>(&party_id, &sub_share, &commitments));

        let bad_share = sub_share + F::one();
        assert!(!verify_feldman::<C>(&party_id, &bad_share, &commitments));
    }

    #[test]
    fn test_lagrange_coefficient() {
        let ids: Vec<Scalar<C>> = vec![
            scalar_from_u64::<C>(1),
            scalar_from_u64::<C>(2),
            scalar_from_u64::<C>(3),
        ];
        let l1 = lagrange_coefficient::<C>(&ids[0], &ids);
        let l2 = lagrange_coefficient::<C>(&ids[1], &ids);
        let l3 = lagrange_coefficient::<C>(&ids[2], &ids);
        assert_eq!(l1 + l2 + l3, F::one());
    }

    #[test]
    fn test_lagrange_secret_reconstruction() {
        let mut rng = rand::thread_rng();
        let secret = F::random(&mut rng);
        let poly = Polynomial::<C>::random(secret, 1, &mut rng);

        let ids = vec![scalar_from_u64::<C>(1), scalar_from_u64::<C>(2), scalar_from_u64::<C>(3)];
        let shares: Vec<Scalar<C>> = ids.iter().map(|id| poly.evaluate(id)).collect();

        let subset = &ids[0..2];
        let mut reconstructed = F::zero();
        for (i, id) in subset.iter().enumerate() {
            let lambda = lagrange_coefficient::<C>(id, subset);
            reconstructed = reconstructed + shares[i] * lambda;
        }
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_element_serialization_roundtrip() {
        let scalar = scalar_from_u64::<C>(42);
        let point = <<C as Ciphersuite>::Group as Group>::generator() * scalar;
        let bytes = serialize_element::<C>(&point).unwrap();
        let recovered = deserialize_element::<C>(&bytes).unwrap();
        assert_eq!(point, recovered);
    }

    #[test]
    fn test_scalar_serialization_roundtrip() {
        let scalar = scalar_from_u64::<C>(123456789);
        let bytes = serialize_scalar::<C>(&scalar);
        let recovered = deserialize_scalar::<C>(&bytes).unwrap();
        assert_eq!(scalar, recovered);
    }

    // Also run on Ed25519 to prove generics work.
    type E = frost_ed25519::Ed25519Sha512;
    type FE = <<frost_ed25519::Ed25519Sha512 as Ciphersuite>::Group as Group>::Field;

    #[test]
    fn test_ed25519_lagrange_coefficient() {
        let ids: Vec<Scalar<E>> = vec![
            scalar_from_u64::<E>(1),
            scalar_from_u64::<E>(2),
            scalar_from_u64::<E>(3),
        ];
        let l1 = lagrange_coefficient::<E>(&ids[0], &ids);
        let l2 = lagrange_coefficient::<E>(&ids[1], &ids);
        let l3 = lagrange_coefficient::<E>(&ids[2], &ids);
        assert_eq!(l1 + l2 + l3, FE::one());
    }

    #[test]
    fn test_ed25519_feldman() {
        let mut rng = rand::thread_rng();
        let secret = FE::random(&mut rng);
        let poly = Polynomial::<E>::random(secret, 2, &mut rng);
        let commitments = poly.commitments();

        let party_id = scalar_from_u64::<E>(3);
        let sub_share = poly.evaluate(&party_id);

        assert!(verify_feldman::<E>(&party_id, &sub_share, &commitments));
    }

    /// Helper: build a scalar from a u64 by serializing through the identifier path.
    fn scalar_from_u64<CC: Ciphersuite>(n: u64) -> Scalar<CC> {
        // Use Field::one() and repeated addition for small values.
        let one = <<CC::Group as Group>::Field as Field>::one();
        let zero = <<CC::Group as Group>::Field as Field>::zero();
        let mut result = zero;
        for _ in 0..n {
            result = result + one;
        }
        result
    }
}
