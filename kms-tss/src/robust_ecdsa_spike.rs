//! Spike: Robust threshold ECDSA — 4-round online protocol.
//!
//! Standalone implementation to validate the math and profile performance.
//! See ecdsa_session.rs for the distributed session implementation and
//! full references (DJNPO20, GS21, NEAR MPC).

#[cfg(test)]
mod tests {
    use k256::{
        elliptic_curve::{
            group::GroupEncoding,
            ops::Reduce,
            sec1::ToEncodedPoint,
            Field as FFField, PrimeField,
        },
        AffinePoint, ProjectivePoint, Scalar, U256,
    };
    use rand::thread_rng;
    use sha2::{Digest, Sha256};

    /// A polynomial f(x) = a_0 + a_1*x + ... + a_d*x^d
    struct Polynomial {
        coeffs: Vec<Scalar>,
    }

    impl Polynomial {
        fn random(constant: Option<Scalar>, degree: usize) -> Self {
            let mut rng = thread_rng();
            let mut coeffs = Vec::with_capacity(degree + 1);
            coeffs.push(constant.unwrap_or_else(|| Scalar::random(&mut rng)));
            for _ in 0..degree {
                coeffs.push(Scalar::random(&mut rng));
            }
            Polynomial { coeffs }
        }

        fn eval(&self, x: &Scalar) -> Scalar {
            let mut result = *self.coeffs.last().unwrap();
            for coeff in self.coeffs[..self.coeffs.len() - 1].iter().rev() {
                result = result * x + coeff;
            }
            result
        }

        fn eval_at_zero(&self) -> Scalar {
            self.coeffs[0]
        }
    }

    /// Lagrange coefficient for party i among a set of parties.
    fn lagrange(i: &Scalar, participants: &[Scalar]) -> Scalar {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for j in participants {
            if j == i {
                continue;
            }
            num = num * j;
            den = den * (*j - i);
        }
        num * den.invert().unwrap()
    }

    /// Exponent interpolation: given (x_i, P_i) pairs where P_i = g^{f(x_i)},
    /// compute g^{f(eval_at)} using Lagrange in the exponent.
    fn exponent_interpolation(
        xs: &[Scalar],
        points: &[ProjectivePoint],
        eval_at: Option<&Scalar>,
    ) -> ProjectivePoint {
        let mut result = ProjectivePoint::IDENTITY;
        for (i, (x_i, p_i)) in xs.iter().zip(points.iter()).enumerate() {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for (j, x_j) in xs.iter().enumerate() {
                if i == j {
                    continue;
                }
                let target = eval_at.copied().unwrap_or(Scalar::ZERO);
                num = num * (target - x_j);
                den = den * (*x_i - x_j);
            }
            let lambda = num * den.invert().unwrap();
            result = result + *p_i * lambda;
        }
        result
    }

    /// Scalar interpolation: given (x_i, y_i) pairs, compute f(eval_at).
    fn scalar_interpolation(
        xs: &[Scalar],
        ys: &[Scalar],
        eval_at: Option<&Scalar>,
    ) -> Scalar {
        let mut result = Scalar::ZERO;
        for (i, (x_i, y_i)) in xs.iter().zip(ys.iter()).enumerate() {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for (j, x_j) in xs.iter().enumerate() {
                if i == j {
                    continue;
                }
                let target = eval_at.copied().unwrap_or(Scalar::ZERO);
                num = num * (target - x_j);
                den = den * (*x_i - x_j);
            }
            let lambda = num * den.invert().unwrap();
            result = result + *y_i * lambda;
        }
        result
    }

    /// Extract x-coordinate from an affine point as a scalar.
    fn x_coordinate(point: &AffinePoint) -> Scalar {
        let encoded = point.to_encoded_point(false);
        let x_bytes = encoded.x().unwrap();
        <Scalar as Reduce<U256>>::reduce_bytes(x_bytes)
    }

    /// Presignature output per party.
    #[derive(Clone, Debug)]
    struct PresignShare {
        big_r: AffinePoint,
        alpha: Scalar,
        beta: Scalar,
        e: Scalar,
    }

    /// Run the full 4-round robust ECDSA protocol in-memory.
    ///
    /// Participants: party scalars (identifiers).
    /// secret_shares: each party's private key share f_x(party_i).
    /// public_key: the group public key (g^{f_x(0)}).
    /// msg_hash: the message hash to sign.
    /// max_malicious: t, requires N = 2t+1 participants.
    fn robust_ecdsa_sign(
        participants: &[Scalar],
        secret_shares: &[Scalar],
        public_key: ProjectivePoint,
        msg_hash: &Scalar,
        max_malicious: usize,
    ) -> (AffinePoint, Scalar) {
        let n = participants.len();
        let t = max_malicious;
        assert_eq!(n, 2 * t + 1, "need exactly 2t+1 participants");
        assert!(!bool::from(msg_hash.is_zero()), "msg_hash cannot be zero");

        let mut rng = thread_rng();

        // =====================================================================
        // Round 1: Generate polynomials and distribute evaluations
        // =====================================================================

        // Each party generates 5 polynomials:
        //   fk (degree t, random secret) — nonce share
        //   fa (degree t, random secret) — blinding share
        //   fb (degree 2t, zero secret)  — masking for w
        //   fd (degree 2t, zero secret)  — extra blinding for alpha
        //   fe (degree 2t, zero secret)  — extra blinding for beta
        let mut all_polys: Vec<[Polynomial; 5]> = Vec::new();
        for _ in 0..n {
            all_polys.push([
                Polynomial::random(None, t),
                Polynomial::random(None, t),
                Polynomial::random(Some(Scalar::ZERO), 2 * t),
                Polynomial::random(Some(Scalar::ZERO), 2 * t),
                Polynomial::random(Some(Scalar::ZERO), 2 * t),
            ]);
        }

        // Each party computes its summed shares from all parties' polynomials.
        // In a real protocol, party i receives eval from party j privately.
        let mut k_shares = vec![Scalar::ZERO; n];
        let mut a_shares = vec![Scalar::ZERO; n];
        let mut b_shares = vec![Scalar::ZERO; n];
        let mut d_shares = vec![Scalar::ZERO; n];
        let mut e_shares = vec![Scalar::ZERO; n];

        for (j, polys) in all_polys.iter().enumerate() {
            for (i, p_i) in participants.iter().enumerate() {
                k_shares[i] = k_shares[i] + polys[0].eval(p_i);
                a_shares[i] = a_shares[i] + polys[1].eval(p_i);
                b_shares[i] = b_shares[i] + polys[2].eval(p_i);
                d_shares[i] = d_shares[i] + polys[3].eval(p_i);
                e_shares[i] = e_shares[i] + polys[4].eval(p_i);
            }
        }

        // =====================================================================
        // Round 2: Broadcast R_i = g^{k_i} and w_i = a_i * k_i + b_i
        // =====================================================================

        let big_r_shares: Vec<ProjectivePoint> = k_shares
            .iter()
            .map(|k| ProjectivePoint::GENERATOR * k)
            .collect();

        let w_shares: Vec<Scalar> = (0..n)
            .map(|i| a_shares[i] * k_shares[i] + b_shares[i])
            .collect();

        // =====================================================================
        // Round 3: Interpolate, verify, compute presignature shares
        // =====================================================================

        // Exponent interpolation of R: use first t+1 points to get R = g^k
        let big_r = exponent_interpolation(
            &participants[..t + 1],
            &big_r_shares.iter().map(|p| *p).collect::<Vec<_>>()[..t + 1],
            None,
        );
        assert!(
            big_r != ProjectivePoint::IDENTITY,
            "R is identity — protocol failure"
        );

        // Scalar interpolation of w: use all 2t+1 points (degree 2t polynomial)
        let w = scalar_interpolation(participants, &w_shares, None);
        assert!(!bool::from(w.is_zero()), "w is zero — protocol failure");

        // Compute W_i = R^{a_i} and verify via exponent interpolation
        let big_w_shares: Vec<ProjectivePoint> = a_shares
            .iter()
            .map(|a| big_r * a)
            .collect();

        let big_w = exponent_interpolation(
            &participants[..t + 1],
            &big_w_shares[..t + 1],
            None,
        );
        // Verify W == g^w
        assert_eq!(
            big_w,
            ProjectivePoint::GENERATOR * w,
            "W != g^w — inconsistency detected"
        );

        let w_inv = w.invert().unwrap();

        // Compute per-party presignature shares
        let presigns: Vec<PresignShare> = (0..n)
            .map(|i| {
                let c_i = w_inv * a_shares[i];
                let alpha_i = c_i + d_shares[i];
                let beta_i = c_i * secret_shares[i];
                let e_i = e_shares[i];
                PresignShare {
                    big_r: big_r.to_affine(),
                    alpha: alpha_i,
                    beta: beta_i,
                    e: e_i,
                }
            })
            .collect();

        // =====================================================================
        // Round 4: Compute signature shares, coordinator aggregates
        // =====================================================================

        let big_r_x = x_coordinate(&presigns[0].big_r);

        let sig_shares: Vec<Scalar> = (0..n)
            .map(|i| {
                let beta_rx = presigns[i].beta * big_r_x + presigns[i].e;
                let s_i = *msg_hash * presigns[i].alpha + beta_rx;
                // Linearize with Lagrange coefficient
                s_i * lagrange(&participants[i], participants)
            })
            .collect();

        // Coordinator: sum all shares
        let mut s: Scalar = sig_shares.iter().copied().fold(Scalar::ZERO, |acc, x| acc + x);
        assert!(!bool::from(s.is_zero()), "s is zero — protocol failure");

        // Normalize s to low-S form
        use k256::elliptic_curve::scalar::IsHigh;
        if bool::from(s.is_high()) {
            s = -s;
        }

        (presigns[0].big_r, s)
    }

    /// Verify an ECDSA signature using raw scalar verification.
    /// s^{-1} * (msg_hash * G + r * PK) should have x-coordinate == r.
    fn verify_ecdsa(
        public_key: &ProjectivePoint,
        msg_hash: &Scalar,
        r: &Scalar,
        s: &Scalar,
    ) -> bool {
        let s_inv = s.invert().unwrap();
        let u1 = *msg_hash * s_inv;
        let u2 = *r * s_inv;
        let point = ProjectivePoint::GENERATOR * u1 + *public_key * u2;
        let recovered_r = x_coordinate(&point.to_affine());
        recovered_r == *r
    }

    #[test]
    fn test_robust_ecdsa_3_of_3() {
        let t = 1;
        let n = 2 * t + 1;

        let fx = Polynomial::random(None, t);
        let secret_key = fx.eval_at_zero();
        let public_key = ProjectivePoint::GENERATOR * secret_key;

        let participants: Vec<Scalar> = (1..=n as u64).map(|i| Scalar::from(i)).collect();
        let secret_shares: Vec<Scalar> = participants.iter().map(|p| fx.eval(p)).collect();

        let msg = b"hello robust ecdsa";
        let msg_hash_bytes = Sha256::digest(msg);
        let msg_hash = <Scalar as Reduce<U256>>::reduce_bytes(&msg_hash_bytes.into());

        let start = std::time::Instant::now();
        let (big_r, s) = robust_ecdsa_sign(&participants, &secret_shares, public_key, &msg_hash, t);
        let elapsed = start.elapsed();

        let r_scalar = x_coordinate(&big_r);
        println!("Robust ECDSA sign: {elapsed:?}");
        println!("r: {}", hex::encode(r_scalar.to_bytes()));
        println!("s: {}", hex::encode(s.to_bytes()));

        assert!(verify_ecdsa(&public_key, &msg_hash, &r_scalar, &s), "ECDSA verification failed");
        println!("Verification: OK");

        // Also verify with k256 ecdsa crate (prehash)
        let sig = k256::ecdsa::Signature::from_scalars(r_scalar, s).unwrap();
        let vk = k256::ecdsa::VerifyingKey::from(
            k256::PublicKey::from_affine(public_key.to_affine()).unwrap(),
        );
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        vk.verify_prehash(&msg_hash_bytes, &sig).expect("k256 ECDSA prehash verification failed");
        println!("k256 prehash verification: OK");
    }

    #[test]
    fn test_robust_ecdsa_5_of_5() {
        let t = 2;
        let n = 2 * t + 1;

        let fx = Polynomial::random(None, t);
        let public_key = ProjectivePoint::GENERATOR * fx.eval_at_zero();
        let participants: Vec<Scalar> = (1..=n as u64).map(|i| Scalar::from(i)).collect();
        let secret_shares: Vec<Scalar> = participants.iter().map(|p| fx.eval(p)).collect();

        let msg_hash_bytes = Sha256::digest(b"five party robust ecdsa test");
        let msg_hash = <Scalar as Reduce<U256>>::reduce_bytes(&msg_hash_bytes.into());

        let start = std::time::Instant::now();
        let (big_r, s) = robust_ecdsa_sign(&participants, &secret_shares, public_key, &msg_hash, t);
        let elapsed = start.elapsed();
        println!("Robust ECDSA (5-of-5) sign: {elapsed:?}");

        let r_scalar = x_coordinate(&big_r);
        assert!(verify_ecdsa(&public_key, &msg_hash, &r_scalar, &s), "verification failed");

        let sig = k256::ecdsa::Signature::from_scalars(r_scalar, s).unwrap();
        let vk = k256::ecdsa::VerifyingKey::from(
            k256::PublicKey::from_affine(public_key.to_affine()).unwrap(),
        );
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        vk.verify_prehash(&msg_hash_bytes, &sig).expect("k256 prehash verification failed");
        println!("Verification: OK");
    }

    #[test]
    fn test_robust_ecdsa_7_of_7() {
        let t = 3;
        let n = 2 * t + 1;

        let fx = Polynomial::random(None, t);
        let public_key = ProjectivePoint::GENERATOR * fx.eval_at_zero();
        let participants: Vec<Scalar> = (1..=n as u64).map(|i| Scalar::from(i)).collect();
        let secret_shares: Vec<Scalar> = participants.iter().map(|p| fx.eval(p)).collect();

        let msg_hash_bytes = Sha256::digest(b"seven party robust ecdsa test");
        let msg_hash = <Scalar as Reduce<U256>>::reduce_bytes(&msg_hash_bytes.into());

        let start = std::time::Instant::now();
        let (big_r, s) = robust_ecdsa_sign(&participants, &secret_shares, public_key, &msg_hash, t);
        let elapsed = start.elapsed();
        println!("Robust ECDSA (7-of-7) sign: {elapsed:?}");

        let r_scalar = x_coordinate(&big_r);
        assert!(verify_ecdsa(&public_key, &msg_hash, &r_scalar, &s), "verification failed");

        let sig = k256::ecdsa::Signature::from_scalars(r_scalar, s).unwrap();
        let vk = k256::ecdsa::VerifyingKey::from(
            k256::PublicKey::from_affine(public_key.to_affine()).unwrap(),
        );
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        vk.verify_prehash(&msg_hash_bytes, &sig).expect("k256 prehash verification failed");
        println!("Verification: OK");
    }

    #[test]
    fn test_robust_ecdsa_stress() {
        let t = 2;
        let n = 5;

        let fx = Polynomial::random(None, t);
        let public_key = ProjectivePoint::GENERATOR * fx.eval_at_zero();
        let participants: Vec<Scalar> = (1..=n as u64).map(|i| Scalar::from(i)).collect();
        let secret_shares: Vec<Scalar> = participants.iter().map(|p| fx.eval(p)).collect();

        let start = std::time::Instant::now();
        let iterations = 100u32;
        for i in 0..iterations {
            let msg = format!("stress test message {i}");
            let msg_hash_bytes = Sha256::digest(msg.as_bytes());
            let msg_hash = <Scalar as Reduce<U256>>::reduce_bytes(&msg_hash_bytes.into());
            let (big_r, s) =
                robust_ecdsa_sign(&participants, &secret_shares, public_key, &msg_hash, t);

            let r_scalar = x_coordinate(&big_r);
            assert!(verify_ecdsa(&public_key, &msg_hash, &r_scalar, &s));
        }
        let elapsed = start.elapsed();
        let per_sig = elapsed / iterations;
        println!(
            "Robust ECDSA stress: {iterations} sigs in {elapsed:?} ({per_sig:?}/sig)"
        );
    }
}
