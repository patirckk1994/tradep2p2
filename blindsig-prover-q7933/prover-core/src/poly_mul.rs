// Polynomial multiplication mod q in Z_q[X]/(X^N+1), via plain O(n^2)
// schoolbook convolution - NOT the NTT-based approach the q=12289 sibling
// crate (blindsig-prover/prover-core/src/ntt.rs) uses.
//
// Why schoolbook here specifically: q=7933 does not support a standard
// radix-2 NTT at N=512 (7932 = 2^2*3*661, not divisible by 1024 - this was
// established earlier in this project's own research, not assumed). The
// original research prototype's own guest was ALSO originally built with
// this exact schoolbook approach before NTT was added purely as a
// zkVM-proving-speed optimization over an already-correct implementation
// (see blindsig-prover/prover-core/src/ntt.rs's own module comment, and
// pq-blind-sig-research/prototype/README_PROTOTYPE.md's "Performance
// note"). This function is that same schoolbook approach, reparametrized
// for q=7933 - a real, working reference, not a stopgap invented for this
// port. Whether it remains the final answer or a faster (Karatsuba, etc.)
// non-NTT approach is needed instead is an open question this project
// answers empirically (real zkVM cycle counts), not by assumption - see
// this crate's own README/commit history for that measurement once taken.

use crate::{N, Q};

/// Multiplies two polynomials mod q in Z_q[X]/(X^n+1) via schoolbook
/// convolution: O(n^2) coefficient-pair products, each landing at index
/// `i+j` if `i+j<N` or negated at index `i+j-N` otherwise (the negacyclic
/// wraparound `X^N = -1` gives), followed by a single reduction mod q per
/// output coefficient. Slower than an NTT-based multiply, exactly as
/// correct - see this module's own comment for why that tradeoff is the
/// right one at this modulus.
pub fn poly_mul_mod_q_schoolbook(a: &[i64], b: &[i64]) -> Vec<i64> {
    debug_assert_eq!(a.len(), N);
    debug_assert_eq!(b.len(), N);

    let mut acc = vec![0i64; N];
    for i in 0..N {
        if a[i] == 0 {
            continue;
        }
        for j in 0..N {
            if b[j] == 0 {
                continue;
            }
            let term = a[i] * b[j];
            let raw = i + j;
            if raw < N {
                acc[raw] += term;
            } else {
                acc[raw - N] -= term;
            }
        }
    }
    for v in acc.iter_mut() {
        *v = v.rem_euclid(Q);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    // N is a crate-wide const (512), but sparse hand-computable cases at
    // full length are still practical (most coefficients zero) - these
    // exercise the two structurally distinct code paths (plain index
    // placement vs. the negacyclic wraparound's sign flip) with an exact,
    // by-hand-checkable expected answer, not just internal self-
    // consistency. Combined with two property checks below (identity,
    // distributivity) that neither wraparound sign nor index arithmetic
    // could satisfy by accident if wrong.

    fn sparse_poly(entries: &[(usize, i64)]) -> Vec<i64> {
        let mut out = vec![0i64; N];
        for &(index, value) in entries {
            out[index] = value.rem_euclid(Q);
        }
        out
    }

    #[test]
    fn hand_computable_case_without_wraparound() {
        // a = X^2, b = 2 + X^3  =>  a*b = 2*X^2 + X^5 (exponent sum 5 < N,
        // no wraparound involved at all).
        let a = sparse_poly(&[(2, 1)]);
        let b = sparse_poly(&[(0, 2), (3, 1)]);
        let expected = sparse_poly(&[(2, 2), (5, 1)]);
        assert_eq!(poly_mul_mod_q_schoolbook(&a, &b), expected);
    }

    #[test]
    fn hand_computable_case_with_negacyclic_wraparound() {
        // a = X^510, b = X^3 => exponent sum 513 >= N=512, wraps to index
        // 513-512=1 with X^N=-1's sign flip: a*b = -X^1 = (q-1)*X^1 in
        // Z_q's canonical [0,q) representation.
        let a = sparse_poly(&[(510, 1)]);
        let b = sparse_poly(&[(3, 1)]);
        let expected = sparse_poly(&[(1, -1)]);
        assert_eq!(poly_mul_mod_q_schoolbook(&a, &b), expected);
    }
    struct XorShiftRng(u64);
    impl XorShiftRng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn range_q(&mut self) -> i64 {
            (self.next() % Q as u64) as i64
        }
    }

    fn random_poly(rng: &mut XorShiftRng) -> Vec<i64> {
        (0..N).map(|_| rng.range_q()).collect()
    }

    fn add_mod_q(a: &[i64], b: &[i64]) -> Vec<i64> {
        (0..N).map(|i| (a[i] + b[i]).rem_euclid(Q)).collect()
    }

    #[test]
    fn multiplying_by_one_is_identity() {
        let mut rng = XorShiftRng(0x5eed_5eed_5eed_5eedu64);
        let mut one = vec![0i64; N];
        one[0] = 1;
        for _ in 0..20 {
            let a = random_poly(&mut rng);
            let product = poly_mul_mod_q_schoolbook(&a, &one);
            assert_eq!(product, a, "multiplying by the ring identity must be a no-op");
        }
    }

    #[test]
    fn multiplication_distributes_over_addition() {
        let mut rng = XorShiftRng(0xdead_beef_1234_5678u64);
        for _ in 0..20 {
            let a = random_poly(&mut rng);
            let b = random_poly(&mut rng);
            let c = random_poly(&mut rng);
            let lhs = poly_mul_mod_q_schoolbook(&a, &add_mod_q(&b, &c));
            let rhs = add_mod_q(
                &poly_mul_mod_q_schoolbook(&a, &b),
                &poly_mul_mod_q_schoolbook(&a, &c),
            );
            assert_eq!(lhs, rhs, "a*(b+c) must equal a*b + a*c mod q");
        }
    }
}
