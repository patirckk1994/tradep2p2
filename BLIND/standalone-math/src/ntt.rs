// Faithful Rust port of FALCON's own NTT-based polynomial multiplication
// (Falcon-impl-20211101/vrfy.c's mq_NTT/mq_iNTT/mq_montymul/etc.), ported
// function-by-function against the real C source, not re-derived from
// scratch - see ../../../README_PROTOTYPE.md's optimization note for why
// that distinction matters. Replaces the guest's O(n^2) schoolbook
// poly_mul_mod_q with O(n log n), same modulus (q=12289), same tables
// (ntt_tables.rs, extracted programmatically from the C source).
//
// Cross-checked against the schoolbook implementation on random inputs
// before ever being trusted - see tests below and the self-check the guest
// runs at startup (main.rs).

use crate::ntt_tables::{GMB, IGMB};

const N: usize = 512;
const LOGN: u32 = 9;
const Q: u32 = 12289;
const Q0I: u32 = 12287;
const R: u32 = 4091;
const R2: u32 = 10952;

#[inline]
fn mq_add(x: u32, y: u32) -> u32 {
    let mut d = x.wrapping_add(y).wrapping_sub(Q);
    d = d.wrapping_add(Q & (0u32.wrapping_sub(d >> 31)));
    d
}

#[inline]
fn mq_sub(x: u32, y: u32) -> u32 {
    let mut d = x.wrapping_sub(y);
    d = d.wrapping_add(Q & (0u32.wrapping_sub(d >> 31)));
    d
}

#[inline]
fn mq_montymul(x: u32, y: u32) -> u32 {
    let mut z = x.wrapping_mul(y);
    let w = (z.wrapping_mul(Q0I) & 0xFFFF).wrapping_mul(Q);
    z = (z.wrapping_add(w)) >> 16;
    z = z.wrapping_sub(Q);
    z = z.wrapping_add(Q & (0u32.wrapping_sub(z >> 31)));
    z
}

#[inline]
fn mq_rshift1(x: u32) -> u32 {
    let x = x.wrapping_add(Q & (0u32.wrapping_sub(x & 1)));
    x >> 1
}

fn mq_ntt(a: &mut [u16; N]) {
    let mut t = N;
    let mut m = 1usize;
    while m < N {
        let ht = t >> 1;
        let mut j1 = 0usize;
        for i in 0..m {
            let s = GMB[m + i] as u32;
            let j2 = j1 + ht;
            for j in j1..j2 {
                let u = a[j] as u32;
                let v = mq_montymul(a[j + ht] as u32, s);
                a[j] = mq_add(u, v) as u16;
                a[j + ht] = mq_sub(u, v) as u16;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

fn mq_intt(a: &mut [u16; N]) {
    let mut t = 1usize;
    let mut m = N;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1 = 0usize;
        for i in 0..hm {
            let j2 = j1 + t;
            let s = IGMB[hm + i] as u32;
            for j in j1..j2 {
                let u = a[j] as u32;
                let v = a[j + t] as u32;
                a[j] = mq_add(u, v) as u16;
                let w = mq_sub(u, v);
                a[j + t] = mq_montymul(w, s) as u16;
            }
            j1 += dt;
        }
        t = dt;
        m = hm;
    }
    let mut ni = R;
    let mut mm = N;
    while mm > 1 {
        ni = mq_rshift1(ni);
        mm >>= 1;
    }
    for v in a.iter_mut() {
        *v = mq_montymul(*v as u32, ni) as u16;
    }
}

fn mq_poly_tomonty(f: &mut [u16; N]) {
    for v in f.iter_mut() {
        *v = mq_montymul(*v as u32, R2) as u16;
    }
}

fn mq_poly_montymul_ntt(f: &mut [u16; N], g: &[u16; N]) {
    for i in 0..N {
        f[i] = mq_montymul(f[i] as u32, g[i] as u32) as u16;
    }
}

fn reduce_to_u16(v: i64) -> u16 {
    v.rem_euclid(Q as i64) as u16
}

/// Multiplies two polynomials mod q in Z_q[X]/(X^n+1), via NTT - same
/// modulus, same ring, same result as the schoolbook version, ~57x fewer
/// multiply operations for n=512 (O(n log n) vs O(n^2)). Mirrors exactly
/// how FALCON's own verify_raw() multiplies s2 by the public key h (see
/// vrfy.c): one operand gets the extra Montgomery pre-scale
/// (mq_poly_tomonty), the other doesn't - the R factor this introduces is
/// exactly what mq_montymul's pointwise multiply divides back out,
/// leaving the true convolution product after the inverse NTT.
pub fn poly_mul_mod_q_ntt(a: &[i64], b: &[i64]) -> Vec<i64> {
    let mut a_arr: [u16; N] = core::array::from_fn(|i| reduce_to_u16(a[i]));
    let mut b_arr: [u16; N] = core::array::from_fn(|i| reduce_to_u16(b[i]));

    mq_poly_tomonty(&mut b_arr);
    mq_ntt(&mut a_arr);
    mq_ntt(&mut b_arr);
    mq_poly_montymul_ntt(&mut a_arr, &b_arr);
    mq_intt(&mut a_arr);

    a_arr.iter().map(|&v| v as i64).collect()
}

#[allow(dead_code)]
pub fn logn() -> u32 {
    LOGN
}

#[cfg(test)]
mod tests {
    use super::*;

    // Regression test replacing the original research prototype's
    // standalone ntt_verify/ tool: cross-checks poly_mul_mod_q_ntt
    // against a plain schoolbook reference on 200 random trials, mixing
    // dense-random and short-vector operand patterns (matching the real
    // B/h vs. r/s2 usage) - this must pass before this NTT port is
    // trusted anywhere inside a zkVM guest.
    fn poly_mul_schoolbook(a: &[i64], b: &[i64]) -> Vec<i64> {
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
            *v = v.rem_euclid(Q as i64);
        }
        acc
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
        fn small(&mut self) -> i64 {
            (self.next() % 5) as i64 - 2 // [-2, 2], matches r's own distribution
        }
    }

    #[test]
    fn ntt_multiply_matches_schoolbook_on_200_random_trials() {
        let mut rng = XorShiftRng(0xdead_beef_cafe_f00d);
        const TRIALS: usize = 200;
        for trial in 0..TRIALS {
            let a: Vec<i64> = if trial % 2 == 0 {
                (0..N).map(|_| rng.range_q()).collect()
            } else {
                (0..N).map(|_| rng.small()).collect()
            };
            let b: Vec<i64> = (0..N).map(|_| rng.range_q()).collect();

            let schoolbook = poly_mul_schoolbook(&a, &b);
            let via_ntt = poly_mul_mod_q_ntt(&a, &b);
            assert_eq!(schoolbook, via_ntt, "mismatch on trial {trial}");
        }
    }
}
