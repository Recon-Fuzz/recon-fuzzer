//! Generic array mutation helpers
//!

use rand::prelude::*;

/// Mutate a list-like structure
pub fn mutate_ll<R: Rng, T: Clone>(
    rng: &mut R,
    target_len: Option<usize>,
    complement: Vec<T>,
    xs: &[T],
) -> Vec<T> {
    // Select mutator (weighted [pure 1, expand 10, delete 10, swap 10])
    let mutated = match rng.gen_range(0..31) {
        0 => xs.to_vec(), // 1/31 no-op
        1..=10 => expand_rand_list(rng, xs),
        11..=20 => delete_rand_list(rng, xs),
        _ => swap_rand_list(rng, xs),
    };

    match target_len {
        Some(len) => {
            let mut res = mutated;
            if res.len() < len {
                res.extend(complement);
            }
            res.truncate(len);
            res
        }
        None => mutated,
    }
}

pub fn expand_rand_list<R: Rng, T: Clone>(rng: &mut R, txs: &[T]) -> Vec<T> {
    let l = txs.len();
    if l == 0 || l >= 32 {
        return txs.to_vec();
    }
    let k = rng.gen_range(0..l);
    let t = rng.gen_range(1..=32.min(l));
    expand_at(txs, k, t)
}

fn expand_at<T: Clone>(xs: &[T], k: usize, t: usize) -> Vec<T> {
    if xs.is_empty() {
        return Vec::new();
    }
    if k == 0 {
        let mut res = Vec::with_capacity(xs.len() + t);
        res.extend(std::iter::repeat(xs[0].clone()).take(t));
        res.extend_from_slice(&xs[1..]);
        res
    } else {
        let mut res = Vec::with_capacity(xs.len() + t);
        res.push(xs[0].clone());
        res.extend(expand_at(&xs[1..], k - 1, t));
        res
    }
}

pub fn swap_rand_list<R: Rng, T: Clone>(rng: &mut R, txs: &[T]) -> Vec<T> {
    if txs.len() < 2 {
        return txs.to_vec();
    }
    let mut result = txs.to_vec();
    let i = rng.gen_range(0..txs.len());
    let j = rng.gen_range(0..txs.len());
    result.swap(i, j);
    result
}

pub fn delete_rand_list<R: Rng, T: Clone>(rng: &mut R, txs: &[T]) -> Vec<T> {
    if txs.is_empty() {
        return Vec::new();
    }
    let mut result = txs.to_vec();
    let idx = rng.gen_range(0..txs.len());
    result.remove(idx);
    result
}

pub fn splice_at_random<R: Rng, T: Clone>(rng: &mut R, a: &[T], b: &[T]) -> Vec<T> {
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    let cut_a = rng.gen_range(0..=a.len());
    let cut_b = rng.gen_range(0..=b.len());
    let mut result = a[..cut_a].to_vec();
    result.extend_from_slice(&b[cut_b..]);
    result
}

pub fn interleave_at_random<R: Rng, T: Clone>(rng: &mut R, a: &[T], b: &[T]) -> Vec<T> {
    let idx1 = rng.gen_range(0..a.len());
    let idx2 = rng.gen_range(0..b.len());
    interleave_ll(&a[..idx1], &b[..idx2])
}

fn interleave_ll<T: Clone>(a: &[T], b: &[T]) -> Vec<T> {
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    let mut res = Vec::with_capacity(a.len() + b.len());
    res.push(a[0].clone());
    res.push(b[0].clone());
    res.extend(interleave_ll(&a[1..], &b[1..]));
    res
}
