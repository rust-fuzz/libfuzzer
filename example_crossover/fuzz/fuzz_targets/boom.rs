#![no_main]

use example_crossover::sum;
use libfuzzer_sys::{fuzz_crossover, fuzz_mutator, fuzz_target};
use rand::distributions::{Bernoulli, Distribution, Uniform};
use rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use std::mem::size_of;

fuzz_target!(|data: &[u8]| {
    let (_, floats, _) = unsafe { data.align_to::<f64>() };

    let res = sum(floats);

    assert!(
        !res.is_nan(),
        "The sum of the following f64's resulted in a NaN: {floats:?}"
    );
});

fn rfp(rng: &mut StdRng) -> f64 {
    match Uniform::new_inclusive(0, 10).sample(rng) {
        0 => f64::NAN,
        1 => f64::MIN,
        2 => f64::MAX,
        3 => -f64::MIN,
        4 => -f64::MAX,
        5 => f64::EPSILON,
        6 => -f64::EPSILON,
        7 => f64::INFINITY,
        8 => f64::NEG_INFINITY,
        9 => 0.0,
        10 => Uniform::new_inclusive(-1.0, 1.0).sample(rng),
        _ => 0.0,
    }
}

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    let mut gen = StdRng::seed_from_u64(seed.into());

    match Uniform::new_inclusive(0, 3).sample(&mut gen) {
        0 => {
            // "Change [an] element"

            // Not altering the size, so decode the intended space (i.e. `size`) as floats
            let (_, floats, _) = unsafe { data[..size].align_to_mut::<f64>() };

            if !floats.is_empty() {
                let d = Uniform::new(0, floats.len());
                floats[d.sample(&mut gen)] = rfp(&mut gen);
            }
        }
        1 => {
            // "Add [an] element [to the end]"
            let plus_one = size + size_of::<f64>();
            if plus_one <= max_size {
                // Adding 1, f64 to the size, so decode the intended space (i.e.
                // `size`) plus one more (since we just checked it will fit) as floats
                let (_, floats, _) = unsafe { data[..plus_one].align_to_mut::<f64>() };

                let last = floats.last_mut().unwrap();
                *last = rfp(&mut gen);

                return plus_one;
            }
        }
        2 => {
            // "Delete [the end] element"

            // Attempting to shrink the size by 1, f64, so decode the intended
            // space (i.e. `size`) as floats and see if we have any
            let (_, floats, _) = unsafe { data[..size].align_to::<f64>() };

            if !floats.is_empty() {
                return size - size_of::<f64>();
            }
        }
        3 => {
            // "Shuffle [the] elements"

            // Not altering the size, so decode the intended space (i.e. `size`) as floats
            let (_, floats, _) = unsafe { data[..size].align_to_mut::<f64>() };
            floats.shuffle(&mut gen);
        }
        _ => unreachable!(),
    };

    size
});

fuzz_crossover!(|data1: &[u8], data2: &[u8], out: &mut [u8], seed: u32| {
    let mut gen = StdRng::seed_from_u64(seed.into());

    let bd = Bernoulli::new(0.5).unwrap();

    // Decode each source to see how many floats we can pull with proper
    // alignment, and destination as to how many will fit with proper alignment
    //
    // Keep track of the unaligned prefix to `out`, as we will need to remember
    // that those bytes will remain prepended to the actual floats that we
    // write into the out buffer.
    let (out_pref, out_floats, _) = unsafe { out.align_to_mut::<f64>() };
    let (_, d1_floats, _) = unsafe { data1.align_to::<f64>() };
    let (_, d2_floats, _) = unsafe { data2.align_to::<f64>() };

    // Given that the sources and destinations may have drastically fewer
    // available aligned floats than decoding allows for; see which has the
    // smallest number.
    let n = *[out_floats.len(), d1_floats.len(), d2_floats.len()]
        .iter()
        .min()
        .unwrap();

    // Put into the destination, floats from either data1 or data2 if the
    // Bernoulli distribution succeeds or fails
    for i in 0..n {
        out_floats[i] = if bd.sample(&mut gen) {
            d1_floats[i]
        } else {
            d2_floats[i]
        };
    }

    // Now that we have written the true floats, report back to the fuzzing
    // engine that we left the unaligned `out` prefix bytes at the beginning of
    // `out` and also then the floats that we wrote into the aligned float
    // section.
    out_pref.len() * size_of::<u8>() + n * size_of::<f64>()
});
