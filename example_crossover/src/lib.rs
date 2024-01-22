pub fn sum(floats: &[f64]) -> f64 {
    floats
        .iter()
        .fold(0.0, |a, b| if b.is_nan() { a } else { a + b })
}
