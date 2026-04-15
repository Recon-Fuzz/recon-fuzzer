//! Core traits for fuzzing operations
//!
//! These traits define the fundamental operations for fuzzing:
//! generation, mutation, and shrinking.

/// Trait for types that can be randomly generated
pub trait Generatable {
    /// Generate a random instance
    fn generate<R: rand::Rng>(rng: &mut R) -> Self;
}

/// Trait for types that can be mutated
pub trait Mutatable {
    /// Mutate the value in place
    /// Returns true if mutation was applied
    fn mutate<R: rand::Rng>(&mut self, rng: &mut R) -> bool;
}

/// Trait for types that can be shrunk (simplified)
pub trait Shrinkable {
    /// Try to shrink the value to a simpler form
    /// Returns true if shrinking made progress
    fn shrink(&mut self) -> bool;

    /// Returns a complexity score (lower = simpler)
    /// Used to guide shrinking toward simpler values
    fn complexity(&self) -> u64 {
        0
    }
}

/// Trait for types that can be fuzzed (generated, mutated, and shrunk)
pub trait Fuzzable: Generatable + Mutatable + Shrinkable {}

// Blanket implementation
impl<T: Generatable + Mutatable + Shrinkable> Fuzzable for T {}
