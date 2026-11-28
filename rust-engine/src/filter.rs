//! Re-exports unified SIMD RegexSet filter rule evaluators from `dex2c_dex`.

pub use dex2c_dex::filter::{
    evaluate_dex_methods, evaluate_dex_methods_and_classes, CompiledFilter,
    FilterMatchResult as DexFilterMatchResult,
};
