use thiserror::Error;

#[derive(Error, Debug)]
pub enum NftablesError {
    #[error(transparent)]
    BuilderError(#[from] derive_builder::UninitializedFieldError)
}
