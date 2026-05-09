//! Модуль авторизации
//!
//! Двухшаговый auth flow:
//! 1. SignIn через Xaman — получаем wallet_address
//! 2. Sign Challenge — получаем signature для деривации PRE ключей

pub mod session;
pub mod xaman;

pub use session::Session;
pub use xaman::{XamanAuth, XamanPayload, KeyDerivationResult, SignInResult};