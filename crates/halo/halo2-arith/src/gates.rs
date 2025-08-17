//! gates module

/// Gate trait
pub trait Gate {}

/// Standard gate
#[derive(Clone, Debug)]
pub struct StandardGate;

impl Gate for StandardGate {}

/// Custom gate
#[derive(Clone, Debug)]
pub struct CustomGate;

impl Gate for CustomGate {}
