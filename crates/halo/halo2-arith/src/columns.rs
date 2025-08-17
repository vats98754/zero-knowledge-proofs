//! columns module

/// Column trait
pub trait Column {}

/// Advice column
#[derive(Clone, Debug)]
pub struct AdviceColumn;

impl Column for AdviceColumn {}

/// Fixed column
#[derive(Clone, Debug)]
pub struct FixedColumn;

impl Column for FixedColumn {}

/// Instance column
#[derive(Clone, Debug)]
pub struct InstanceColumn;

impl Column for InstanceColumn {}
