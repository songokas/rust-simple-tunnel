use byte_unit::ByteError;
use humantime::DurationError;
use ipnetwork::IpNetworkError;
use std::io;
use std::net;

#[derive(Debug)]
pub enum RuleError
{
    InvalidNetwork(String),
    InvalidByte(String),
    InvalidDuration(String),
}

#[derive(Debug)]
pub enum CliError
{
    IoError(io::Error),
    NetError(net::AddrParseError),
    InvalidRule(RuleError),
    SyntaxError(String),
}

impl From<io::Error> for CliError
{
    fn from(error: io::Error) -> Self
    {
        CliError::IoError(error)
    }
}

impl From<net::AddrParseError> for CliError
{
    fn from(error: net::AddrParseError) -> Self
    {
        CliError::NetError(error)
    }
}

impl From<IpNetworkError> for RuleError
{
    fn from(error: IpNetworkError) -> Self
    {
        RuleError::InvalidNetwork(error.to_string())
    }
}

impl From<ByteError> for RuleError
{
    fn from(error: ByteError) -> Self
    {
        RuleError::InvalidByte(error.to_string())
    }
}

impl From<DurationError> for RuleError
{
    fn from(error: DurationError) -> Self
    {
        RuleError::InvalidDuration(error.to_string())
    }
}
