use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Pcap(pcap::Error),
    LockError,
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Io(error) => write!(formatter, "IO error: {}", error),
            Error::Pcap(error) => write!(formatter, "PCAP error: {}", error),
            Error::LockError => write!(formatter, "Failed to acquire lock"),
            Error::Other(error) => write!(formatter, "Other error: {}", error),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Io(error)
    }
}

impl From<pcap::Error> for Error {
    fn from(error: pcap::Error) -> Self {
        Error::Pcap(error)
    }
}

impl From<String> for Error {
    fn from(error: String) -> Self {
        Error::Other(error)
    }
}