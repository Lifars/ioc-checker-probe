use std::io::{Read, BufReader, Write};
use std::io;
use std::fs::File;
use md5::{Md5, Digest};
use sha1::Sha1;
use sha2::Sha256;
use std::str::Utf8Error;
use std::path::Path;
use std::fmt::{Display, Formatter};
use serde::export::fmt::Error;
use crate::data::{HashType, Hashed};

#[derive(Debug)]
pub struct HashError {
    pub kind: String,
    pub message: String,
}

impl Display for HashError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(f, "HashError(kind: {}, message: {})", self.kind, self.message)
    }
}

pub struct Hasher {
    algorithm: HashType
}

impl From<io::Error> for HashError {
    fn from(error: io::Error) -> Self {
        HashError {
            kind: String::from("IO Error"),
            message: error.to_string(),
        }
    }
}

impl From<Utf8Error> for HashError {
    fn from(error: Utf8Error) -> Self {
        HashError {
            kind: String::from("UTF-8 conversion"),
            message: error.to_string(),
        }
    }
}

impl Hasher {
    pub fn new(algorithm: HashType) -> Hasher { Hasher { algorithm } }

    fn hash_impl<R: Read, D: Digest + Write>(&self, mut reader: R, mut algorithm: D) -> Result<Hashed, HashError> {
        io::copy(&mut reader, &mut algorithm)?;
        let result_array = algorithm.result();
        let result = hex::encode(result_array);
        Ok(Hashed { algorithm: self.algorithm.clone(), value: result })
    }

    pub fn hash<R: Read>(&self, reader: R) -> Result<Hashed, HashError> {
        return match self.algorithm {
            HashType::Md5 => self.hash_impl(reader, Md5::new()),
            HashType::Sha1 => self.hash_impl(reader, Sha1::new()),
            HashType::Sha256 => self.hash_impl(reader, Sha256::new()),
        };
    }

    pub fn hash_file(&self, file: File) -> Result<Hashed, HashError> {
        let reader = BufReader::new(file);
        return self.hash(reader);
    }

    pub fn hash_file_by_path(&self, file_path: &Path) -> Result<Hashed, HashError> {
        let file = File::open(file_path);

        match file {
            Ok(file) => self.hash_file(file),
            Err(error) => Err(HashError {
                kind: "IO Error".to_string(),
                message: format!("Cannot open file \"{}\": {}", file_path.display(), error),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_md5() {
        use md5::{Md5, Digest};
        let mut hasher = Md5::new();
        hasher.input(b"hello world");
        let result = hasher.result();
        let text = hex::encode(result);
        assert_eq!(text.as_str(), "5eb63bbbe01eeed093cb22bb8f5acdc3");
    }
}