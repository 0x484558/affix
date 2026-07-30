use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};

pub const MAX_IMAGE_NAME_CHARS: usize = 260;

#[derive(Clone, Copy)]
pub struct ImageName {
    len: u16,
    chars: [char; MAX_IMAGE_NAME_CHARS],
}

impl ImageName {
    pub fn from_os_str(value: &OsStr) -> Result<Self, ImageNameError> {
        Self::parse(&value.to_string_lossy())
    }

    pub fn parse(value: &str) -> Result<Self, ImageNameError> {
        let mut image = Self::empty();
        for ch in value.chars() {
            image.push_lowercase(ch)?;
        }
        if image.is_empty() {
            return Err(ImageNameError::Empty);
        }
        Ok(image)
    }

    pub fn as_string(&self) -> String {
        self.chars[..usize::from(self.len)].iter().collect()
    }

    pub fn eq_ignore_ascii_case_str(&self, other: &str) -> bool {
        self.chars[..usize::from(self.len)]
            .iter()
            .copied()
            .eq(other.chars().flat_map(char::to_lowercase))
    }

    const fn empty() -> Self {
        Self {
            len: 0,
            chars: ['\0'; MAX_IMAGE_NAME_CHARS],
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push_lowercase(&mut self, ch: char) -> Result<(), ImageNameError> {
        for lower in ch.to_lowercase() {
            let index = usize::from(self.len);
            if index >= MAX_IMAGE_NAME_CHARS {
                return Err(ImageNameError::TooLong);
            }
            self.chars[index] = lower;
            self.len += 1;
        }
        Ok(())
    }
}

impl fmt::Debug for ImageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for ImageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for ch in &self.chars[..usize::from(self.len)] {
            f.write_char(*ch)?;
        }
        Ok(())
    }
}

impl PartialEq for ImageName {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len
            && self.chars[..usize::from(self.len)] == other.chars[..usize::from(other.len)]
    }
}

impl Eq for ImageName {}

impl Hash for ImageName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.len.hash(state);
        self.chars[..usize::from(self.len)].hash(state);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageNameError {
    Empty,
    TooLong,
}

impl fmt::Display for ImageNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "image name must not be empty"),
            Self::TooLong => write!(f, "image name exceeds {MAX_IMAGE_NAME_CHARS} characters"),
        }
    }
}

impl Error for ImageNameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_names_normalize_case() {
        let image = ImageName::parse("Example.EXE").unwrap();
        assert_eq!(image.as_string(), "example.exe");
        assert!(image.eq_ignore_ascii_case_str("EXAMPLE.exe"));
    }

    #[test]
    fn image_names_reject_empty_and_oversized_values() {
        assert_eq!(ImageName::parse(""), Err(ImageNameError::Empty));
        assert_eq!(
            ImageName::parse(&"x".repeat(MAX_IMAGE_NAME_CHARS + 1)),
            Err(ImageNameError::TooLong)
        );
    }
}
