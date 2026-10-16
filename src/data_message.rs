//! Тело I2NP `Data` (type 20): длина и непрозрачные данные.
//!
//! ```text
//!   offset  size  field
//!   ------  ----  -----
//!        0     4  length  (BE u32)
//!        4   len  data    (gzip-датаграмма и т.п., не разбираем)
//! ```
//!
//! Как в i2pd (`ClientDestination::HandleDataMessage`), `length` не
//! должен превышать число оставшихся байт; хвост игнорируется.

use crate::endian::{read_u32_be, write_u32_be};
use crate::error::{I2PError, Result};

/// Размер префикса длины.
pub const DATA_MESSAGE_HEADER_SIZE: usize = 4;

/// Тело `Data`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DataBody {
    /// Данные без префикса длины.
    pub data: Vec<u8>,
}

impl DataBody {
    /// Разбирает payload.
    ///
    /// # Errors
    ///
    /// - [`I2PError::InvalidLength`] — буфер короче префикса;
    /// - [`I2PError::Malformed`] — `length` больше оставшихся байт.
    pub fn from_buffer(buf: &[u8]) -> Result<Self> {
        if buf.len() < DATA_MESSAGE_HEADER_SIZE {
            return Err(I2PError::InvalidLength {
                expected: DATA_MESSAGE_HEADER_SIZE,
                got: buf.len(),
            });
        }
        let len = usize::try_from(read_u32_be(buf))
            .map_err(|_| I2PError::Malformed("data message: length overflow"))?;
        let data = buf[DATA_MESSAGE_HEADER_SIZE..]
            .get(..len)
            .ok_or(I2PError::Malformed("data message: length exceeds payload"))?;
        Ok(Self {
            data: data.to_vec(),
        })
    }

    /// Сериализует payload.
    ///
    /// # Errors
    ///
    /// [`I2PError::Malformed`], если `data.len() > u32::MAX`.
    pub fn to_buffer(&self) -> Result<Vec<u8>> {
        let len = u32::try_from(self.data.len())
            .map_err(|_| I2PError::Malformed("data message: data > 4GB"))?;
        let mut out = vec![0u8; DATA_MESSAGE_HEADER_SIZE + self.data.len()];
        write_u32_be(&mut out, len);
        out[DATA_MESSAGE_HEADER_SIZE..].copy_from_slice(&self.data);
        Ok(out)
    }
}
