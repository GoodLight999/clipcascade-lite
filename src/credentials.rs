use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{mem::zeroed, ptr::null_mut};
use windows_sys::Win32::{Foundation::ERROR_NOT_FOUND, Security::Credentials::*};
use zeroize::{Zeroize, Zeroizing};

pub struct Target(Vec<u16>);

impl Target {
    pub fn new(server: &str, username: &str) -> Self {
        let mut digest = Sha256::new();
        digest.update(server.trim_end_matches('/').as_bytes());
        digest.update([0]);
        digest.update(username.as_bytes());
        Self(
            format!("ClipCascade Lite/{:x}", digest.finalize())
                .encode_utf16()
                .chain([0])
                .collect(),
        )
    }

    pub fn read(&self) -> Result<Option<Zeroizing<String>>> {
        let mut raw = null_mut();
        if unsafe { CredReadW(self.0.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(None);
            }
            return Err(error).context("Windows資格情報マネージャーを読み込めません");
        }
        unsafe {
            let credential = &mut *raw;
            let result =
                if credential.CredentialBlobSize == 0 || credential.CredentialBlob.is_null() {
                    Ok(None)
                } else {
                    let blob = std::slice::from_raw_parts_mut(
                        credential.CredentialBlob,
                        credential.CredentialBlobSize as usize,
                    );
                    let read = std::str::from_utf8(blob)
                        .map(|value| Some(Zeroizing::new(value.to_owned())));
                    blob.zeroize();
                    read.context("保存済みパスワードの形式が無効です")
                };
            CredFree(raw.cast());
            result
        }
    }

    pub fn write(&self, password: &str) -> Result<()> {
        ensure!(
            !password.is_empty() && password.len() <= CRED_MAX_CREDENTIAL_BLOB_SIZE as usize,
            "保存できるパスワードの長さを超えています"
        );
        let mut blob = Zeroizing::new(password.as_bytes().to_vec());
        let mut target = self.0.clone();
        let mut credential: CREDENTIALW = unsafe { zeroed() };
        credential.Type = CRED_TYPE_GENERIC;
        credential.TargetName = target.as_mut_ptr();
        credential.CredentialBlobSize = blob.len() as u32;
        credential.CredentialBlob = blob.as_mut_ptr();
        credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
        if unsafe { CredWriteW(&credential, 0) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("Windows資格情報マネージャーに保存できません");
        }
        Ok(())
    }

    pub fn delete(&self) -> Result<()> {
        if unsafe { CredDeleteW(self.0.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                return Err(error).context("保存済みパスワードを削除できません");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_round_trip_is_scoped_to_the_server_and_account() -> Result<()> {
        let user = format!("test-{}", uuid::Uuid::new_v4());
        let target = Target::new("https://example.invalid/clip", &user);
        let result = (|| {
            target.write("検証用-sample-123")?;
            assert_eq!(
                Target::new("https://example.invalid/clip/", &user)
                    .read()?
                    .as_deref()
                    .map(String::as_str),
                Some("検証用-sample-123"),
            );
            assert!(
                Target::new("https://example.invalid/other", &user)
                    .read()?
                    .is_none()
            );
            Ok::<_, anyhow::Error>(())
        })();
        let cleanup = target.delete();
        result?;
        cleanup?;
        assert!(target.read()?.is_none());
        Ok(())
    }
}
