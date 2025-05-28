use anyhow::{Context, Result};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use openssl::hash::MessageDigest;
use std::fs;
use std::path::Path;

/// RSA数字签名器
pub struct RsaSigner {
    private_key: PKey<Private>,
}

impl RsaSigner {
    /// 从PEM格式的私钥文件创建签名器
    pub fn from_pem_file<P: AsRef<Path>>(key_path: P) -> Result<Self> {
        let key_data = fs::read(key_path.as_ref())
            .with_context(|| format!("Failed to read private key file: {}", key_path.as_ref().display()))?;
        
        let rsa = Rsa::private_key_from_pem(&key_data)
            .context("Failed to parse RSA private key from PEM")?;
        
        let private_key = PKey::from_rsa(rsa)
            .context("Failed to create PKey from RSA private key")?;
        
        Ok(Self { private_key })
    }

    /// 从PEM格式的私钥字符串创建签名器
    pub fn from_pem_str(pem_str: &str) -> Result<Self> {
        let rsa = Rsa::private_key_from_pem(pem_str.as_bytes())
            .context("Failed to parse RSA private key from PEM string")?;
        
        let private_key = PKey::from_rsa(rsa)
            .context("Failed to create PKey from RSA private key")?;
        
        Ok(Self { private_key })
    }

    /// 对哈希值进行签名
    pub fn sign_hash(&self, hash: &str) -> Result<Vec<u8>> {
        let mut signer = Signer::new(MessageDigest::sha256(), &self.private_key)
            .context("Failed to create signer")?;
        
        signer.update(hash.as_bytes())
            .context("Failed to update signer with hash data")?;
        
        let signature = signer.sign_to_vec()
            .context("Failed to generate signature")?;
        
        Ok(signature)
    }

    /// 对哈希值进行签名并返回十六进制字符串
    pub fn sign_hash_hex(&self, hash: &str) -> Result<String> {
        let signature = self.sign_hash(hash)?;
        Ok(hex::encode(signature))
    }

    /// 对文件哈希进行签名并保存到文件
    pub fn sign_hash_to_file<P: AsRef<Path>>(&self, hash: &str, output_path: P) -> Result<()> {
        let signature = self.sign_hash(hash)?;
        fs::write(output_path.as_ref(), signature)
            .with_context(|| format!("Failed to write signature to file: {}", output_path.as_ref().display()))?;
        Ok(())
    }
}

/// RSA数字签名验证器
pub struct RsaVerifier {
    public_key: PKey<Public>,
}

impl RsaVerifier {
    /// 从PEM格式的公钥文件创建验证器
    pub fn from_pem_file<P: AsRef<Path>>(key_path: P) -> Result<Self> {
        let key_data = fs::read(key_path.as_ref())
            .with_context(|| format!("Failed to read public key file: {}", key_path.as_ref().display()))?;
        
        let rsa = Rsa::public_key_from_pem(&key_data)
            .context("Failed to parse RSA public key from PEM")?;
        
        let public_key = PKey::from_rsa(rsa)
            .context("Failed to create PKey from RSA public key")?;
        
        Ok(Self { public_key })
    }

    /// 从PEM格式的公钥字符串创建验证器
    pub fn from_pem_str(pem_str: &str) -> Result<Self> {
        let rsa = Rsa::public_key_from_pem(pem_str.as_bytes())
            .context("Failed to parse RSA public key from PEM string")?;
        
        let public_key = PKey::from_rsa(rsa)
            .context("Failed to create PKey from RSA public key")?;
        
        Ok(Self { public_key })
    }

    /// 验证哈希值的签名
    pub fn verify_hash(&self, hash: &str, signature: &[u8]) -> Result<bool> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), &self.public_key)
            .context("Failed to create verifier")?;
        
        verifier.update(hash.as_bytes())
            .context("Failed to update verifier with hash data")?;
        
        let is_valid = verifier.verify(signature)
            .context("Failed to verify signature")?;
        
        Ok(is_valid)
    }

    /// 验证哈希值的十六进制签名
    pub fn verify_hash_hex(&self, hash: &str, signature_hex: &str) -> Result<bool> {
        let signature = hex::decode(signature_hex)
            .context("Failed to decode hex signature")?;
        
        self.verify_hash(hash, &signature)
    }

    /// 从文件读取签名并验证哈希值
    pub fn verify_hash_from_file<P: AsRef<Path>>(&self, hash: &str, signature_path: P) -> Result<bool> {
        let signature = fs::read(signature_path.as_ref())
            .with_context(|| format!("Failed to read signature file: {}", signature_path.as_ref().display()))?;
        
        self.verify_hash(hash, &signature)
    }
}

/// 签名和验证的便利函数
pub struct SignatureManager {
    signer: Option<RsaSigner>,
    verifier: Option<RsaVerifier>,
}

impl SignatureManager {
    /// 创建新的签名管理器
    pub fn new() -> Self {
        Self {
            signer: None,
            verifier: None,
        }
    }

    /// 设置私钥用于签名
    pub fn with_private_key_file<P: AsRef<Path>>(mut self, key_path: P) -> Result<Self> {
        self.signer = Some(RsaSigner::from_pem_file(key_path)?);
        Ok(self)
    }

    /// 设置公钥用于验证
    pub fn with_public_key_file<P: AsRef<Path>>(mut self, key_path: P) -> Result<Self> {
        self.verifier = Some(RsaVerifier::from_pem_file(key_path)?);
        Ok(self)
    }

    /// 对哈希值进行签名
    pub fn sign(&self, hash: &str) -> Result<Vec<u8>> {
        let signer = self.signer.as_ref()
            .context("No private key configured for signing")?;
        signer.sign_hash(hash)
    }

    /// 验证哈希值的签名
    pub fn verify(&self, hash: &str, signature: &[u8]) -> Result<bool> {
        let verifier = self.verifier.as_ref()
            .context("No public key configured for verification")?;
        verifier.verify_hash(hash, signature)
    }

    /// 检查是否可以进行签名
    pub fn can_sign(&self) -> bool {
        self.signer.is_some()
    }

    /// 检查是否可以进行验证
    pub fn can_verify(&self) -> bool {
        self.verifier.is_some()
    }
}

impl Default for SignatureManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::rsa::Rsa;
    use openssl::pkey::PKey;

    fn generate_test_keypair() -> (String, String) {
        let rsa = Rsa::generate(2048).unwrap();
        let private_key = PKey::from_rsa(rsa.clone()).unwrap();
        let public_key = PKey::from_rsa(rsa).unwrap();
        
        let private_pem = private_key.private_key_to_pem_pkcs8().unwrap();
        let public_pem = public_key.public_key_to_pem().unwrap();
        
        (
            String::from_utf8(private_pem).unwrap(),
            String::from_utf8(public_pem).unwrap(),
        )
    }

    #[test]
    fn test_sign_and_verify() {
        let (private_pem, public_pem) = generate_test_keypair();
        
        let signer = RsaSigner::from_pem_str(&private_pem).unwrap();
        let verifier = RsaVerifier::from_pem_str(&public_pem).unwrap();
        
        let hash = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
        let signature = signer.sign_hash(hash).unwrap();
        
        let is_valid = verifier.verify_hash(hash, &signature).unwrap();
        assert!(is_valid);
        
        // Test with wrong hash
        let wrong_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let is_valid = verifier.verify_hash(wrong_hash, &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_signature_manager() {
        let (private_pem, public_pem) = generate_test_keypair();
        
        // Write keys to temporary files
        let temp_dir = std::env::temp_dir();
        let private_key_path = temp_dir.join("test_private.pem");
        let public_key_path = temp_dir.join("test_public.pem");
        
        std::fs::write(&private_key_path, private_pem).unwrap();
        std::fs::write(&public_key_path, public_pem).unwrap();
        
        let manager = SignatureManager::new()
            .with_private_key_file(&private_key_path).unwrap()
            .with_public_key_file(&public_key_path).unwrap();
        
        assert!(manager.can_sign());
        assert!(manager.can_verify());
        
        let hash = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
        let signature = manager.sign(hash).unwrap();
        let is_valid = manager.verify(hash, &signature).unwrap();
        assert!(is_valid);
        
        // Cleanup
        std::fs::remove_file(private_key_path).ok();
        std::fs::remove_file(public_key_path).ok();
    }
} 