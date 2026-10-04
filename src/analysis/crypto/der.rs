//! Just enough ASN.1 DER to tell what a PEM file holds: the algorithm and size of an RSA or EC key,
//! of the key in a certificate, and a weak signature algorithm. No validation.

/// What a key or certificate is.
pub struct KeyInfo {
    /// `RSA 2048-bit`, `EC secp256r1`, `Ed25519`, ...
    pub algorithm: String,
    /// Why it is weak: a small key or curve, a SHA-1 or MD5 signature.
    pub weak: Vec<String>,
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn read(buf: &[u8]) -> Option<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |a, b| (a << 8) | usize::from(*b)), &rest[n..])
    };
    (rest.len() >= len).then(|| (Tlv { tag, value: &rest[..len] }, &rest[len..]))
}

fn items(mut buf: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = vec![];
    while !buf.is_empty() {
        let Some((t, rest)) = read(buf) else { break };
        out.push(t);
        buf = rest;
    }
    out
}

fn sequence(buf: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let (t, _) = read(buf)?;
    (t.tag == 0x30).then(|| items(t.value))
}

/// The bit length of a DER INTEGER (leading zero bytes dropped).
fn int_bits(t: &Tlv) -> Option<u32> {
    if t.tag != 0x02 {
        return None;
    }
    let v: &[u8] = t.value.iter().position(|b| *b != 0).map_or(&[], |i| &t.value[i..]);
    let first = *v.first()?;
    Some(v.len() as u32 * 8 - first.leading_zeros())
}

fn oid(t: &Tlv) -> Option<String> {
    if t.tag != 0x06 || t.value.is_empty() {
        return None;
    }
    let mut parts = vec![u32::from(t.value[0] / 40), u32::from(t.value[0] % 40)];
    let mut acc = 0u32;
    for b in &t.value[1..] {
        acc = acc.checked_shl(7)? | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            parts.push(acc);
            acc = 0;
        }
    }
    Some(parts.iter().map(u32::to_string).collect::<Vec<_>>().join("."))
}

/// `(name, bits)` of a named curve.
fn curve(o: &str) -> Option<(&'static str, u32)> {
    Some(match o {
        "1.2.840.10045.3.1.1" => ("prime192v1", 192),
        "1.2.840.10045.3.1.7" => ("prime256v1", 256),
        "1.3.132.0.33" => ("secp224r1", 224),
        "1.3.132.0.34" => ("secp384r1", 384),
        "1.3.132.0.35" => ("secp521r1", 521),
        "1.3.132.0.10" => ("secp256k1", 256),
        "1.3.132.0.31" => ("secp192k1", 192),
        "1.3.132.0.8" => ("secp160r1", 160),
        "1.3.132.0.9" => ("secp160k1", 160),
        "1.3.132.0.30" => ("secp160r2", 160),
        "1.3.132.0.1" => ("sect163k1", 163),
        _ => return None,
    })
}

fn signature(o: &str) -> Option<&'static str> {
    Some(match o {
        "1.2.840.113549.1.1.4" => "MD5 signature",
        "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" | "1.2.840.10040.4.3" => "SHA-1 signature",
        _ => return None,
    })
}

fn rsa_info(bits: Option<u32>) -> KeyInfo {
    let mut weak = vec![];
    if let Some(b) = bits.filter(|b| *b < 2048) {
        weak.push(format!("{b}-bit key"));
    }
    KeyInfo { algorithm: bits.map_or("RSA".to_string(), |b| format!("RSA {b}-bit")), weak }
}

fn ec_info(curve_oid: Option<String>) -> KeyInfo {
    match curve_oid.as_deref().and_then(curve) {
        Some((name, bits)) => KeyInfo { algorithm: format!("EC {name}"), weak: if bits < 224 { vec![format!("EC curve {name}")] } else { vec![] } },
        None => KeyInfo { algorithm: "EC".into(), weak: vec![] },
    }
}

/// An `AlgorithmIdentifier` and what follows it (the public key, or the private key octets).
fn by_algorithm(alg: &Tlv, key: Option<&Tlv>, private: bool) -> Option<KeyInfo> {
    let parts = items(alg.value);
    let id = oid(parts.first()?)?;
    Some(match id.as_str() {
        "1.2.840.113549.1.1.1" => {
            let inner = key.map(|k| if private { k.value } else { k.value.get(1..).unwrap_or(&[]) });
            let seq = inner.and_then(sequence);
            // private: version, modulus, ...; public: modulus, exponent
            let modulus = seq.as_ref().and_then(|s| s.get(usize::from(private))).and_then(int_bits);
            rsa_info(modulus)
        }
        "1.2.840.10045.2.1" => ec_info(parts.get(1).and_then(oid)),
        "1.3.101.112" => KeyInfo { algorithm: "Ed25519".into(), weak: vec![] },
        "1.3.101.110" => KeyInfo { algorithm: "X25519".into(), weak: vec![] },
        "1.2.840.10040.4.1" => KeyInfo { algorithm: "DSA".into(), weak: vec!["DSA".into()] },
        _ => return None,
    })
}

/// SubjectPublicKeyInfo: `SEQUENCE { AlgorithmIdentifier, BIT STRING }`.
fn spki(buf: &[u8]) -> Option<KeyInfo> {
    let s = sequence(buf)?;
    by_algorithm(s.first()?, s.get(1), false)
}

/// What the DER body of a PEM block with this label holds.
pub fn key_info(label: &str, der: &[u8]) -> Option<KeyInfo> {
    match label {
        "RSA PRIVATE KEY" => Some(rsa_info(sequence(der)?.get(1).and_then(int_bits))),
        "RSA PUBLIC KEY" => Some(rsa_info(sequence(der)?.first().and_then(int_bits))),
        "PRIVATE KEY" => {
            let s = sequence(der)?;
            by_algorithm(s.get(1)?, s.get(2), true)
        }
        "PUBLIC KEY" => spki(der),
        "EC PRIVATE KEY" => {
            let s = sequence(der)?;
            let params = s.iter().find(|t| t.tag == 0xa0)?;
            Some(ec_info(items(params.value).first().and_then(oid)))
        }
        "DH PARAMETERS" => {
            let bits = sequence(der)?.first().and_then(int_bits)?;
            Some(KeyInfo { algorithm: format!("DH {bits}-bit"), weak: if bits < 2048 { vec![format!("{bits}-bit key")] } else { vec![] } })
        }
        "CERTIFICATE" | "TRUSTED CERTIFICATE" => {
            let cert = sequence(der)?;
            let tbs = items(cert.first()?.value);
            // [0] version is optional: serial, signature, issuer, validity, subject, public key
            let o = usize::from(tbs.first()?.tag == 0xa0);
            let sig = tbs.get(o + 1).and_then(|a| items(a.value).first().and_then(oid)).and_then(|o| signature(&o));
            let key_der = tbs.get(o + 5).map(|k| {
                let mut v = vec![0x30];
                // re-wrap the SPKI contents as a sequence for `spki`
                let len = k.value.len();
                if len < 0x80 {
                    v.push(len as u8);
                } else {
                    let bytes = len.to_be_bytes();
                    let skip = bytes.iter().take_while(|b| **b == 0).count();
                    v.push(0x80 | (bytes.len() - skip) as u8);
                    v.extend_from_slice(&bytes[skip..]);
                }
                v.extend_from_slice(k.value);
                v
            });
            let mut info = key_der.as_deref().and_then(spki).unwrap_or(KeyInfo { algorithm: "X.509".into(), weak: vec![] });
            info.algorithm = format!("X.509 {}", info.algorithm);
            info.weak.extend(sig.map(str::to_string));
            Some(info)
        }
        _ => None,
    }
}

/// What a bare DER structure is, by its shape: `(PEM label, info)`.
pub fn guess(der: &[u8]) -> Option<(&'static str, KeyInfo)> {
    let s = sequence(der)?;
    let tags: Vec<u8> = s.iter().map(|t| t.tag).collect();
    let label = match tags.as_slice() {
        [0x30, 0x30, 0x03] => "CERTIFICATE",
        [0x02, 0x30, 0x04, ..] => "PRIVATE KEY",
        [0x30, 0x03] => "PUBLIC KEY",
        [0x02, 0x04, ..] => "EC PRIVATE KEY",
        [0x02, 0x02] => "RSA PUBLIC KEY",
        [t0, t1, t2, t3, t4, t5, t6, t7, t8, ..] if [t0, t1, t2, t3, t4, t5, t6, t7, t8].iter().all(|t| **t == 0x02) => "RSA PRIVATE KEY",
        _ => return None,
    };
    key_info(label, der).map(|i| (label, i))
}

/// Base64url (JWK) to bytes.
pub fn base64url(s: &str) -> Option<Vec<u8>> {
    base64(&s.replace('-', "+").replace('_', "/"))
}

/// The bit length of a big-endian number (a JWK's `n`).
pub fn bits_of(bytes: &[u8]) -> u32 {
    bytes.iter().position(|b| *b != 0).map_or(0, |i| (bytes.len() - i) as u32 * 8 - bytes[i].leading_zeros())
}

/// The bytes of the base64 body that follows a PEM header, up to `-----END`: tolerant of the
/// escaped newlines and quotes of a key written inside source code.
pub fn decode_body(after_header: &str) -> Option<Vec<u8>> {
    let body = after_header.split("-----END").next()?;
    let body = body.replace("\\r", "\n").replace("\\n", "\n");
    let mut b64 = String::new();
    for line in body.lines() {
        let l = line.trim();
        if l.is_empty() || l.contains(':') {
            continue; // blank lines and headers (`Proc-Type: ...`)
        }
        if l.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')) {
            b64.push_str(l);
        }
    }
    base64(&b64)
}

pub fn base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().take_while(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_integers() {
        assert_eq!(base64("aGVsbG8=").unwrap(), b"hello");
        // 0x00 0x80 -> 8 bits; 0x01 0x00 0x01 -> 17 bits
        assert_eq!(int_bits(&Tlv { tag: 2, value: &[0, 0x80] }), Some(8));
        assert_eq!(int_bits(&Tlv { tag: 2, value: &[1, 0, 1] }), Some(17));
    }

    #[test]
    fn oids() {
        // 1.2.840.113549.1.1.1 (rsaEncryption)
        let v = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        assert_eq!(oid(&Tlv { tag: 6, value: &v }).as_deref(), Some("1.2.840.113549.1.1.1"));
    }

    #[test]
    fn small_rsa_public_key() {
        // SEQUENCE { INTEGER (9-bit modulus 0x01ff), INTEGER 3 }
        let der = [0x30, 0x08, 0x02, 0x02, 0x01, 0xff, 0x02, 0x02, 0x00, 0x03];
        let info = key_info("RSA PUBLIC KEY", &der).unwrap();
        assert_eq!((info.algorithm.as_str(), info.weak), ("RSA 9-bit", vec!["9-bit key".to_string()]));
    }
}

/// What a PKCS#12 file (`.p12`, `.pfx`) shows without its password.
#[derive(Default)]
pub struct Pkcs12 {
    /// Certificates in bags that are not encrypted (DER).
    pub certs: Vec<Vec<u8>>,
    /// The algorithms that encrypt certificates and private keys, by name.
    pub encryption: Vec<String>,
    /// The digest of the MAC over the file.
    pub mac: Option<String>,
}

fn pbe_name(o: &str) -> String {
    match o {
        "1.2.840.113549.1.12.1.1" => "pbeWithSHAAnd128BitRC4",
        "1.2.840.113549.1.12.1.2" => "pbeWithSHAAnd40BitRC4",
        "1.2.840.113549.1.12.1.3" => "pbeWithSHAAnd3-KeyTripleDES-CBC",
        "1.2.840.113549.1.12.1.4" => "pbeWithSHAAnd2-KeyTripleDES-CBC",
        "1.2.840.113549.1.12.1.5" => "pbeWithSHAAnd128BitRC2-CBC",
        "1.2.840.113549.1.12.1.6" => "pbeWithSHAAnd40BitRC2-CBC",
        "1.2.840.113549.1.5.13" => "PBES2",
        "1.2.840.113549.1.5.3" => "pbeWithMD5AndDES-CBC",
        "1.2.840.113549.1.5.10" => "pbeWithSHA1AndDES-CBC",
        "1.3.14.3.2.26" => "SHA-1",
        "2.16.840.1.101.3.4.2.1" => "SHA-256",
        "2.16.840.1.101.3.4.2.2" => "SHA-384",
        "2.16.840.1.101.3.4.2.3" => "SHA-512",
        "1.2.840.113549.2.5" => "MD5",
        other => other,
    }
    .to_string()
}

/// The inside of an explicit `[0]` wrapper.
fn explicit(t: &Tlv) -> Option<Vec<u8>> {
    (t.tag == 0xa0).then(|| t.value.to_vec())
}

/// Read a PKCS#12 structure: the certificates that are in the clear, the algorithms that protect the
/// rest, and the MAC digest. None when the bytes are not one.
pub fn pkcs12(bytes: &[u8]) -> Option<Pkcs12> {
    let pfx = sequence(bytes)?;
    if pfx.first()?.tag != 0x02 {
        return None;
    }
    let auth = items(pfx.get(1)?.value);
    if oid(auth.first()?)? != "1.2.840.113549.1.7.1" {
        return None;
    }
    let inner = explicit(auth.get(1)?)?;
    let (octets, _) = read(&inner)?;
    let safe = sequence(octets.value)?;
    let mut out = Pkcs12::default();
    if let Some(mac) = pfx.get(2).map(|m| items(m.value)).and_then(|m| m.first().map(|d| items(d.value))).and_then(|d| d.first().map(|a| items(a.value)))
        && let Some(o) = mac.first().and_then(oid)
    {
        out.mac = Some(pbe_name(&o));
    }
    let mut bags: Vec<Vec<u8>> = vec![];
    for info in &safe {
        let parts = items(info.value);
        let (Some(kind), Some(content)) = (parts.first().and_then(oid), parts.get(1).and_then(explicit)) else { continue };
        match kind.as_str() {
            "1.2.840.113549.1.7.1" => {
                if let Some((o, _)) = read(&content) {
                    bags.push(o.value.to_vec());
                }
            }
            "1.2.840.113549.1.7.6" => {
                // encryptedData: version, EncryptedContentInfo { type, algorithm, [0] data }
                let enc = sequence(&content).and_then(|e| e.get(1).map(|c| items(c.value)));
                if let Some(alg) = enc.and_then(|c| c.get(1).map(|a| items(a.value))).and_then(|a| a.first().and_then(oid)) {
                    out.encryption.push(pbe_name(&alg));
                }
            }
            _ => {}
        }
    }
    for list in bags {
        for bag in sequence(&list).unwrap_or_default() {
            let parts = items(bag.value);
            let (Some(kind), Some(value)) = (parts.first().and_then(oid), parts.get(1).and_then(explicit)) else { continue };
            match kind.as_str() {
                // certBag { certId, [0] OCTET STRING }
                "1.2.840.113549.1.12.10.1.3" => {
                    let cert = sequence(&value).and_then(|c| c.get(1).and_then(explicit)).and_then(|o| read(&o).map(|(t, _)| t.value.to_vec()));
                    out.certs.extend(cert);
                }
                // pkcs8ShroudedKeyBag: EncryptedPrivateKeyInfo { algorithm, data }
                "1.2.840.113549.1.12.10.1.2" => {
                    if let Some(alg) = sequence(&value).and_then(|k| k.first().map(|a| items(a.value))).and_then(|a| a.first().and_then(oid)) {
                        out.encryption.push(pbe_name(&alg));
                    }
                }
                _ => {}
            }
        }
    }
    out.encryption.sort();
    out.encryption.dedup();
    Some(out)
}
