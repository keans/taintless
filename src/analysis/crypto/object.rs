//! Symbol and import tables of compiled programs (ELF, Mach-O, PE), the legacy and v0 mangling of
//! Rust symbols, and a DEFLATE decoder for the entries of a `.jar`. Just enough to list names: no
//! validation, and anything unexpected ends the reading with what was found.

/// What a program imports or defines, and the libraries it links.
#[derive(Default)]
pub struct Symbols {
    pub names: Vec<String>,
    pub libraries: Vec<String>,
    /// PE imports by number: `(dll, ordinal)`.
    pub ordinals: Vec<(String, usize)>,
}

struct Bytes<'a> {
    data: &'a [u8],
    big: bool,
}

impl Bytes<'_> {
    fn get16(&self, at: usize) -> Option<usize> {
        let b: [u8; 2] = self.data.get(at..at + 2)?.try_into().ok()?;
        Some(usize::from(if self.big { u16::from_be_bytes(b) } else { u16::from_le_bytes(b) }))
    }
    fn get32(&self, at: usize) -> Option<usize> {
        let b: [u8; 4] = self.data.get(at..at + 4)?.try_into().ok()?;
        Some((if self.big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }) as usize)
    }
    fn get64(&self, at: usize) -> Option<usize> {
        let b: [u8; 8] = self.data.get(at..at + 8)?.try_into().ok()?;
        usize::try_from(if self.big { u64::from_be_bytes(b) } else { u64::from_le_bytes(b) }).ok()
    }
    /// The NUL-terminated string at `at`.
    fn get_cstr(&self, at: usize) -> Option<String> {
        let rest = self.data.get(at..)?;
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len()).min(300);
        let s = std::str::from_utf8(&rest[..end]).ok()?;
        (!s.is_empty()).then(|| s.to_string())
    }
}

const MAX_NAMES: usize = 100_000;

/// The symbols of an ELF, Mach-O or PE file, or None when it is none of them or has no table.
pub fn symbols(data: &[u8]) -> Option<Symbols> {
    let s = if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        elf_symbols(data)
    } else if data.starts_with(b"MZ") {
        pe_symbols(data)
    } else {
        macho_symbols(data)
    }?;
    (!s.names.is_empty() || !s.libraries.is_empty()).then_some(s)
}

fn elf_symbols(data: &[u8]) -> Option<Symbols> {
    let wide = *data.get(4)? == 2;
    let b = Bytes { data, big: *data.get(5)? == 2 };
    let (shoff, shentsize, shnum) = if wide { (b.get64(0x28)?, b.get16(0x3a)?, b.get16(0x3c)?) } else { (b.get32(0x20)?, b.get16(0x2e)?, b.get16(0x30)?) };
    if shoff == 0 || shentsize < 40 || shnum == 0 || shnum > 4096 {
        return None;
    }
    // (type, offset, size, link)
    let section = |i: usize| -> Option<(usize, usize, usize, usize)> {
        let at = shoff + i * shentsize;
        if wide { Some((b.get32(at + 4)?, b.get64(at + 0x18)?, b.get64(at + 0x20)?, b.get32(at + 0x28)?)) } else { Some((b.get32(at + 4)?, b.get32(at + 0x10)?, b.get32(at + 0x14)?, b.get32(at + 0x18)?)) }
    };
    let mut out = Symbols::default();
    for i in 0..shnum {
        let Some((kind, offset, size, link)) = section(i) else { continue };
        match kind {
            // SHT_SYMTAB, SHT_DYNSYM
            2 | 11 => {
                let Some((_, strings, _, _)) = section(link) else { continue };
                let entry = if wide { 24 } else { 16 };
                for k in 0..(size / entry).min(MAX_NAMES) {
                    let Some(name) = b.get32(offset + k * entry).and_then(|n| b.get_cstr(strings + n)) else { continue };
                    out.names.push(name);
                }
            }
            // SHT_DYNAMIC: DT_NEEDED entries name the libraries
            6 => {
                let Some((_, strings, _, _)) = section(link) else { continue };
                let entry = if wide { 16 } else { 8 };
                for k in 0..(size / entry).min(512) {
                    let (tag, val) = if wide { (b.get64(offset + k * entry), b.get64(offset + k * entry + 8)) } else { (b.get32(offset + k * entry), b.get32(offset + k * entry + 4)) };
                    if tag == Some(1) && let Some(name) = val.and_then(|v| b.get_cstr(strings + v)) {
                        out.libraries.push(name);
                    }
                }
            }
            _ => {}
        }
    }
    Some(out)
}

fn macho_symbols(data: &[u8]) -> Option<Symbols> {
    let magic: [u8; 4] = data.get(..4)?.try_into().ok()?;
    // a fat binary: the first architecture
    if magic == [0xca, 0xfe, 0xba, 0xbe] {
        let b = Bytes { data, big: true };
        let (n, offset, size) = (b.get32(4)?, b.get32(16)?, b.get32(20)?);
        return (n > 0 && n < 20).then(|| data.get(offset..offset.checked_add(size)?)).flatten().and_then(macho_symbols);
    }
    let (wide, big) = match magic {
        [0xcf, 0xfa, 0xed, 0xfe] => (true, false),
        [0xce, 0xfa, 0xed, 0xfe] => (false, false),
        [0xfe, 0xed, 0xfa, 0xcf] => (true, true),
        [0xfe, 0xed, 0xfa, 0xce] => (false, true),
        _ => return None,
    };
    let b = Bytes { data, big };
    let ncmds = b.get32(16)?;
    let mut at = if wide { 32 } else { 28 };
    let mut out = Symbols::default();
    for _ in 0..ncmds.min(1024) {
        let (cmd, size) = (b.get32(at)?, b.get32(at + 4)?);
        match cmd {
            // LC_SYMTAB
            2 => {
                let (symoff, nsyms, stroff) = (b.get32(at + 8)?, b.get32(at + 12)?, b.get32(at + 16)?);
                let entry = if wide { 16 } else { 12 };
                for k in 0..nsyms.min(MAX_NAMES) {
                    let Some(name) = b.get32(symoff + k * entry).and_then(|n| b.get_cstr(stroff + n)) else { continue };
                    out.names.push(name);
                }
            }
            // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB
            0xc | 0x8000_0018 | 0x8000_001f => {
                if let Some(name) = b.get32(at + 8).and_then(|o| b.get_cstr(at + o)) {
                    out.libraries.push(name);
                }
            }
            _ => {}
        }
        if size < 8 {
            break;
        }
        at += size;
    }
    Some(out)
}

fn pe_symbols(data: &[u8]) -> Option<Symbols> {
    let b = Bytes { data, big: false };
    let pe = b.get32(0x3c)?;
    if data.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let (nsections, optional_size) = (b.get16(pe + 6)?, b.get16(pe + 20)?);
    let optional = pe + 24;
    let wide = b.get16(optional)? == 0x20b;
    // the import directory is the second data directory
    let imports = b.get32(optional + if wide { 120 } else { 104 })?;
    let sections = optional + optional_size;
    // RVA -> file offset
    let offset = |rva: usize| -> Option<usize> {
        (0..nsections.min(96)).find_map(|i| {
            let at = sections + i * 40;
            let (size, va, raw) = (b.get32(at + 8)?, b.get32(at + 12)?, b.get32(at + 20)?);
            (rva >= va && rva < va + size.max(1)).then(|| raw + (rva - va))
        })
    };
    let mut out = Symbols::default();
    // the DLL a descriptor names, and the names and ordinals its thunk table lists
    let dll = |out: &mut Symbols, name: usize| -> String {
        let d = offset(name).and_then(|o| b.get_cstr(o)).unwrap_or_default();
        if !d.is_empty() {
            out.libraries.push(d.clone());
        }
        d
    };
    let walk = |out: &mut Symbols, dll: &str, start: usize| -> Option<()> {
        let mut entry = start;
        for _ in 0..4096 {
            let word = if wide { b.get64(entry)? } else { b.get32(entry)? };
            if word == 0 {
                break;
            }
            if word >> if wide { 63 } else { 31 } != 0 {
                out.ordinals.push((dll.to_string(), word & 0xffff));
            } else if let Some(n) = offset(word & 0x7fff_ffff).and_then(|o| b.get_cstr(o + 2)) {
                out.names.push(n);
            }
            entry += if wide { 8 } else { 4 };
        }
        Some(())
    };
    if let Some(mut at) = (imports != 0).then(|| offset(imports)).flatten() {
        for _ in 0..512 {
            let (thunk, name, first) = (b.get32(at)?, b.get32(at + 12)?, b.get32(at + 16)?);
            if name == 0 {
                break;
            }
            let d = dll(&mut out, name);
            walk(&mut out, &d, offset(if thunk != 0 { thunk } else { first })?)?;
            at += 20;
        }
    }
    // delay-loaded imports: the delay import directory is the 14th data directory; without the RVA
    // flag its fields are addresses, which this does not translate
    if let Some(delay) = b.get32(optional + if wide { 112 } else { 96 } + 13 * 8).filter(|d| *d != 0).and_then(offset) {
        for k in 0..256 {
            let at = delay + k * 32;
            let (attrs, name, names) = (b.get32(at)?, b.get32(at + 4)?, b.get32(at + 16)?);
            if name == 0 || attrs & 1 == 0 {
                break;
            }
            let d = dll(&mut out, name);
            if let Some(start) = offset(names) {
                walk(&mut out, &d, start)?;
            }
        }
    }
    Some(out)
}

/// The exported names of a PE file by ordinal, to name what another file imports by number.
pub fn pe_exports(data: &[u8]) -> Option<std::collections::BTreeMap<usize, String>> {
    let b = Bytes { data, big: false };
    let pe = b.get32(0x3c)?;
    if data.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let (nsections, optional_size) = (b.get16(pe + 6)?, b.get16(pe + 20)?);
    let optional = pe + 24;
    let wide = b.get16(optional)? == 0x20b;
    let dir = b.get32(optional + if wide { 112 } else { 96 })?;
    let sections = optional + optional_size;
    let offset = |rva: usize| -> Option<usize> {
        (0..nsections.min(96)).find_map(|i| {
            let at = sections + i * 40;
            let (size, va, raw) = (b.get32(at + 8)?, b.get32(at + 12)?, b.get32(at + 20)?);
            (rva >= va && rva < va + size.max(1)).then(|| raw + (rva - va))
        })
    };
    let table = offset(dir).filter(|_| dir != 0)?;
    let (base, count, names, ordinals) = (b.get32(table + 16)?, b.get32(table + 24)?, offset(b.get32(table + 32)?)?, offset(b.get32(table + 36)?)?);
    let mut out = std::collections::BTreeMap::new();
    for k in 0..count.min(MAX_NAMES) {
        let (Some(name), Some(index)) = (b.get32(names + k * 4).and_then(offset).and_then(|o| b.get_cstr(o)), b.get16(ordinals + k * 2)) else { continue };
        out.insert(base + index, name);
    }
    Some(out)
}

/// What a Rust symbol names: the crates it mentions (the one the function is in, and those of the
/// type and trait of an `impl`) and the identifiers of its path in order.
pub struct RustSymbol {
    pub crates: Vec<String>,
    pub names: Vec<String>,
}

/// A Rust symbol in the legacy (`_ZN3foo3bar17h0123456789abcdefE`, `_ZN` + `$LT$..$u20$as$u20$..$GT$`
/// for an impl) or v0 (`_RNvCs..._3foo3bar`, `X` for an impl, `I..E` for generic arguments) mangling.
pub fn demangle_rust(sym: &str) -> Option<RustSymbol> {
    let mut out = RustSymbol { crates: vec![], names: vec![] };
    if let Some(rest) = sym.strip_prefix("_ZN").or_else(|| sym.strip_prefix("__ZN")) {
        let mut parts = vec![];
        let mut s = rest;
        while let Some(end) = s.find(|c: char| !c.is_ascii_digit()).filter(|e| *e > 0) {
            let n: usize = s[..end].parse().ok()?;
            let ident = s.get(end..end + n)?;
            parts.push(ident.to_string());
            s = &s[end + n..];
        }
        if !s.starts_with('E') || parts.is_empty() {
            return None;
        }
        // the hash closes the path
        if parts.last().is_some_and(|h| h.len() == 17 && h.starts_with('h') && h[1..].chars().all(|c| c.is_ascii_hexdigit())) {
            parts.pop();
        }
        for (i, part) in parts.iter().enumerate() {
            let text = part.replace("$LT$", "<").replace("$GT$", ">").replace("$u20$", " ").replace("$C$", ",").replace("..", "::");
            // an impl segment starts with an underscore (`_$LT$`) so that it is a valid identifier
            let text = text.strip_prefix('_').filter(|t| t.starts_with('<')).map_or(text.clone(), str::to_string);
            if let Some(inner) = text.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
                // `<md5::Md5 as digest::Digest>`: the type and the trait
                for side in inner.split(" as ") {
                    let path: Vec<&str> = side.split("::").map(|p| p.split('<').next().unwrap_or(p).trim_start_matches('&')).collect();
                    if path.len() > 1 {
                        out.crates.push(path[0].to_string());
                        out.names.extend(path[1..].iter().map(|p| p.to_string()));
                    }
                }
            } else if text.contains("::") {
                let path: Vec<&str> = text.split("::").collect();
                out.crates.push(path[0].to_string());
                out.names.extend(path[1..].iter().map(|p| p.to_string()));
            } else {
                if i == 0 {
                    out.crates.push(text.clone());
                }
                out.names.push(text);
            }
        }
        return (!out.crates.is_empty()).then_some(out);
    }
    let rest = sym.strip_prefix("_R").or_else(|| sym.strip_prefix("__R"))?;
    // identifiers (`<length>[_]<name>`) in order; the structure letters, the crate disambiguator
    // (`Cs<base62>_`), back references (`B<base62>_`) and base62 numbers (`3_`) are skipped; the
    // identifier after a `C` names a crate
    let chars: Vec<char> = rest.chars().collect();
    let (mut i, mut crate_next) = (0, false);
    while i < chars.len() && out.names.len() < 24 {
        let c = chars[i];
        if (c == 'B' || (c == 's' && i > 0 && chars[i - 1] == 'C')) && let Some(end) = chars[i..].iter().position(|x| *x == '_') {
            i += end + 1;
        } else if c.is_ascii_digit() {
            let digits: String = chars[i..].iter().take_while(|x| x.is_ascii_digit()).collect();
            let n: usize = digits.parse().ok()?;
            i += digits.len();
            if chars.get(i) == Some(&'_') {
                // `<length>_<name>` is for a name that starts with a digit or `_`; otherwise `3_` is a number
                if !chars.get(i + 1).is_some_and(|x| x.is_ascii_digit() || *x == '_') {
                    i += 1;
                    continue;
                }
                i += 1;
            }
            let ident: String = chars.get(i..i + n)?.iter().collect();
            if !ident.chars().all(|x| x.is_ascii_alphanumeric() || x == '_') {
                break;
            }
            if crate_next {
                out.crates.push(ident.clone());
            }
            crate_next = false;
            out.names.push(ident);
            i += n;
        } else {
            crate_next = c == 'C';
            i += 1;
        }
    }
    (!out.crates.is_empty()).then_some(out)
}

/// Decompress raw DEFLATE data (RFC 1951), at most `limit` bytes of output.
pub fn inflate(input: &[u8], limit: usize) -> Option<Vec<u8>> {
    struct Bits<'a> {
        data: &'a [u8],
        pos: usize,
        bit: u32,
        count: u32,
    }
    impl Bits<'_> {
        fn bits_need(&mut self, n: u32) -> Option<()> {
            while self.count < n {
                self.bit |= u32::from(*self.data.get(self.pos)?) << self.count;
                self.pos += 1;
                self.count += 8;
            }
            Some(())
        }
        fn bits_take(&mut self, n: u32) -> Option<u32> {
            if n == 0 {
                return Some(0);
            }
            self.bits_need(n)?;
            let v = self.bit & ((1u32 << n) - 1);
            self.bit >>= n;
            self.count -= n;
            Some(v)
        }
    }
    /// A canonical Huffman code: how many codes of each length, and the symbols in code order.
    struct Huffman {
        counts: [u16; 16],
        symbols: Vec<u16>,
    }
    impl Huffman {
        fn huff_new(lengths: &[u8]) -> Self {
            let mut counts = [0u16; 16];
            for l in lengths {
                counts[usize::from(*l)] += 1;
            }
            counts[0] = 0;
            let mut offsets = [0u16; 16];
            for i in 1..16 {
                offsets[i] = offsets[i - 1] + counts[i - 1];
            }
            let mut symbols = vec![0u16; lengths.len()];
            for (sym, l) in lengths.iter().enumerate() {
                if *l != 0 {
                    symbols[usize::from(offsets[usize::from(*l)])] = sym as u16;
                    offsets[usize::from(*l)] += 1;
                }
            }
            Self { counts, symbols }
        }
        fn huff_decode(&self, bits: &mut Bits) -> Option<u16> {
            let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
            for len in 1..16 {
                code |= bits.bits_take(1)? as i32;
                let count = i32::from(self.counts[len]);
                if code - count < first {
                    return self.symbols.get((index + (code - first)) as usize).copied();
                }
                index += count;
                first = (first + count) << 1;
                code <<= 1;
            }
            None
        }
    }
    const LEN_BASE: [u16; 29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
    const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    const DIST_BASE: [u16; 30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
    const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
    let mut bits = Bits { data: input, pos: 0, bit: 0, count: 0 };
    let mut out: Vec<u8> = vec![];
    loop {
        let last = bits.bits_take(1)? == 1;
        match bits.bits_take(2)? {
            0 => {
                bits.bit = 0;
                bits.count = 0;
                let len = usize::from(u16::from_le_bytes(input.get(bits.pos..bits.pos + 2)?.try_into().ok()?));
                let block = input.get(bits.pos + 4..bits.pos + 4 + len)?;
                out.extend_from_slice(block);
                bits.pos += 4 + len;
            }
            kind @ (1 | 2) => {
                let (lit, dist) = if kind == 1 {
                    let mut l = [8u8; 288];
                    l[144..256].fill(9);
                    l[256..280].fill(7);
                    (Huffman::huff_new(&l), Huffman::huff_new(&[5u8; 30]))
                } else {
                    let (hlit, hdist, hclen) = (bits.bits_take(5)? as usize + 257, bits.bits_take(5)? as usize + 1, bits.bits_take(4)? as usize + 4);
                    const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
                    let mut cl = [0u8; 19];
                    for &o in ORDER.iter().take(hclen) {
                        cl[o] = bits.bits_take(3)? as u8;
                    }
                    let code_lengths = Huffman::huff_new(&cl);
                    let mut lengths = vec![0u8; hlit + hdist];
                    let mut i = 0;
                    while i < hlit + hdist {
                        let sym = code_lengths.huff_decode(&mut bits)?;
                        let (value, repeat) = match sym {
                            0..=15 => (sym as u8, 1),
                            16 => (*lengths.get(i.checked_sub(1)?)?, 3 + bits.bits_take(2)? as usize),
                            17 => (0, 3 + bits.bits_take(3)? as usize),
                            _ => (0, 11 + bits.bits_take(7)? as usize),
                        };
                        for _ in 0..repeat {
                            *lengths.get_mut(i)? = value;
                            i += 1;
                        }
                    }
                    (Huffman::huff_new(&lengths[..hlit]), Huffman::huff_new(&lengths[hlit..]))
                };
                loop {
                    let sym = lit.huff_decode(&mut bits)?;
                    match sym {
                        0..=255 => out.push(sym as u8),
                        256 => break,
                        _ => {
                            let i = usize::from(sym - 257);
                            let len = usize::from(*LEN_BASE.get(i)?) + bits.bits_take(u32::from(*LEN_EXTRA.get(i)?))? as usize;
                            let d = usize::from(dist.huff_decode(&mut bits)?);
                            let distance = usize::from(*DIST_BASE.get(d)?) + bits.bits_take(u32::from(*DIST_EXTRA.get(d)?))? as usize;
                            if distance > out.len() {
                                return None;
                            }
                            for _ in 0..len {
                                out.push(out[out.len() - distance]);
                            }
                        }
                    }
                    if out.len() > limit {
                        return None;
                    }
                }
            }
            _ => return None,
        }
        if out.len() > limit {
            return None;
        }
        if last {
            return Some(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangles_both_rust_schemes() {
        let d = |s: &str| demangle_rust(s).map(|r| (r.crates, r.names));
        let v = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(d("_ZN3md57compute17h0123456789abcdefE").unwrap(), (v(&["md5"]), v(&["md5", "compute"])));
        assert_eq!(d("_RNvCs1234_3md57compute").unwrap(), (v(&["md5"]), v(&["md5", "compute"])));
        assert_eq!(d("__RNvMCs9J9hliPSYAT_3md5NtB2_3Md53new").unwrap(), (v(&["md5"]), v(&["md5", "Md5", "new"])));
        // a trait impl, legacy and v0: the type's and the trait's crates
        assert_eq!(d("_ZN43_$LT$md5..Md5$u20$as$u20$digest..Digest$GT$6update17h0123456789abcdefE").unwrap(), (v(&["md5", "digest"]), v(&["Md5", "Digest", "update"])));
        assert_eq!(d("__RNvXCs9J9hliPSYAT_3md5NtB2_3Md5NtB2_6Digest6update").unwrap(), (v(&["md5"]), v(&["md5", "Md5", "Digest", "update"])));
        // generic arguments, with a base62 number among them
        assert_eq!(d("__RINvCs9J9hliPSYAT_3md54hashRAhj3_EB2_").unwrap(), (v(&["md5"]), v(&["md5", "hash"])));
        assert!(demangle_rust("EVP_md5").is_none());
    }

    #[test]
    fn reads_the_delay_import_table_of_a_pe_file() {
        let bytes = std::fs::read("tests/crypto_objects_bin/delay.exe").unwrap();
        let s = symbols(&bytes).unwrap();
        assert_eq!(s.libraries, ["bcrypt.dll"]);
        assert!(s.names.contains(&"BCryptGenRandom".to_string()));
    }

    #[test]
    fn inflates_stored_and_fixed_blocks() {
        // stored: BFINAL=1, BTYPE=00, LEN=3, NLEN=!3, "abc"
        assert_eq!(inflate(&[1, 3, 0, 0xfc, 0xff, b'a', b'b', b'c'], 100).unwrap(), b"abc");
        // fixed Huffman for "a"
        assert_eq!(inflate(&[0x4b, 0x04, 0x00], 100).unwrap(), b"a");
    }
}
