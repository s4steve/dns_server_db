//! Parsing and validation of records submitted to the API. Pure functions, no database.

use std::str::FromStr;

use hickory_proto::rr::{Name, RData, RecordType};

/// `LUA` records hold a script that answers for one record type, as `"<TYPE> <script>"`.
/// Nodes store them under this private-use type code (RFC 6895 §3.1) and never serve them.
pub const LUA: RecordType = RecordType::Unknown(65402);

/// Record types a LUA script may answer for.
pub const LUA_TARGETS: [RecordType; 5] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::TXT,
    RecordType::MX,
    RecordType::CAA,
];

pub const SUPPORTED: [RecordType; 8] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::CNAME,
    RecordType::MX,
    RecordType::TXT,
    RecordType::NS,
    RecordType::CAA,
    LUA,
];

/// The type's name as stored and served by the API.
pub fn type_name(t: RecordType) -> String {
    if t == LUA {
        "LUA".into()
    } else {
        t.to_string()
    }
}

/// RFC 2181 §8: TTLs are unsigned 31-bit.
const MAX_TTL: i64 = 2_147_483_647;

/// Parses a zone name into lowercase FQDN form.
pub fn parse_zone(input: &str) -> Result<Name, String> {
    let name = Name::from_str(input).map_err(|e| format!("invalid zone name {input:?}: {e}"))?;
    let mut name = name.to_lowercase();
    name.set_fqdn(true);
    if name.is_root() {
        return Err("hosting the root zone is not supported".into());
    }
    Ok(name)
}

/// Parses an owner name: `@` is the apex, relative names are relative to the zone, and a
/// name ending in `.` is absolute. Returns lowercase FQDN form.
pub fn parse_name(input: &str, zone: &Name) -> Result<Name, String> {
    let name = if input == "@" {
        zone.clone()
    } else {
        Name::parse(input, Some(zone)).map_err(|e| format!("invalid name {input:?}: {e}"))?
    }
    .to_lowercase();
    if !zone.zone_of(&name) {
        return Err(format!("{name} is not in zone {zone}"));
    }
    if name.iter().skip(1).any(|label| label == b"*") {
        return Err(format!("{name}: '*' is only allowed as the leftmost label"));
    }
    Ok(name)
}

pub fn parse_type(input: &str) -> Result<RecordType, String> {
    if input.eq_ignore_ascii_case("LUA") {
        return Ok(LUA);
    }
    let t = RecordType::from_str(&input.to_ascii_uppercase())
        .map_err(|_| format!("unknown record type {input:?}"))?;
    if t == RecordType::SOA {
        return Err(
            "SOA is managed through the zone (PATCH /zones/{zone}), not as a record".into(),
        );
    }
    if !SUPPORTED.contains(&t) {
        return Err(format!("record type {t} is not supported"));
    }
    Ok(t)
}

pub fn parse_ttl(ttl: i64) -> Result<u32, String> {
    if !(0..=MAX_TTL).contains(&ttl) {
        return Err(format!("ttl {ttl} must be between 0 and {MAX_TTL}"));
    }
    Ok(ttl as u32)
}

/// Parses record data and returns its canonical text form, which is what gets stored and
/// what nodes parse back.
pub fn parse_data(rtype: RecordType, input: &str) -> Result<String, String> {
    if rtype == LUA {
        return parse_lua(input);
    }
    let rdata = RData::try_from_str(rtype, input)
        .map_err(|e| format!("invalid {rtype} data {input:?}: {e}"))?;
    let target = match &rdata {
        RData::CNAME(n) => Some(&n.0),
        RData::NS(n) => Some(&n.0),
        RData::MX(mx) => Some(&mx.exchange),
        _ => None,
    };
    if let Some(target) = target {
        if !target.is_fqdn() {
            return Err(format!(
                "{rtype} target {target} must be fully qualified (end in '.')"
            ));
        }
    }
    let canonical = match &rdata {
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|s| quote(s))
            .collect::<Vec<_>>()
            .join(" "),
        // Names are case-insensitive; store them lowercase so duplicates are caught.
        RData::CNAME(_) | RData::NS(_) | RData::MX(_) => rdata.to_string().to_lowercase(),
        _ => rdata.to_string(),
    };
    // Guard against a lossy text form: the canonical string must parse back to the same data.
    if RData::try_from_str(rtype, &canonical).ok() != Some(rdata) {
        return Err(format!("{rtype} data {input:?} has no stable text form"));
    }
    Ok(canonical)
}

/// `"<TYPE> <script>"`: the type must be one scripts can answer for, and the script must
/// compile under LuaJIT (the nodes' runtime). Canonical form keeps the script verbatim.
fn parse_lua(input: &str) -> Result<String, String> {
    let (target, script) = input
        .trim()
        .split_once(char::is_whitespace)
        .ok_or("LUA data must be \"<TYPE> <script>\", e.g. \"A return '192.0.2.1'\"")?;
    let target = RecordType::from_str(&target.to_ascii_uppercase())
        .ok()
        .filter(|t| LUA_TARGETS.contains(t))
        .ok_or_else(|| {
            let allowed: Vec<String> = LUA_TARGETS.iter().map(|t| t.to_string()).collect();
            format!(
                "LUA scripts can answer {}, not {target:?}",
                allowed.join(", ")
            )
        })?;
    let script = script.trim();
    mlua::Lua::new_with(mlua::StdLib::NONE, mlua::LuaOptions::default())
        .and_then(|lua| lua.load(script).into_function().map(|_| ()))
        .map_err(|e| format!("LUA script does not compile: {e}"))?;
    Ok(format!("{target} {script}"))
}

/// One RFC 1035 <character-string>, quoted, with `"`, `\` and non-printables escaped.
fn quote(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in bytes {
        match b {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(b as char);
            }
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\{b:03}")),
        }
    }
    out.push('"');
    out
}

/// Rules over a name's complete record set after a change: `(type, ttl, data)` per record.
pub fn check_name(zone: &Name, name: &Name, records: &[(RecordType, u32, &str)]) -> Vec<String> {
    let mut errors = vec![];
    let of_type = |t: RecordType| records.iter().filter(move |(rt, _, _)| *rt == t);
    let cnames = of_type(RecordType::CNAME).count();
    if cnames > 1 {
        errors.push(format!("{name}: only one CNAME is allowed"));
    }
    if cnames > 0 && records.len() > cnames {
        errors.push(format!(
            "{name}: a CNAME cannot coexist with other records (RFC 1034 §3.6.2)"
        ));
    }
    if cnames > 0 && name == zone {
        errors.push(format!(
            "{name}: CNAME is not allowed at the zone apex (RFC 1912 §2.4)"
        ));
    }
    if name == zone && of_type(RecordType::NS).count() == 0 {
        errors.push(format!(
            "{name}: the zone apex must keep at least one NS record"
        ));
    }
    for t in SUPPORTED {
        let mut ttls = of_type(t).map(|(_, ttl, _)| *ttl);
        if let Some(first) = ttls.next() {
            if ttls.any(|ttl| ttl != first) {
                errors.push(format!(
                    "{name} {}: all records in an RRset must share one TTL (RFC 2181 §5.2)",
                    type_name(t)
                ));
            }
        }
    }
    for target in LUA_TARGETS {
        let target = target.to_string();
        let scripts = of_type(LUA)
            .filter(|(_, _, data)| data.split_whitespace().next() == Some(target.as_str()))
            .count();
        if scripts > 1 {
            errors.push(format!("{name}: only one LUA script may answer {target}"));
        }
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone() -> Name {
        parse_zone("Example.COM").unwrap()
    }

    #[test]
    fn names() {
        let z = zone();
        assert_eq!(z.to_string(), "example.com.");
        assert_eq!(parse_name("@", &z).unwrap(), z);
        assert_eq!(
            parse_name("WWW", &z).unwrap().to_string(),
            "www.example.com."
        );
        assert_eq!(
            parse_name("a.example.com.", &z).unwrap().to_string(),
            "a.example.com."
        );
        assert_eq!(
            parse_name("*.wild", &z).unwrap().to_string(),
            "*.wild.example.com."
        );
        assert!(parse_name("www.example.org.", &z).is_err());
        assert!(parse_name("a.*.example.com.", &z).is_err());
    }

    #[test]
    fn data_is_canonical_and_round_trips() {
        assert_eq!(
            parse_data(RecordType::A, " 192.0.2.1 ").unwrap(),
            "192.0.2.1"
        );
        assert_eq!(
            parse_data(RecordType::AAAA, "2001:DB8::1").unwrap(),
            "2001:db8::1"
        );
        assert_eq!(
            parse_data(RecordType::CNAME, "WWW.Example.com.").unwrap(),
            "www.example.com."
        );
        assert_eq!(
            parse_data(RecordType::MX, "10 mail.example.com.").unwrap(),
            "10 mail.example.com."
        );
        assert_eq!(
            parse_data(RecordType::TXT, r#""hello world" two"#).unwrap(),
            r#""hello world" "two""#
        );
        assert_eq!(
            parse_data(RecordType::TXT, r#""say \"hi\"""#).unwrap(),
            r#""say \"hi\"""#
        );
        assert_eq!(
            parse_data(RecordType::CAA, r#"0 issue "letsencrypt.org""#).unwrap(),
            r#"0 issue "letsencrypt.org""#
        );
        assert!(parse_data(RecordType::A, "not-an-ip").is_err());
        assert!(parse_data(RecordType::CNAME, "relative").is_err());
        assert!(parse_type("SOA").is_err());
        assert!(parse_type("PTR").is_err());
        assert!(parse_ttl(-1).is_err());
    }

    #[test]
    fn name_rules() {
        let z = zone();
        let www = parse_name("www", &z).unwrap();
        use RecordType::*;
        let c = |name: &Name, recs: &[(RecordType, u32)]| -> Vec<String> {
            let recs: Vec<(RecordType, u32, &str)> =
                recs.iter().map(|(t, ttl)| (*t, *ttl, "")).collect();
            check_name(&z, name, &recs)
        };
        assert!(c(&www, &[(A, 300), (AAAA, 300)]).is_empty());
        assert_eq!(c(&www, &[(CNAME, 300), (A, 300)]).len(), 1);
        assert_eq!(c(&www, &[(CNAME, 300), (CNAME, 300)]).len(), 1);
        assert_eq!(c(&www, &[(A, 300), (A, 60)]).len(), 1);
        assert!(c(&z, &[(NS, 300), (A, 300)]).is_empty());
        assert_eq!(c(&z, &[(A, 300)]).len(), 1); // apex lost its NS
        assert_eq!(c(&z, &[(NS, 300), (CNAME, 300)]).len(), 2);
        // LUA: one script per answered type; it counts as a record for CNAME exclusivity.
        let lua = |d| (LUA, 60, d);
        assert!(
            check_name(
                &z,
                &www,
                &[lua("A return 'x'"), lua("AAAA return 'y'"), (A, 300, "")]
            )
            .is_empty()
        );
        assert_eq!(
            check_name(&z, &www, &[lua("A return 'x'"), lua("A return 'y'")]).len(),
            1
        );
        assert_eq!(
            check_name(&z, &www, &[lua("A return 'x'"), (CNAME, 300, "")]).len(),
            1
        );
    }

    #[test]
    fn lua_data() {
        assert_eq!(parse_type("lua").unwrap(), LUA);
        assert_eq!(type_name(LUA), "LUA");
        assert_eq!(
            parse_data(LUA, "  a   return '192.0.2.1'  ").unwrap(),
            "A return '192.0.2.1'"
        );
        assert!(
            parse_data(LUA, "A return (")
                .unwrap_err()
                .contains("does not compile")
        );
        assert!(
            parse_data(LUA, "NS return 'x.'")
                .unwrap_err()
                .contains("can answer")
        );
        assert!(parse_data(LUA, "A").is_err());
    }
}
