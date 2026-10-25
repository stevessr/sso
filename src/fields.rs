use anyhow::{bail, Context as _, Result};
use boa_engine::{Context, Source};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    pub from: String,
    pub to: String,
}

fn get_path<'a>(source: &'a Value, path: &str) -> Option<&'a Value> {
    if !path.split('.').all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')) {
        return None;
    }
    path.split('.').try_fold(source, |current, part| current.get(part))
}

pub fn transform(input: &Value, rules: &[FieldRule], script: &str) -> Result<Value> {
    if input.to_string().len() > 32 * 1024 || rules.len() > 64 || script.len() > 4096 { bail!("mapping size limit exceeded"); }
    let mut claims = Map::new();
    if rules.is_empty() {
        if let Some(map) = input.as_object() { claims = map.clone(); }
    } else {
        for rule in rules {
            if rule.to.len() > 64 || rule.to.is_empty() || !rule.to.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') { bail!("invalid output key"); }
            if matches!(rule.to.as_str(), "iss" | "aud" | "sub" | "exp" | "iat" | "nonce") { bail!("reserved OIDC claims cannot be mapped"); }
            if let Some(value) = get_path(input, &rule.from) { claims.insert(rule.to.clone(), value.clone()); }
        }
    }
    if script.trim().is_empty() { return Ok(Value::Object(claims)); }
    // Administrator-authored JS only. Boa provides no filesystem/network objects.
    // Runtime loop/recursion/stack guards prevent common accidental infinite loops.
    let literal = serde_json::to_string(&Value::Object(claims))?;
    let program = format!("'use strict'; const claims = {literal}; (function() {{ {script} }})(); JSON.stringify(claims)");
    let mut context = Context::default();
    context.runtime_limits_mut().set_loop_iteration_limit(20_000);
    context.runtime_limits_mut().set_recursion_limit(32);
    context.runtime_limits_mut().set_stack_size_limit(256);
    let result = context.eval(Source::from_bytes(&program))
        .map_err(|err| anyhow::anyhow!("JavaScript mapping error: {}", err))?;
    let output = result.to_string(&mut context)
        .map_err(|err| anyhow::anyhow!("mapping conversion error: {}", err))?
        .to_std_string_escaped();
    if output.len() > 32 * 1024 { bail!("mapping output too large"); }
    let mapped: Value = serde_json::from_str(&output).context("mapping output must be JSON")?;
    if !mapped.is_object() { bail!("mapping output must be an object"); }
    Ok(mapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test] fn maps_nested_field() {
        let out = transform(&json!({"data":{"handle":"abc"}}), &[FieldRule { from:"data.handle".into(), to:"preferred_username".into() }], "claims.name = claims.preferred_username.toUpperCase();").unwrap();
        assert_eq!(out["name"], "ABC");
    }
    #[test] fn rejects_claim_override() {
        assert!(transform(&json!({"a":1}), &[FieldRule { from:"a".into(), to:"sub".into() }], "").is_err());
    }
}
