use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::ptypes::Attribute;
use crate::ptypes::FPos;

/// Convert the list of (key, value) pairs into a list of attributes.
///
/// Note this only supports KEY:VALUE attributes, not TAG attributes.
///
/// TODO: This should be done in config parsing.
pub fn vec_to_attributes(v: &[(String, String)]) -> Result<Vec<Attribute>, CompilationError> {
    let mut attrs = Vec::new();
    for (k, v) in v {
        attrs.push(Attribute::attr(k, v));
    }
    Ok(attrs)
}

// Given a list of attributes that apply, return just the set of unique
// attributes and the ones with values should take precedence over ones without.
pub fn squash_attributes(
    attrs: &[Attribute],
    tok: &FPos,
) -> Result<HashMap<String, Attribute>, CompilationError> {
    let mut attr_map: HashMap<String, Attribute> = HashMap::new();
    for a in attrs {
        if attr_map.contains_key(&a.name) {
            // Map already has this attribute in it. If the map one has a value
            // and this one doesn't, keep the map one. If they both have values and they are different
            // that is an error.

            let map_attr = attr_map.get(&a.name).unwrap();
            if map_attr.value.is_none() && a.value.is_some() {
                attr_map.insert(a.name.clone(), a.clone()); // overwrite old non-valued attribute
            } else if map_attr.value.is_some() && a.value.is_none() {
                // do nothing
            } else if map_attr.value.is_some() && a.value.is_some() {
                if map_attr.value != a.value {
                    return Err(CompilationError::AttributeValueConflict(
                        a.name.clone(),
                        tok.line,
                        tok.col,
                    ));
                }
            }
        } else {
            attr_map.insert(a.name.clone(), a.clone());
        }
    }
    Ok(attr_map)
}
