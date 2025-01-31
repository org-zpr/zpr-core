use std::path::Path;
use thiserror::Error;
use toml::{Table, Value};

#[derive(Debug, Error)]
pub enum PCErr {
    #[error("config read error: {0}")]
    ConfigReadError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParseError(#[from] toml::de::Error),

    #[error("section not found: {0}")]
    SectionNotFound(String),

    #[error("not a table/section: {0}")]
    SectionError(String),

    #[error("problem reading value: {0}")]
    KeyError(String),

    #[error("ambiguous key: {0}")]
    AmbiguousKeyError(String),

    #[error("required key missing: {0}")]
    MissingKeyError(String),
}

pub struct ConfigRdr {
    tables: Table,
}

impl ConfigRdr {
    pub fn new(config_file: &Path) -> Result<ConfigRdr, PCErr> {
        let toml_str =
            std::fs::read_to_string(config_file).or(Err(PCErr::ConfigReadError(format!(
                "failed to read {}: {}",
                config_file.display(),
                std::io::Error::last_os_error()
            ))))?;
        let tables = toml_str.parse::<Table>()?;
        Ok(ConfigRdr { tables })
    }

    pub fn get_config_str_value_for_section_and_key(
        &self,
        section: &str,
        key: &str,
    ) -> Result<Option<String>, PCErr> {
        if !self.tables.contains_key(section) {
            return Err(PCErr::SectionNotFound(section.to_string()));
        }
        let sec_table = self
            .tables
            .get(section)
            .unwrap()
            .as_table()
            .ok_or(PCErr::SectionError(section.to_string()))?;
        if !sec_table.contains_key(key) {
            return Ok(None);
        }
        let value = self
            .value_as_string(sec_table.get(key).unwrap())
            .or(Err(PCErr::KeyError(format!("{}.{}", section, key))))?;
        Ok(Some(value.to_string()))
    }

    pub fn get_config_str_value_for_key(&self, key: &str) -> Result<Option<String>, PCErr> {
        let mut result: Option<String> = None;
        for (table_name, table) in self.tables.iter() {
            let sec_table = table
                .as_table()
                .ok_or(PCErr::SectionError(table_name.to_string()))?;
            if sec_table.contains_key(key) {
                if result.is_some() {
                    return Err(PCErr::AmbiguousKeyError(key.to_string()));
                }
                // let value = sec_table.get(key).unwrap().as_str().ok_or(PCErr::KeyError(key.to_string()))?;
                let value = self
                    .value_as_string(sec_table.get(key).unwrap())
                    .or(Err(PCErr::KeyError(key.to_string())))?;
                result = Some(value);
            }
        }
        Ok(result)
    }

    pub fn must_get_config_str_value_for_key(&self, key: &str) -> Result<String, PCErr> {
        match self.get_config_str_value_for_key(key)? {
            Some(value) => Ok(value),
            None => Err(PCErr::MissingKeyError(key.to_string())),
        }
    }

    // Force value into a string.
    //
    // Only works if value is a simple type, or an array of simple types.
    fn value_as_string(&self, toml_val: &Value) -> Result<String, PCErr> {
        match toml_val {
            Value::Array(a) => {
                let mut result = String::new();
                for (i, val) in a.iter().enumerate() {
                    let val_str = val.as_str().ok_or(PCErr::KeyError(
                        "array value not able to coerce to string".to_string(),
                    ))?;
                    result.push_str(val_str);
                    if i < a.len() - 1 {
                        result.push_str(", ");
                    }
                }
                Ok(result)
            }
            Value::Table(_t) => Err(PCErr::KeyError(
                "table value not able to coerce to string".to_string(),
            )),
            _ => {
                let vstr = match toml_val.as_str() {
                    Some(s) => s,
                    None => {
                        return Err(PCErr::KeyError(
                            "value not able to coerce to string".to_string(),
                        ))
                    }
                };
                Ok(vstr.to_string())
            }
        }
    }
}
