use std::fmt;

/// The ZPLStr type can hold either a plain string or a ZPL tuple.
/// Note that a tuple may have an empty value.
pub struct ZPLStr {
    name: String,
    value: Option<String>,
    tuple: bool,
}

impl ZPLStr {
    pub fn new_atom(name: &str) -> ZPLStr {
        ZPLStr {
            name: name.to_string(),
            value: None,
            tuple: false,
        }
    }

    pub fn new_tuple(name: &str, value: &str) -> ZPLStr {
        ZPLStr {
            name: name.to_string(),
            value: Some(value.to_string()),
            tuple: true,
        }
    }

    #[allow(dead_code)]
    pub fn new_tuple_empty(name: &str) -> ZPLStr {
        ZPLStr {
            name: name.to_string(),
            value: None,
            tuple: true,
        }
    }

    pub fn is_tuple(&self) -> bool {
        self.tuple
    }

    pub fn as_tuple(&self) -> (String, String) {
        if !self.tuple {
            panic!("not a tuple");
        }
        match self.value {
            Some(ref v) => (self.name.clone(), v.clone()),
            None => (self.name.clone(), String::new()),
        }
    }

    pub fn as_atom(&self) -> String {
        if self.tuple {
            panic!("not an atom");
        }
        self.name.clone()
    }

    pub fn to_string(&self) -> String {
        if self.tuple {
            let tup = self.as_tuple();
            format!("{}:{}", tup.0, tup.1)
        } else {
            self.name.clone()
        }
    }
}

impl fmt::Display for ZPLStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub struct ZPLStrBuilder {
    name: String,
    value: String,
    tuple: bool,
    input_to_value: bool,
}

impl ZPLStrBuilder {
    pub fn new() -> Self {
        ZPLStrBuilder {
            name: String::new(),
            value: String::new(),
            tuple: false,
            input_to_value: false,
        }
    }

    pub fn clear(&mut self) {
        self.name.clear();
        self.value.clear();
        self.tuple = false;
        self.input_to_value = false;
    }

    pub fn len(&self) -> usize {
        self.name.len() + self.value.len()
    }

    pub fn push(&mut self, c: char) {
        if self.input_to_value {
            self.value.push(c);
        } else {
            self.name.push(c);
        }
    }

    /// Switch to value mode ... all further pushes go to the tuple value. Implies that this is a tuple.
    /// Returns false if we are already in value mode.
    pub fn accept_value(&mut self) -> bool {
        if self.input_to_value {
            return false;
        }
        self.input_to_value = true;
        self.tuple = true;
        true
    }

    // Size of the value part of the tuple.
    pub fn value_len(&self) -> usize {
        self.value.len()
    }

    pub fn is_tuple(&self) -> bool {
        self.tuple
    }

    pub fn to_string(&self) -> String {
        self.build().to_string()
    }

    pub fn is_sugar(&self) -> bool {
        if self.tuple {
            return false;
        }
        match self.name.as_str() {
            "a" | "an" => true,
            _ => false,
        }
    }

    pub fn build(&self) -> ZPLStr {
        if self.tuple {
            return ZPLStr::new_tuple(&self.name, &self.value);
        }
        return ZPLStr::new_atom(&self.name);
    }
}
