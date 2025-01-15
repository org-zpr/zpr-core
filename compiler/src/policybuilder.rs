//! binp - Binary policy bundle.

use chrono::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::env;
use std::collections::HashMap;

use crate::errors::CompilationError;
use crate::zpl;
use crate::polio;
use crate::fabric::{Fabric, ServiceType};
use crate::ptypes::Attribute;


pub const SERIAL_VERSION: u32 = 1121;

const NO_PROC:u32 = 0xffffffff;


#[allow(dead_code)]
#[derive(Default)]
pub struct PolicyBuilder {
    policy_date: String,
    policy: polio::Policy,
}


#[derive(Debug, Clone, PartialEq, Copy)]
struct PFlags {
    pub node: bool,
    pub vs: bool,
    pub vs_dock: bool,
}

impl PFlags {
    pub fn node() -> PFlags {
        PFlags {
            node: true,
            vs: false,
            vs_dock: true,
        }
    }
    pub fn vs() -> PFlags {
        PFlags {
            node: false,
            vs: true,
            vs_dock: false,
        }
    }
}


#[allow(dead_code)]
impl PolicyBuilder {
    pub fn new() -> PolicyBuilder {
        let utc: DateTime<Utc> = Utc::now();
        let policy_date = utc.to_rfc3339();
        let tsnow = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let policy_version = tsnow.as_secs();

        let mut pp = polio::Policy::default();
        pp.serial_version = SERIAL_VERSION;
        pp.policy_date = policy_date.clone();
        pp.policy_version = policy_version;
        pp.policy_metadata = metadata(&policy_date);

        PolicyBuilder {
            policy_date,
            policy: pp,
        }
    }

    pub fn get_policy_date(&self) -> &str {
        &self.policy_date
    }

    // TODO: trying this with 'self' instead of '&self'...
    pub fn build(self) -> Result<polio::Policy, CompilationError> {
        Ok(self.policy)
    }

    pub fn with_max_visa_lifetime(&mut self, lifetime: Duration) {
        let cs = polio::ConfigSetting {
            key: zpl::CONFIG_KEY_MAX_VISA_LIFETIME,
            val: Some(polio::config_setting::Val::U64v(lifetime.as_secs())),
        };
        self.policy.config.push(cs);
    }


    // fabric can add in
    //   - connects [done]
    //   - policies
    //   - services
    //   - procs [done]
    //   - links
    //   - certificates
    //   - attr keys & vals [done]
    //
    pub fn with_fabric(&mut self, fabric: &Fabric) -> Result<(), CompilationError> {
        self.policy.policy_revision = fabric.revision.clone();

        // The policy refers to attribute keys and values using a lookup table.
        let mut key_table = HashMap::new(); // key -> index
        let mut value_table = HashMap::new(); // value -> index

        // Note that index 0 is not used
        self.populate_key_table(&fabric, &mut key_table);
        self.populate_value_table(&fabric, &mut value_table);
        self.policy.attr_key_index = self.index_from_table(&key_table);
        self.policy.attr_val_index = self.index_from_table(&value_table);

        self.set_connects(&fabric)?;

        Ok(())
    }

    fn set_connects(&mut self, fabric: &Fabric) -> Result<(), CompilationError> {

        for svc in &fabric.services {
            // Any agent that can access a service can connect
            for clipol in &svc.client_policies {
                // No proc for these guys
                let pconnect = polio::Connect {
                    attr_exprs: self.attr_list_to_attrexpr(&clipol.condition),
                    proc: NO_PROC,
                };
                self.policy.connects.push(pconnect);
            }
            // Any agent that provides a service can connect
            match svc.service_type {
                ServiceType::Regular | ServiceType::Visa | ServiceType::BuiltIn => {
                    let flags = if svc.service_type == ServiceType::Visa {
                        Some(PFlags::vs())
                    } else {
                        None
                    };
                    let proc = self.create_service_proc(&svc.fabric_id, svc.service_type, flags);
                    self.policy.procs.push(proc);
                    let proc_idx = self.policy.procs.len() as u32 - 1;
                    let pconnect = polio::Connect {
                        attr_exprs: self.attr_list_to_attrexpr(&svc.provider_attrs),
                        proc: proc_idx,
                    };
                    self.policy.connects.push(pconnect);
                }
                ServiceType::Trusted => {
                    return Err(CompilationError::ConfigError("trusted service not yet implemented".to_string()))
                }
                ServiceType::Undefined => {
                    panic!("undefined service type in fabric{}", svc.config_id);
                }
            }
        }
        // Any agent that provides a node can connect
        for node in &fabric.nodes {
            let proc = self.create_service_proc(&node.config_node.id, ServiceType::Regular, Some(PFlags::node()));
            self.policy.procs.push(proc);
            let proc_idx = self.policy.procs.len() as u32 - 1;
            let pconnect = polio::Connect {
                attr_exprs: self.attr_list_to_attrexpr(&node.provider_attrs),
                proc: proc_idx,
            };
            self.policy.connects.push(pconnect);
        }

        Ok(())
    }

    // fn create_service_proc(&self, svc: &FabricService, flags: Option<PFlags>) -> polio::Proc {
    fn create_service_proc(&self, svc_id: &str, svc_type: ServiceType, flags: Option<PFlags>) -> polio::Proc {
        // In the prototype compiler we include endpoint information in the
        // proc, but that is not used anymore so am leaving it out for
        // now.  We will just use REGISTER but leave endpoints empty.  We
        // will also set relevant flags.

        let mut proc = Vec::new();

        // Args for register are (NAME:String, Type:SvcT, ENDPOINTS:String)
        let mut args = Vec::new();

        args.push(polio::Argument {
            arg: Some(polio::argument::Arg::Strval(svc_id.to_string())),
        });
        let svc_t = if svc_type == ServiceType::Trusted {
            polio::SvcT::SvctAuth
        } else {
            polio::SvcT::SvctDef
        };
        args.push(polio::Argument {
            arg: Some(polio::argument::Arg::Svcval(svc_t as i32)),
        });
        args.push(polio::Argument {
            arg: Some(polio::argument::Arg::Strval("".to_string())), // Empty endpoints
        });

        let register = polio::Instruction {
            opcode: polio::OpCodeT::OpRegister as i32,
            args,
        };
        proc.push(register);

        if let Some(pf) = flags {
            if pf.node {
                let set_flag = polio::Instruction {
                    opcode: polio::OpCodeT::OpSetFlag as i32,
                    args: vec![polio::Argument {
                        arg: Some(polio::argument::Arg::Flagval(polio::FlagT::FNode as i32)),
                    }],
                };
                proc.push(set_flag);
            }
            if pf.vs {
                let set_flag = polio::Instruction {
                    opcode: polio::OpCodeT::OpSetFlag as i32,
                    args: vec![polio::Argument {
                        arg: Some(polio::argument::Arg::Flagval(polio::FlagT::FVisaservice as i32)),
                    }],
                };
                proc.push(set_flag);
            }
            if pf.vs {
                let set_flag = polio::Instruction {
                    opcode: polio::OpCodeT::OpSetFlag as i32,
                    args: vec![polio::Argument {
                        arg: Some(polio::argument::Arg::Flagval(polio::FlagT::FVsDock as i32)),
                    }],
                };
                proc.push(set_flag);
            }
        }

        polio::Proc {
            proc,
        }
    }

    fn attr_list_to_attrexpr(&self, attrs: &Vec<Attribute>) -> Vec<polio::AttrExpr> {
        let mut attrexpr = Vec::new();
        for a in attrs {
            let key = a.zpl_key();
            let val = a.zpl_value();
            let key_idx = self.policy.attr_key_index.iter().position(|x| *x == key).unwrap();
            let val_idx = self.policy.attr_val_index.iter().position(|x| *x == val).unwrap();
            attrexpr.push(polio::AttrExpr {
                key: key_idx as u32,
                op: polio::AttrOpT::Eq as i32,
                val: val_idx as u32,
            });
        }
        attrexpr
    }


    fn index_from_table(&self, table: &HashMap<String, usize>) -> Vec<String> {
        let mut idx = Vec::new();
        idx.resize(table.len() + 1, "".to_string());
        for (k, v) in table {
            idx[*v] = k.clone();
        }
        idx
    }


    fn populate_key_table(&self, fabric: &Fabric, table: &mut HashMap<String, usize>) {
        for s in &fabric.services {
            for a in &s.provider_attrs {
                let key = a.zpl_key();
                if !table.contains_key(&key) {
                    table.insert(key, table.len()+1);
                }
            }
            for policy in &s.client_policies {
                for a in &policy.condition {
                    let key = a.zpl_key();
                    if !table.contains_key(&key) {
                        table.insert(key, table.len()+1);
                    }
                }
            }
        }
        for n in &fabric.nodes {
            for a in &n.provider_attrs {
                let key = a.zpl_key();
                if !table.contains_key(&key) {
                    table.insert(key, table.len()+1);
                }
            }
        }
    }


    fn populate_value_table(&self, fabric: &Fabric, table: &mut HashMap<String, usize>) {
        for s in &fabric.services {
            for a in &s.provider_attrs {
                let key = a.zpl_value();
                if !table.contains_key(&key) {
                    table.insert(key, table.len()+1);
                }
            }
            for policy in &s.client_policies {
                for a in &policy.condition {
                    let key = a.zpl_value();
                    if !table.contains_key(&key) {
                        table.insert(key, table.len()+1);
                    }
                }
            }
        }
        for n in &fabric.nodes {
            for a in &n.provider_attrs {
                let key = a.zpl_value();
                if !table.contains_key(&key) {
                    table.insert(key, table.len()+1);
                }
            }
        }

    }






}






fn metadata(pdate: &str) -> String {
    let username = env::var("USER").unwrap_or_else(|_| "(anonymous)".to_string());
    format!(
        "compiled {} on {} by {}",
        pdate,
        platform::gethostname(),
        username
    )
}



mod platform {

    #[cfg(target_family = "unix")]
    use nix::unistd;

    #[cfg(target_family = "unix")]
    pub fn gethostname() -> String {
        match unistd::gethostname() {
            Ok(h) => h.to_string_lossy().to_string(),
            Err(_) => "(unknown)".to_string(),
        }
    }

    #[cfg(not(target_family = "unix"))]
    pub fn gethostname() -> String {
        return "(unknown)".to_string();
    }
}
