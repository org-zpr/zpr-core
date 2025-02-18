use std::env;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zpc::compilation::CompilationBuilder;

fn get_zpl_dir() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest_dir).join("test-data")
}

fn get_m3_policy_dir() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut pb = PathBuf::from(manifest_dir);
    pb.pop();
    pb.push("examples");
    pb.push("milestone3");
    pb.push("policies");
    pb
}

fn get_integtest_policy_dir() -> PathBuf {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut pb = PathBuf::from(manifest_dir);
    pb.pop();
    pb.push("integration-test");
    pb.push("pregen");
    pb
}

struct TempDir {
    path: PathBuf,
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).expect("failed to remove zpc temp dir");
    }
}

impl TempDir {
    fn new(name_hint: &str) -> Self {
        let mut temp_dir = env::temp_dir();
        temp_dir.push(format!(
            "zpl-test-{}-{}-{}",
            name_hint,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));
        std::fs::create_dir_all(&temp_dir).expect("failed to create temp dir for zpc output");
        TempDir { path: temp_dir }
    }
}

#[test]
fn can_parse_rfc_examples() {
    let zpl_dir = get_zpl_dir();
    let config_file = zpl_dir.join("config.zplc");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list zpl test directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            // And must start with "rfc"
            if let Some(fstem) = path.file_stem() {
                if let Some(fstem_str) = fstem.to_str() {
                    if !fstem_str.starts_with("rfc") {
                        continue;
                    }
                }
            }
            let cb = CompilationBuilder::new(path)
                .verbose(true)
                .parse_only(true)
                .config(&config_file);
            let comp = cb.build();
            match comp.compile() {
                Ok(_) => println!("{:?}: compiled ok", fent.path()),
                Err(e) => {
                    println!("error: {}", e);
                    panic!("failed to compile {:?}", fent.path());
                }
            }
        }
    }
}

#[test]
fn can_compile_m3_policies() {
    let zpl_dir = get_m3_policy_dir();
    let temp_dir = TempDir::new("m3");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list M3 policy directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            let cb = CompilationBuilder::new(path)
                .verbose(true)
                .output_directory(&temp_dir.path);
            let comp = cb.build();
            match comp.compile() {
                Ok(_) => println!("{:?}: compiled ok", fent.path()),
                Err(e) => {
                    println!("error: {}", e);
                    panic!("failed to compile {:?}", fent.path());
                }
            }
        }
    }
}

// Make sure we can still compile the policies in the
// integration-test. Note that this does not try to compile
// with the IPv6 config used there.
#[test]
fn can_compile_integtest_policies() {
    let zpl_dir = get_integtest_policy_dir();
    let temp_dir = TempDir::new("integtest");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list integration-test policy directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
            // Must end with ".zpl"
            match path.extension() {
                Some(ext) => {
                    if ext != "zpl" {
                        continue;
                    }
                }
                None => continue,
            }
            let cb = CompilationBuilder::new(path)
                .verbose(true)
                .output_directory(&temp_dir.path);
            let comp = cb.build();
            match comp.compile() {
                Ok(_) => println!("{:?}: compiled ok", fent.path()),
                Err(e) => {
                    println!("error: {}", e);
                    panic!("failed to compile {:?}", fent.path());
                }
            }
        }
    }
}
