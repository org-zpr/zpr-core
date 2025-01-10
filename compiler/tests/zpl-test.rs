use std::env;
use std::path::PathBuf;
use zpc::compilation::CompilationBuilder;

#[test]
fn can_parse_rfc_examples() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let zpl_dir = PathBuf::from(manifest_dir).join("test-data");

    let config_file = zpl_dir.join("config.zplc");

    for fent in zpl_dir
        .read_dir()
        .expect("failed to list zpl test directory")
    {
        if let Ok(fent) = fent {
            let path = fent.path();
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
