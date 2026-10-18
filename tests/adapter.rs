use licensebox::{derive_binding, native_binding, verify_lease, Client, Config};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, Read},
};
fn run(r: &Value) -> licensebox::Result<Value> {
    let s = |k: &str| r[k].as_str().unwrap_or("");
    let product = s("product");
    let keys: BTreeMap<String, String> =
        serde_json::from_value(r["keys"].clone()).unwrap_or_default();
    match s("op") {
        "derive" => return derive_binding(product, s("source"), s("raw_id")).map(|s| json!(s)),
        "native" => return native_binding(product).map(|s| json!(s)),
        "verify" => return verify_lease(s("token"), product, &keys, r["now"].as_f64().unwrap()),
        _ => {}
    }
    let mut cfg = Config::new(product, keys);
    cfg.version = "conformance".into();
    cfg.server = Some(s("server").into());
    cfg.directory = Some(s("directory").into());
    let now = r["now"].as_f64().unwrap();
    cfg.callbacks.clock = Some(Box::new(move || now));
    let host = s("binding").to_string();
    cfg.callbacks.machine_binding = Some(Box::new(move || Ok(host.clone())));
    cfg.callbacks.on_sign_in = Some(Box::new(|_, _| {}));
    let mut c = Client::new(cfg)?;
    match s("op") {
        "lease" => c.lease(),
        "status" => c.status(),
        "sign_in" => c.sign_in(3.0),
        "require" => c.require(if s("module").is_empty() {
            "core"
        } else {
            s("module")
        }),
        "repeat" => {
            c.require("core")?;
            c.require("core")
        }
        "logout" => c.logout().map(|_| Value::Null),
        "modules" => c.modules(),
        "requests" => c.requests(),
        "access-link" => c.access_link().map(|s| json!(s)),
        "request" => c.request_access(&["export"], "café – test"),
        "record" => {
            c.record("export", true, 0.125)?;
            c.record("export", false, 0.025)?;
            Ok(Value::Null)
        }
        _ => panic!("unknown operation"),
    }
}
fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    let r: Value = serde_json::from_str(&text).unwrap();
    let result = match run(&r) {
        Ok(v) => json!({"ok":true,"value":v}),
        Err(e) => json!({"ok":false,"error":e.code}),
    };
    println!("{result}");
}
