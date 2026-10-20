//! Safe Rust API over Licensebox C >=0.5.0. Linux is the validated platform.
//! Keep one client per process; check access before protected work.
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ffi::{c_char, c_int, c_void, CStr, CString},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr,
};

#[derive(Debug, Clone)]
pub struct Error {
    pub code: String,
    pub message: String,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "licensebox: {}", self.message)
    }
}
impl std::error::Error for Error {}
fn error(code: &str, message: &str) -> Error {
    Error {
        code: code.into(),
        message: message.into(),
    }
}
pub type Result<T> = std::result::Result<T, Error>;
fn cstr(value: &str) -> Result<CString> {
    CString::new(value).map_err(|_| error("invalid_argument", "NUL byte in argument"))
}
unsafe fn text(value: *const c_char) -> String {
    if value.is_null() {
        String::new()
    } else {
        CStr::from_ptr(value).to_string_lossy().into_owned()
    }
}

#[derive(Default)]
pub struct Callbacks {
    pub on_sign_in: Option<SignInCallback>,
    pub cancelled: Option<Box<dyn FnMut() -> bool>>,
    /// Trusted platform/test seam, never an end-user identity override.
    pub machine_binding: Option<Box<dyn FnMut() -> Result<String>>>,
    /// Unix seconds. Production applications normally use the system clock.
    pub clock: Option<Box<dyn FnMut() -> f64>>,
}
pub type SignInCallback = Box<dyn FnMut(&str, &str)>;
pub struct Config {
    pub product: String,
    pub keys: BTreeMap<String, String>,
    pub version: String,
    pub server: Option<String>,
    pub directory: Option<String>,
    pub callbacks: Callbacks,
}
impl Config {
    pub fn new(product: impl Into<String>, keys: BTreeMap<String, String>) -> Self {
        Self {
            product: product.into(),
            keys,
            version: String::new(),
            server: None,
            directory: None,
            callbacks: Callbacks::default(),
        }
    }
}
struct State {
    hooks: Callbacks,
    failure: Option<Error>,
}
#[repr(C)]
struct NativeCallbacks {
    context: *mut c_void,
    on_sign_in: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char)>,
    clock: Option<unsafe extern "C" fn(*mut c_void) -> f64>,
    machine_binding: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> c_int>,
    cancelled: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}
extern "C" {
    fn lb_client_create_json(
        options: *const c_char,
        hooks: *const NativeCallbacks,
        out: *mut *mut c_void,
    ) -> c_int;
    fn lb_client_call_json(
        client: *mut c_void,
        op: *const c_char,
        args: *const c_char,
        out: *mut *mut c_char,
    ) -> c_int;
    fn lb_client_destroy(client: *mut c_void);
    fn lb_error_code(client: *const c_void) -> *const c_char;
    fn lb_error_message(client: *const c_void) -> *const c_char;
    fn lb_result_code(result: c_int) -> *const c_char;
    fn lb_free(output: *mut c_void);
    fn lb_derive_binding(
        product: *const c_char,
        source: *const c_char,
        raw: *const c_char,
        out: *mut c_char,
        capacity: usize,
    ) -> c_int;
    fn lb_native_binding(product: *const c_char, out: *mut c_char, capacity: usize) -> c_int;
    fn lb_verify_lease_json(
        token: *const c_char,
        product: *const c_char,
        keys: *const c_char,
        now: f64,
        out: *mut *mut c_char,
    ) -> c_int;
}
unsafe fn result_error(code: c_int, handle: *const c_void) -> Error {
    let standard = text(lb_result_code(code));
    if handle.is_null() || standard == "invalid_argument" {
        return error(&standard, &standard);
    }
    let saved = text(lb_error_code(handle));
    let message = text(lb_error_message(handle));
    error(
        if saved == "ok" { &standard } else { &saved },
        if message.is_empty() {
            &standard
        } else {
            &message
        },
    )
}
unsafe fn owned_json(value: *mut c_char) -> Result<Value> {
    if value.is_null() {
        return Err(error("protocol_error", "missing native result"));
    }
    let bytes = CStr::from_ptr(value).to_bytes().to_vec();
    lb_free(value.cast());
    serde_json::from_slice(&bytes)
        .map_err(|_| error("protocol_error", "invalid native JSON result"))
}
unsafe extern "C" fn signin(p: *mut c_void, url: *const c_char, code: *const c_char) {
    let s = &mut *p.cast::<State>();
    if catch_unwind(AssertUnwindSafe(|| {
        if let Some(f) = s.hooks.on_sign_in.as_mut() {
            f(&text(url), &text(code));
        }
    }))
    .is_err()
    {
        s.failure = Some(error("callback_error", "sign-in callback failed"));
    }
}
unsafe extern "C" fn clock(p: *mut c_void) -> f64 {
    let s = &mut *p.cast::<State>();
    match catch_unwind(AssertUnwindSafe(|| s.hooks.clock.as_mut().unwrap()())) {
        Ok(v) if v.is_finite() => v,
        _ => {
            s.failure = Some(error("callback_error", "clock callback failed"));
            0.0
        }
    }
}
unsafe extern "C" fn binding(p: *mut c_void, out: *mut c_char, n: usize) -> c_int {
    let s = &mut *p.cast::<State>();
    match catch_unwind(AssertUnwindSafe(|| {
        s.hooks.machine_binding.as_mut().unwrap()()
    })) {
        Ok(Ok(v)) if v.len() < n && !v.as_bytes().contains(&0) => {
            ptr::copy_nonoverlapping(v.as_ptr(), out.cast(), v.len());
            *out.add(v.len()) = 0;
            0
        }
        Ok(Err(e)) => {
            s.failure = Some(e);
            1
        }
        _ => {
            s.failure = Some(error(
                "identity_unavailable",
                "native identity callback failed",
            ));
            1
        }
    }
}
unsafe extern "C" fn cancelled(p: *mut c_void) -> c_int {
    let s = &mut *p.cast::<State>();
    if s.failure.is_some() {
        return 1;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        s.hooks.cancelled.as_mut().map(|f| f()).unwrap_or(false)
    })) {
        Ok(v) => v as c_int,
        Err(_) => {
            s.failure = Some(error("callback_error", "cancellation callback failed"));
            1
        }
    }
}
/// Owns a native client. Calls require mutable access; this type is not Send/Sync.
/// Callback panics/errors never unwind into C or allow protected work to succeed.
pub struct Client {
    handle: *mut c_void,
    // Owned stable allocation. C borrows this pointer only until destroy.
    state: *mut State,
}
impl Client {
    pub fn new(config: Config) -> Result<Self> {
        let mut options =
            json!({"product":config.product,"keys":config.keys,"version":config.version});
        if let Some(v) = config.server {
            options["server"] = json!(v)
        }
        if let Some(v) = config.directory {
            options["directory"] = json!(v)
        }
        let state = Box::new(State {
            hooks: config.callbacks,
            failure: None,
        });
        let mut cb = NativeCallbacks {
            context: ptr::null_mut(),
            on_sign_in: state.hooks.on_sign_in.as_ref().map(|_| signin as _),
            clock: state.hooks.clock.as_ref().map(|_| clock as _),
            machine_binding: state.hooks.machine_binding.as_ref().map(|_| binding as _),
            cancelled: Some(cancelled),
        };
        let options = cstr(&options.to_string())?;
        let state = Box::into_raw(state);
        cb.context = state.cast();
        let mut handle = ptr::null_mut();
        let code = unsafe { lb_client_create_json(options.as_ptr(), &cb, &mut handle) };
        if code != 0 {
            unsafe {
                drop(Box::from_raw(state));
            }
            return Err(unsafe { result_error(code, ptr::null()) });
        }
        Ok(Self { handle, state })
    }
    fn call(&mut self, op: &str, args: Value) -> Result<Value> {
        let op = cstr(op)?;
        let args = cstr(&args.to_string())?;
        let mut output = ptr::null_mut();
        let code =
            unsafe { lb_client_call_json(self.handle, op.as_ptr(), args.as_ptr(), &mut output) };
        if let Some(e) = unsafe { (*self.state).failure.take() } {
            unsafe { lb_free(output.cast()) };
            return Err(e);
        }
        if code != 0 {
            unsafe { lb_free(output.cast()) };
            return Err(unsafe { result_error(code, self.handle) });
        }
        unsafe { owned_json(output) }
    }
    pub fn lease(&mut self) -> Result<Value> {
        self.call("lease", json!({}))
    }
    pub fn require(&mut self, module: &str) -> Result<Value> {
        self.call("require", json!({"module":module}))
    }
    /// Explicit bounded renewal without activation; returns {lease, online}.
    /// Application scheduling must independently respect the verified expiry.
    pub fn heartbeat(&mut self, module: &str) -> Result<Value> {
        self.call("heartbeat", json!({"module":module}))
    }
    pub fn status(&mut self) -> Result<Value> {
        self.call("status", json!({}))
    }
    pub fn sign_in(&mut self, timeout_seconds: f64) -> Result<Value> {
        if !timeout_seconds.is_finite() {
            return Err(error("invalid_argument", "invalid timeout"));
        }
        self.call("sign_in", json!({"timeout":timeout_seconds}))
    }
    pub fn logout(&mut self) -> Result<()> {
        self.call("logout", json!({})).map(|_| ())
    }
    pub fn modules(&mut self) -> Result<Value> {
        self.call("modules", json!({}))
    }
    pub fn requests(&mut self) -> Result<Value> {
        self.call("requests", json!({}))
    }
    pub fn request_access(&mut self, modules: &[&str], note: &str) -> Result<Value> {
        self.call("request", json!({"modules":modules,"note":note}))
    }
    pub fn access_link(&mut self) -> Result<String> {
        self.call("access-link", json!({}))?
            .as_str()
            .map(String::from)
            .ok_or_else(|| error("protocol_error", "invalid access link"))
    }
    pub fn record(&mut self, command: &str, success: bool, elapsed_seconds: f64) -> Result<()> {
        if !elapsed_seconds.is_finite() || elapsed_seconds < 0.0 {
            return Err(error("invalid_argument", "invalid elapsed time"));
        }
        self.call(
            "record",
            json!({"command":command,"success":success,"elapsed":elapsed_seconds}),
        )
        .map(|_| ())
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            lb_client_destroy(self.handle);
            drop(Box::from_raw(self.state));
        }
    }
}
pub fn derive_binding(product: &str, source: &str, raw: &str) -> Result<String> {
    let (p, s, r) = (
        cstr(product)?,
        cstr(source)?,
        cstr(raw.trim_end_matches('\0'))
            .map_err(|_| error("identity_unavailable", "invalid native identity"))?,
    );
    let mut out = [0 as c_char; 128];
    let code = unsafe {
        lb_derive_binding(
            p.as_ptr(),
            s.as_ptr(),
            r.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if code != 0 {
        return Err(unsafe { result_error(code, ptr::null()) });
    }
    Ok(unsafe { text(out.as_ptr()) })
}
pub fn native_binding(product: &str) -> Result<String> {
    let p = cstr(product)?;
    let mut out = [0 as c_char; 128];
    let code = unsafe { lb_native_binding(p.as_ptr(), out.as_mut_ptr(), out.len()) };
    if code != 0 {
        return Err(unsafe { result_error(code, ptr::null()) });
    }
    Ok(unsafe { text(out.as_ptr()) })
}
pub fn verify_lease(
    token: &str,
    product: &str,
    keys: &BTreeMap<String, String>,
    now: f64,
) -> Result<Value> {
    if !now.is_finite() {
        return Err(error("invalid_argument", "invalid time"));
    }
    let (t, p, k) = (
        cstr(token)?,
        cstr(product)?,
        cstr(&serde_json::to_string(keys).unwrap())?,
    );
    let mut out = ptr::null_mut();
    let code = unsafe { lb_verify_lease_json(t.as_ptr(), p.as_ptr(), k.as_ptr(), now, &mut out) };
    if code != 0 {
        unsafe { lb_free(out.cast()) };
        return Err(unsafe { result_error(code, ptr::null()) });
    }
    unsafe { owned_json(out) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_callback_failure_stops_before_network() {
        let mut cfg = Config::new(
            "demo",
            BTreeMap::from([(
                "test".into(),
                "ed25519-mldsa65:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbgBskJ2J1ZnAC5A6WhahxalHLyrs5Np9U8kswmC3vyjzuM5K47fXvZQ-j8x35JybT0vXygJlrzL1XgbsswQZ5TsRxcRPJ_0gcuItfpG4hGPb8_kMRob8LeLhK9y0lyyKkjuPDAjLxpCoCtt1WebJSVZVEVNHVwbGAHIZzcI44Q_9XERNHnhn1pd0VH4hRmvBhEWJd2e7wui09lnVTUx-Xea97WP893KrtB_zMeyMz3YXaqybb3vMYq4qxZUTtbQRDEZWdczummvKgzQUfoh69hLTG5Yv3W8AEcCWCA17C18GVD9SmDFKfoNP7PqdHT8cBMgF717QebmrCfwVD32fL4JK5VCb_7jt4N2qKpTnyZh8Ip1WOA5E__dO88mVrUFiipkbESzqwTnI0JSl7Hpm0zPN2yhnzAgz4ZvR7DNTtcy6tiPjhAcOnknUNj9_sn4cAd8tEWeTcQIGh3gYOJVJf8llFJK2J-W86kM9zLYALmzcPJLeZRm3RPotMAd7CbWgBHCwGEx7_R8xKQHSn_bIX4HPNoKu-JwDXSu0jSd9tQyJF82to_UDBkDc1IXtwfqkk6g0jm0Nc76iPSHEaGxNtRHocnZxojIDzx07wEHbA2HjwWBkCRkH4SfdGopWDOvbNmxkFjfy9y2nYZ5UT0jtJcwJa2gUwLtkHm-ScarVsmLqphuFqH-MZ073mC4vf-DbSNLjfDB9GLDac1oUzP8SkHo7Lbbfv3k0p8k_Qn_gS2IttdHQ9bZNSv-ui-qffQ19FPPyriWxXUjU44Jc8kuG_07xG6PGbdkGaevMm5HKzYRjNUZxpzged7AqcztVznoNcpVXKVXr5uROHh6vPaYg-jYlkImr5TU1irFrcwKO6EnNd837UeoauInGbViwSmc24tYJqJgIW6Fc1Vj9IjuwbyjPplnRXo7c6SX2NVWznxSiOk487vjiCogCRqdD6nFpZXNotB3xYOKMlyhmXq1n-wVJxcc34GIQ8oDdbKJyP0xXMRLxg4xbbYUlmE1HKk0BXN-bARK9_MtGiFJjjPOAFmvndD5xA1VjNyuUe6bblyS2ybn5FqkbSsufyTnvsjY9GVhVkA-BBJRKvNS0qIpJEDFHb7uscQAChPKhpeC2JU2B9Qy7KLRhzX9c1ru15ZHvBN0U1yv_ScNW4tn7SD20yipPpiG_THNZDbg1n76LpV-T4odFNJqgF51u3wb86ck1JNr4yZK7GwKu1Hso8iVcoK_67J5J5xUWC6YL0biy4_13aTKEi4bDUPs7ZT0dGc6KDfAXbYFw8X4TEElIT33XvE-RD6vgrBRQr2zDDeRfmbBNrZBMs222h_Ghc4byXS70O2ecZ8VIlKN1Rzj3llEskHkovohBdkS5K7POWPc7CVWpVXt7EFw7hEOQ48bu9s0Seo_Clyyy1xu3S1kO4WM1tkLIK55uaRTYcxX7IuvTPpep2M9wn0dUE9DyKnVQ72Ofjwn_DGlKdRz0DYA6Qb7n1l57HOYe8MH0hDRRM0u0_wRphYPMIGx1KU3L7tpo5uOL0hA6a1iPIkcKH28N3GLfoD0Xcf0-VC58cZl3UXxLGDBbTavvKADWWYVkl7kQK2UgHbS34bKExQHGRh4SAas0uOy7cZ6hqmw-1brz0MWqmj4rCBlmSo-fqLlBz3U-St20pwNZpAqufTPHbbyqbCy2U9iNpLpiU_hkMyoFag3oaXr0a8I2nFQFEZP7jzPKbcmmTsfyBFkd517XXkljyNY6R9zZFfKV8dv90tYYaoVHZ3BUhOFXUYoB65VkFoWPbyGtuMxQ4zgzNnxHlUNn6kLidcYJbLy1vqnyy7cZz05CbjYVp2B4CdipAmdyvq-WDieMg4DYbmyYW_YQJwM0pi2YaTCHqNVbcDrR3yl1Wlzonp6X-Cw2zLdqV_Vo0lw2vmUdbcHkh1ulWhFKZ6FX57JzUeMD7SmXtYHQQq1imNP_17CJX6T6i9c_2xH4KevUz9gQb7chPOuDL0MHlguSZXttGotPtCex09jf-6dFsE_Bje-9yF4jpdJozimIolygCsb876JdhsIL3tJ7AGFeAKnNysAphoAbkluhwqJq1s7MNThUqYLIzyrwfu4yDeduzAks8XhlA5XkdnHSmEphbqVc7-6eqGlcBD2NEtGCNXxnEr5u3vAKn6ngQW4ms_0WiVnX0pjOM-XKdBOhnJg-4VsLX28i67SRxPFtYmB3pSy9HadLihn-vHeD1dk0K9GNhJDDS-TMutxoXunggKLdNwBoLgUgadnUKg0imeyKqbFp5fZpE5BRwite4rVByOW7hGZKxaPZWuIGjCYI8T72RZ6YpzsRVUI83sMQ-XOsIxg19NX2qvasM1cxdyFFmGr2R8ve00Xaf5S0q-bpLeDqfKyHyM6UijkZ8BGT69_Ms5QN2z38FrJURuBcwOIyKJlvYSOTHuBJD3YX0R-NyzMhzY7lVlcb59WeKwfUSMDPkjqxS6kQfzMT-w6LbNfVp4ZYqJEYvcezwKm2Rd1zFFr7cGPzCzIxRFb9gvWIjM8QGe0H81Jqt5e3mbBajO1Ojsn73TA5yNdvk0KBwppJhJagr8S4B9w4cVE8xezoQ1a7yNi4asPGw".into(),
            )]),
        );
        cfg.server = Some("http://127.0.0.1:1".into());
        cfg.callbacks.machine_binding = Some(Box::new(|| {
            Err(error("identity_unavailable", "synthetic provider failure"))
        }));
        let mut client = Client::new(cfg).unwrap();
        assert_eq!(
            client.require("core").unwrap_err().code,
            "identity_unavailable"
        );
    }
    #[test]
    fn embedded_native_nul_is_rejected() {
        assert_eq!(
            derive_binding("demo", "linux-machine-id", "0123456789abcdef\0garbage")
                .unwrap_err()
                .code,
            "identity_unavailable"
        );
    }
}
