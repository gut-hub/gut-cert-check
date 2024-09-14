use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use std::net::TcpStream;

gut_plugin::gut_export!(
    ["cert_check"],
    ["Prints the certificate expiration date of the url"]
);

#[no_mangle]
fn cert_check(ptr: *mut c_char) {
    let c_string = unsafe { CString::from_raw(ptr) };
    let str_from_host = c_string.to_str().unwrap();

    if str_from_host.is_empty() {
        println!("Please provide a domain to check for cert.");
        return;
    }

    let context = {
        let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
        ctx.set_verify(SslVerifyMode::empty());
        ctx.build()
    };
    let connector = Ssl::new(&context).unwrap();
    let stream = TcpStream::connect(format!("{}:443", str_from_host)).unwrap();
    let stream = connector
        .connect(stream)
        .map_err(|e| panic!("Failed to connect: {}", e))
        .unwrap();
    let cert = stream
        .ssl()
        .peer_certificate()
        .ok_or("Failed to find certificate")
        .unwrap();

    println!("{:?}", cert.not_after());
}
