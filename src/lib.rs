#[allow(improper_ctypes_definitions)]
pub mod gut_cert_check {
    use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
    use std::net::TcpStream;

    #[no_mangle]
    pub extern "C" fn gut_export_functions() -> String {
        r#"["cert_check"]"#.to_string()
    }

    #[no_mangle]
    pub extern "C" fn gut_export_descriptions() -> String {
        r#"["Prints the certificate expiration date of the url"]"#.to_string()
    }

    #[no_mangle]
    fn cert_check(url: String) {
        let context = {
            let mut ctx = SslContext::builder(SslMethod::tls()).unwrap();
            ctx.set_verify(SslVerifyMode::empty());
            ctx.build()
        };
        let connector = Ssl::new(&context).unwrap();
        let stream = TcpStream::connect(format!("{}:443", url)).unwrap();
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
}
