use enclava_cli::tee_client::TeeClient;

#[test]
fn tee_client_constructs_with_bare_domain() {
    let client = TeeClient::new("myapp.enclava.dev");
    let _ = client;
}

#[test]
fn tee_client_constructs_with_https_prefix() {
    let client = TeeClient::new("https://myapp.enclava.dev");
    let _ = client;
}

#[test]
fn tee_client_constructs_with_trailing_slash() {
    let client = TeeClient::new("https://myapp.enclava.dev/");
    let _ = client;
}
