use enclava_engine::apply::teardown::build_teardown_url;

#[test]
fn teardown_url_uses_well_known_path() {
    let url = build_teardown_url("myapp.enclava.dev");
    assert_eq!(
        url,
        "https://myapp.enclava.dev/.well-known/confidential/teardown"
    );
}

#[test]
fn teardown_url_strips_trailing_slash() {
    let url = build_teardown_url("myapp.enclava.dev/");
    assert_eq!(
        url,
        "https://myapp.enclava.dev/.well-known/confidential/teardown"
    );
}
