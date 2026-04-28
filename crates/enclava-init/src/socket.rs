//! Unix socket framing for the password handoff between attestation-proxy
//! (which terminates the TLS-pinned `/unlock` POST) and enclava-init.
//!
//! Wire format: a single line of UTF-8 text. attestation-proxy writes the
//! password followed by `\n`; enclava-init reads up to a configurable max,
//! validates, and replies with `OK\n` or `ERR <reason>\n`.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use crate::errors::{InitError, Result};

pub const MAX_PASSWORD_LEN: usize = 1024;

pub fn bind(socket_path: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn read_password_line(stream: &mut UnixStream) -> Result<String> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut buf = String::new();
    let n = reader.read_line(&mut buf)?;
    if n == 0 {
        return Err(InitError::Config("empty unlock request".into()));
    }
    if n > MAX_PASSWORD_LEN {
        return Err(InitError::Config("unlock request too large".into()));
    }
    let line = buf.trim_end_matches(['\r', '\n']).to_string();
    Ok(line)
}

pub fn reply_ok(stream: &mut UnixStream) -> Result<()> {
    stream.write_all(b"OK\n")?;
    Ok(())
}

pub fn reply_err(stream: &mut UnixStream, reason: &str) -> Result<()> {
    let line = format!("ERR {reason}\n");
    stream.write_all(line.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn bind_creates_socket_with_mode_0600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unlock.sock");
        let _l = bind(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn read_password_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("unlock.sock");
        let listener = bind(&path).unwrap();

        let path_clone = path.clone();
        let handle = thread::spawn(move || {
            let mut client = UnixStream::connect(&path_clone).unwrap();
            client.write_all(b"hunter2\n").unwrap();
            let mut reader = BufReader::new(client);
            let mut reply = String::new();
            reader.read_line(&mut reply).unwrap();
            reply
        });

        let (mut server_stream, _) = listener.accept().unwrap();
        let pw = read_password_line(&mut server_stream).unwrap();
        assert_eq!(pw, "hunter2");
        reply_ok(&mut server_stream).unwrap();
        drop(server_stream);
        let reply = handle.join().unwrap();
        assert_eq!(reply.trim(), "OK");
    }
}
