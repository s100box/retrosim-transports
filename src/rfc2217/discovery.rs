// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Howard M. Harte
//! How a bridge and its clients find each other. A bridge holding a port
//! writes `rfc2217://host:port` to a file named for the port while it serves
//! it; a client that wants the port reads that file first. The same rule is
//! implemented by `serbridge` (the writer), by `bridgeport.py` and by
//! `SerBridge.psm1`; all of them must agree on the file name.

use std::path::PathBuf;

/// The file a bridge holding `port` writes its URL to.
///
/// The name is the port as given, with a leading `/dev/` removed and `/`,
/// `\` and `:` replaced by `_`; on Windows it is uppercased, since `COM17` and
/// `com17` are one port. Windows also replaces `?` in qualified device paths,
/// since a literal question mark is not valid in a metadata filename.
/// The directory is `%LOCALAPPDATA%\serbridge` on
/// Windows (`%TEMP%` if that is unset) and `$XDG_RUNTIME_DIR/serbridge`
/// elsewhere (`<temp>/serbridge-$USER` if that is unset).
pub fn url_file(port: &str) -> PathBuf {
    let base = port
        .trim_start_matches("/dev/")
        .replace(['/', '\\', ':'], "_");
    #[cfg(windows)]
    let (dir, base) = (
        std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("TEMP"))
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("serbridge"),
        base.replace('?', "_").to_ascii_uppercase(),
    );
    #[cfg(not(windows))]
    let dir = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(d) => PathBuf::from(d).join("serbridge"),
        None => std::env::temp_dir().join(format!(
            "serbridge-{}",
            std::env::var("USER").unwrap_or_else(|_| "user".into())
        )),
    };
    dir.join(format!("{base}.url"))
}

/// The URL of the bridge holding `port` (`rfc2217://127.0.0.1:N`), if one has
/// written its file. A bridge that died without removing the file leaves a
/// stale URL behind, so a connection to it can still be refused.
pub fn bridge_url(port: &str) -> Option<String> {
    let text = std::fs::read_to_string(url_file(port)).ok()?;
    let url = text.lines().next()?.trim();
    url.starts_with("rfc2217://").then(|| url.to_string())
}

/// [`bridge_url`] as the `host:port` to connect to.
pub fn bridge_addr(port: &str) -> Option<String> {
    let url = bridge_url(port)?;
    let addr = url["rfc2217://".len()..].trim_end_matches('/');
    (!addr.is_empty()).then(|| addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_flattens_the_path() {
        let f = url_file("/dev/serial/by-id/usb-FTDI:1");
        let name = f.file_name().unwrap().to_str().unwrap();
        #[cfg(windows)]
        assert_eq!(name, "SERIAL_BY-ID_USB-FTDI_1.url");
        #[cfg(not(windows))]
        assert_eq!(name, "serial_by-id_usb-FTDI_1.url");
    }

    #[cfg(windows)]
    #[test]
    fn windows_names_ignore_case() {
        assert_eq!(url_file("com17"), url_file("COM17"));
    }

    /// Writes a URL file for a port name no real port has, and removes it
    /// when dropped.
    struct UrlFile(PathBuf);

    impl UrlFile {
        fn new(tag: &str, contents: &str) -> (String, UrlFile) {
            let port = format!("rtt{}{tag}", std::process::id());
            let path = url_file(&port);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, contents).unwrap();
            (port, UrlFile(path))
        }
    }

    impl Drop for UrlFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn a_url_file_names_the_bridge() {
        let (port, _f) = UrlFile::new("ok", "rfc2217://127.0.0.1:4001/\nsecond line\n");
        assert_eq!(
            bridge_url(&port).as_deref(),
            Some("rfc2217://127.0.0.1:4001/")
        );
        assert_eq!(bridge_addr(&port).as_deref(), Some("127.0.0.1:4001"));
    }

    #[test]
    fn only_an_rfc2217_url_counts() {
        let (port, _f) = UrlFile::new("http", "http://127.0.0.1:4001\n");
        assert_eq!(bridge_url(&port), None);
        let (port, _f) = UrlFile::new("bare", "rfc2217://");
        assert_eq!(bridge_url(&port).as_deref(), Some("rfc2217://"));
        assert_eq!(bridge_addr(&port), None);
        let (port, _f) = UrlFile::new("empty", "");
        assert_eq!(bridge_url(&port), None);
    }

    #[test]
    fn no_file_no_bridge() {
        assert_eq!(bridge_url("no-such-port-for-this-test"), None);
        assert_eq!(bridge_addr("no-such-port-for-this-test"), None);
    }
}
