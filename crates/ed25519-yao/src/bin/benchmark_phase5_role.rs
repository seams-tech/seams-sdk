#[cfg(unix)]
fn main() {
    if let Err(error) = unix::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(unix))]
fn main() {
    eprintln!("benchmark_phase5_role requires Unix domain sockets");
    std::process::exit(1);
}

#[cfg(unix)]
mod unix {
    use std::env;
    use std::io::ErrorKind;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;
    use std::thread;
    use std::time::{Duration, Instant};

    use ed25519_yao::phase5_benchmark::{
        run_activation_deriver_a_128k_fixture, run_activation_deriver_a_256k_fixture,
        run_activation_deriver_a_64k_fixture, run_activation_deriver_b_128k_fixture,
        run_activation_deriver_b_256k_fixture, run_activation_deriver_b_64k_fixture,
        run_export_deriver_a_128k_fixture, run_export_deriver_a_256k_fixture,
        run_export_deriver_a_64k_fixture, run_export_deriver_b_128k_fixture,
        run_export_deriver_b_256k_fixture, run_export_deriver_b_64k_fixture,
        Phase5ActivationRoleFixturePackages, Phase5ExportRoleFixturePackage,
        Phase5RoleStreamMetrics,
    };
    use ed25519_yao::{UnixEofBodyWriter, UnixExactEofBodyReader};

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
    const IO_TIMEOUT: Duration = Duration::from_secs(30);

    pub(super) fn run() -> Result<(), String> {
        let mut arguments = env::args().skip(1);
        let family = arguments.next().ok_or_else(usage)?;
        let profile = FixedProfile::parse(&arguments.next().ok_or_else(usage)?)?;
        let role = arguments.next().ok_or_else(usage)?;
        let control_socket = arguments.next().ok_or_else(usage)?;
        let table_socket = arguments.next().ok_or_else(usage)?;
        let session = decode_hex_32(&arguments.next().ok_or_else(usage)?)?;
        if arguments.next().is_some() {
            return Err(usage());
        }
        let (control, table) =
            open_role_channels(&role, Path::new(&control_socket), Path::new(&table_socket))?;
        for stream in [&control, &table] {
            stream
                .set_read_timeout(Some(IO_TIMEOUT))
                .map_err(|error| error.to_string())?;
            stream
                .set_write_timeout(Some(IO_TIMEOUT))
                .map_err(|error| error.to_string())?;
        }
        let control_reader = control.try_clone().map_err(|error| error.to_string())?;
        let control_writer = UnixEofBodyWriter::new(control);

        match (family.as_str(), profile, role.as_str()) {
            ("activation", FixedProfile::K64, "a") => {
                let output = run_activation_deriver_a_64k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixEofBodyWriter::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_activation(output);
            }
            ("activation", FixedProfile::K64, "b") => {
                let output = run_activation_deriver_b_64k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixExactEofBodyReader::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_activation(output);
            }
            ("activation", FixedProfile::K128, "a") => {
                let output = run_activation_deriver_a_128k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixEofBodyWriter::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_activation(output);
            }
            ("activation", FixedProfile::K128, "b") => {
                let output = run_activation_deriver_b_128k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixExactEofBodyReader::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_activation(output);
            }
            ("activation", FixedProfile::K256, "a") => {
                let output = run_activation_deriver_a_256k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixEofBodyWriter::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_activation(output);
            }
            ("activation", FixedProfile::K256, "b") => {
                let output = run_activation_deriver_b_256k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixExactEofBodyReader::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_activation(output);
            }
            ("export", FixedProfile::K64, "a") => {
                let output = run_export_deriver_a_64k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixEofBodyWriter::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_export(output);
            }
            ("export", FixedProfile::K64, "b") => {
                let output = run_export_deriver_b_64k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixExactEofBodyReader::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_export(output);
            }
            ("export", FixedProfile::K128, "a") => {
                let output = run_export_deriver_a_128k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixEofBodyWriter::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_export(output);
            }
            ("export", FixedProfile::K128, "b") => {
                let output = run_export_deriver_b_128k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixExactEofBodyReader::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_export(output);
            }
            ("export", FixedProfile::K256, "a") => {
                let output = run_export_deriver_a_256k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixEofBodyWriter::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_export(output);
            }
            ("export", FixedProfile::K256, "b") => {
                let output = run_export_deriver_b_256k_fixture(
                    session,
                    control_reader,
                    control_writer,
                    UnixExactEofBodyReader::new(table),
                )
                .map_err(|error| error.to_string())?;
                print_export(output);
            }
            _ => return Err(usage()),
        }
        Ok(())
    }

    #[derive(Clone, Copy)]
    enum FixedProfile {
        K64,
        K128,
        K256,
    }

    impl FixedProfile {
        fn parse(value: &str) -> Result<Self, String> {
            match value {
                "64k" => Ok(Self::K64),
                "128k" => Ok(Self::K128),
                "256k" => Ok(Self::K256),
                _ => Err(usage()),
            }
        }
    }

    fn usage() -> String {
        "usage: benchmark_phase5_role <activation|export> <64k|128k|256k> <a|b> CONTROL_SOCKET TABLE_SOCKET SESSION_HEX"
            .to_owned()
    }

    fn open_role_channels(
        role: &str,
        control_socket: &Path,
        table_socket: &Path,
    ) -> Result<(UnixStream, UnixStream), String> {
        match role {
            "b" => {
                let control_listener =
                    UnixListener::bind(control_socket).map_err(|error| error.to_string())?;
                let table_listener =
                    UnixListener::bind(table_socket).map_err(|error| error.to_string())?;
                let (control, _) = control_listener
                    .accept()
                    .map_err(|error| error.to_string())?;
                let (table, _) = table_listener.accept().map_err(|error| error.to_string())?;
                Ok((control, table))
            }
            "a" => Ok((
                connect_with_deadline(control_socket)?,
                connect_with_deadline(table_socket)?,
            )),
            _ => Err(usage()),
        }
    }

    fn connect_with_deadline(socket: &Path) -> Result<UnixStream, String> {
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        loop {
            match UnixStream::connect(socket) {
                Ok(stream) => return Ok(stream),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::ConnectionRefused
                    ) && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    }

    fn print_activation(output: Phase5ActivationRoleFixturePackages) {
        println!(
            "{}:{}|{}",
            encode_hex(output.client_package()),
            encode_hex(output.signing_worker_package()),
            encode_metrics(output.stream_metrics())
        );
    }

    fn print_export(output: Phase5ExportRoleFixturePackage) {
        println!(
            "{}|{}",
            encode_hex(output.package()),
            encode_metrics(output.stream_metrics())
        );
    }

    fn encode_metrics(metrics: Phase5RoleStreamMetrics) -> String {
        format!(
            "{},{},{},{},{}",
            metrics.table_payload_bytes(),
            metrics.body_bytes(),
            metrics.frame_count(),
            metrics.peak_table_buffer_bytes(),
            metrics.peak_arena_bytes(),
        )
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;
            write!(output, "{byte:02x}").expect("writing to String succeeds");
        }
        output
    }

    fn decode_hex_32(encoded: &str) -> Result<[u8; 32], String> {
        if encoded.len() != 64 {
            return Err("session must be exactly 32 lowercase-hex bytes".to_owned());
        }
        let source = encoded.as_bytes();
        let mut output = [0_u8; 32];
        let mut index = 0_usize;
        while index < output.len() {
            output[index] =
                (decode_nibble(source[index * 2])? << 4) | decode_nibble(source[index * 2 + 1])?;
            index += 1;
        }
        if output.iter().all(|byte| *byte == 0) {
            return Err("session must be nonzero".to_owned());
        }
        Ok(output)
    }

    fn decode_nibble(value: u8) -> Result<u8, String> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err("session must use lowercase hex".to_owned()),
        }
    }
}
