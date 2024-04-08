use std::net::TcpStream;
use std::process::{Child, Command};
use std::{env, panic, thread};

const HOST: &str = "localhost";
const PORT: &str = "8443";

#[test]
#[ignore] // This test requires the client & server binaries be present.
fn client_server_integration() {
    let server_addr = format!("{}:{}", HOST, PORT);
    if TcpStream::connect(&server_addr).is_ok() {
        panic!("cannot run tests; something is already listening on {server_addr}");
    }

    let valgrind = env::var("VALGRIND").ok();

    let standard_server = TestCase {
        name: "Standard client/server tests",
        server_opts: ServerOptions {
            valgrind: valgrind.clone(),
            env: vec![],
        },
        client_tests: standard_client_tests(valgrind.clone()),
    };

    let vectored_server = TestCase {
        name: "Vectored server tests",
        server_opts: ServerOptions {
            valgrind: valgrind.clone(),
            env: vec![("VECTORED_IO", "1")],
        },
        client_tests: standard_client_tests(valgrind.clone()),
    };

    let mandatory_client_auth_server = TestCase {
        name: "Mandatory client auth tests",
        server_opts: ServerOptions {
            valgrind: valgrind.clone(),
            env: vec![("AUTH_CERT", "testdata/minica.pem")],
        },
        client_tests: vec![
            ClientTest {
                name: "No client auth",
                valgrind: valgrind.clone(),
                env: vec![("CA_FILE", "testdata/minica.pem")],
                expect_error: true, // Client connecting w/o AUTH_CERT/AUTH_KEY should err.
            },
            ClientTest {
                name: "Valid client auth",
                valgrind: valgrind.clone(),
                env: vec![
                    ("CA_FILE", "testdata/minica.pem"),
                    ("AUTH_CERT", "testdata/localhost/cert.pem"),
                    ("AUTH_KEY", "testdata/localhost/key.pem"),
                ],
                expect_error: false,
            },
        ],
    };

    let mandatory_client_auth_server_with_crls = TestCase {
        name: "Mandatory client auth w/ CRLs tests",
        server_opts: ServerOptions {
            valgrind: valgrind.clone(),
            env: vec![
                ("AUTH_CERT", "testdata/minica.pem"),
                ("AUTH_CRL", "testdata/test.crl.pem"),
            ],
        },
        client_tests: vec![
            ClientTest {
                name: "Valid client auth",
                valgrind: valgrind.clone(),
                env: vec![
                    ("CA_FILE", "testdata/minica.pem"),
                    ("AUTH_CERT", "testdata/example.com/cert.pem"),
                    ("AUTH_KEY", "testdata/example.com/key.pem"),
                ],
                expect_error: false,
            },
            ClientTest {
                name: "Revoked client auth",
                valgrind: valgrind.clone(),
                env: vec![
                    ("CA_FILE", "testdata/minica.pem"),
                    ("AUTH_CERT", "testdata/localhost/cert.pem"),
                    ("AUTH_KEY", "testdata/localhost/key.pem"),
                ],
                expect_error: true, // Client connecting w/ revoked cert should err.
            },
        ],
    };

    TestCases(vec![
        standard_server,
        vectored_server,
        mandatory_client_auth_server,
        mandatory_client_auth_server_with_crls,
    ])
    .run();
}

fn standard_client_tests(valgrind: Option<String>) -> Vec<ClientTest> {
    vec![
        ClientTest {
            name: "rustls-platform-verifier",
            valgrind: valgrind.clone(),
            env: vec![("RUSTLS_PLATFORM_VERIFIER", "1")],
            expect_error: true,
        },
        ClientTest {
            name: "With CA_FILE",
            valgrind: valgrind.clone(),
            env: vec![("CA_FILE", "testdata/minica.pem")],
            expect_error: false,
        },
        ClientTest {
            name: "No certificate validation",
            valgrind: valgrind.clone(),
            env: vec![("NO_CHECK_CERTIFICATE", "1")],
            expect_error: false,
        },
        ClientTest {
            name: "Client Vectored I/O",
            valgrind: valgrind.clone(),
            env: vec![("CA_FILE", "testdata/minica.pem"), ("USE_VECTORED", "1")],
            expect_error: false,
        },
        ClientTest {
            name: "Client authentication",
            valgrind: valgrind.clone(),
            env: vec![
                ("CA_FILE", "testdata/minica.pem"),
                ("AUTH_CERT", "testdata/localhost/cert.pem"),
                ("AUTH_KEY", "testdata/localhost/key.pem"),
            ],
            expect_error: false,
        },
    ]
}

struct ClientTest {
    name: &'static str,
    valgrind: Option<String>,
    env: Vec<(&'static str, &'static str)>,
    expect_error: bool,
}

impl ClientTest {
    fn run(&self) {
        let client_binary = client_binary();
        let args = vec![HOST, PORT, "/"];
        let (program, args) = match &self.valgrind {
            None => (client_binary.as_str(), args),
            Some(valgrind) => (
                valgrind.as_str(),
                [vec![client_binary.as_str()], args].concat(),
            ),
        };
        let result = Command::new(program)
            .args(args)
            .envs(self.env.clone())
            .output()
            .expect(&format!("failed to run client binary {client_binary}"));

        let passed = result.status.success() == !self.expect_error;
        if !passed {
            println!(
                "client test failed. Failed process output:\n {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        assert!(passed, "client test failed");
    }
}

struct ServerOptions {
    valgrind: Option<String>,
    env: Vec<(&'static str, &'static str)>,
}

impl ServerOptions {
    fn run_server(&self) -> Child {
        let server_binary = server_binary();
        let args = vec!["testdata/localhost/cert.pem", "testdata/localhost/key.pem"];
        let (program, args) = match &self.valgrind {
            None => (server_binary.as_str(), args),
            Some(valgrind) => (
                valgrind.as_str(),
                [vec![server_binary.as_str()], args].concat(),
            ),
        };
        Command::new(program)
            .args(args)
            .envs(self.env.clone())
            .spawn()
            .expect(&format!("failed to run server binary {server_binary}"))
    }
}

struct TestCases(Vec<TestCase>);

impl TestCases {
    fn run(&self) {
        for test_case in &self.0 {
            assert!(test_case.run().is_ok(), "client test panicked");
        }
    }
}

struct TestCase {
    name: &'static str,
    server_opts: ServerOptions,
    client_tests: Vec<ClientTest>,
}

impl TestCase {
    fn run(&self) -> thread::Result<()> {
        println!("\nRunning {:?}", self.name);
        let mut server = self.server_opts.run_server();

        let result = panic::catch_unwind(|| {
            for client_test in &self.client_tests {
                println!("\nRunning client {:?}\n", client_test.name);
                client_test.run();
            }
        });

        server.kill().expect("failed to kill server");
        result
    }
}

fn client_binary() -> String {
    let custom_client_binary = env::var("CLIENT_BINARY").ok();
    #[cfg(not(target_os = "windows"))]
    {
        custom_client_binary.unwrap_or(format!("{}/client", target_dir()))
    }
    #[cfg(target_os = "windows")]
    {
        custom_client_binary.unwrap_or(format!("{}/client.exe", target_dir()))
    }
}

fn server_binary() -> String {
    let custom_server_binary = env::var("SERVER_BINARY").ok();
    #[cfg(not(target_os = "windows"))]
    {
        custom_server_binary.unwrap_or(format!("{}/server", target_dir()))
    }
    #[cfg(target_os = "windows")]
    {
        custom_server_binary.unwrap_or(format!("{}/server.exe", target_dir()))
    }
}

fn target_dir() -> String {
    env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| "target".to_string())
        .to_string()
}
