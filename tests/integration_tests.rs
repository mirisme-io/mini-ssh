use std::process::{Command, Stdio, Child};
use std::thread;
use std::time::Duration;
use std::io::{Read, Write};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::env; // Added for setting environment variable

const DEFAULT_HOST: &str = "127.0.0.1";
const TEST_PORT: u16 = 2223; // Changed to a different port for testing
const SERVER_BIN: &str = "target/debug/server";
const CLIENT_BIN: &str = "target/debug/client";
const TEST_USER: &str = "user_pass"; // Define a test username
const TEST_PASS: &str = "password123"; // Removed newline, env var won't have it
const TEST_ENV_PASSWORD_VAR: &str = "RUST_SSH_TEST_PASSWORD";

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let pid = Pid::from_raw(self.0.id() as i32);
        let _ = signal::kill(pid, Signal::SIGTERM);
        thread::sleep(Duration::from_millis(100)); // Increased sleep duration slightly
        match self.0.try_wait() {
            Ok(Some(_)) => { /* Already exited */ }
            Ok(None) => { 
                println!("Process {} did not exit after SIGTERM, sending SIGKILL.", self.0.id());
                match signal::kill(pid, Signal::SIGKILL) {
                    Ok(_) => println!("Successfully SIGKILLed process {}", self.0.id()),
                    Err(e) => eprintln!("Failed to SIGKILL process {}: {}", self.0.id(), e),
                }
                let _ = self.0.wait(); // Wait after SIGKILL as well
            }
            Err(e) => eprintln!("Error trying to wait for process {}: {}", self.0.id(), e),
        }
    }
}


#[test]
fn server_starts_and_client_connects_authenticates_and_exits() {
    // --- Server Setup ---
    println!("Starting server on port {}...", TEST_PORT);
    let mut server_cmd = Command::new(SERVER_BIN);
    server_cmd.arg("--port").arg(TEST_PORT.to_string()); // Pass test port to server
    
    let server_process = server_cmd
        .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
        .expect("Failed to start server binary");
    let mut server_guard = ChildGuard(server_process); // Use guard to ensure cleanup

    println!("Waiting for server to initialize...");
    thread::sleep(Duration::from_secs(2)); // Give server time to bind

    // --- Client Connection ---
    println!("Attempting client connection to port {}...", TEST_PORT);
    let mut client_cmd = Command::new(CLIENT_BIN);
    client_cmd.arg("--server").arg(DEFAULT_HOST);
    client_cmd.arg("--port").arg(TEST_PORT.to_string()); // Use test port for client
    client_cmd.arg("--username").arg(TEST_USER);
    
    // Set environment variable for non-interactive password
    client_cmd.env(TEST_ENV_PASSWORD_VAR, TEST_PASS);

    client_cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut client_process = client_cmd.spawn()
        .expect("Failed to spawn client binary");

    // Send "exit" command via stdin after a delay
    if let Some(mut stdin) = client_process.stdin.take() {
        thread::sleep(Duration::from_millis(500)); // Wait for client to auth and potentially start REPL
        println!("Sending 'exit' command to client stdin...");
        if let Err(e) = stdin.write_all(b"exit\n") {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                println!("Client stdin pipe was broken before writing 'exit'. Client might have exited.");
            } else {
                eprintln!("Error writing 'exit' to client stdin: {}", e);
            }
        }
        drop(stdin);
    }

    let client_output = client_process.wait_with_output()
        .expect("Failed to wait for client");

    // --- Assertions & Output ---
    println!("Client finished.");
    let client_stdout = String::from_utf8_lossy(&client_output.stdout);
    let client_stderr = String::from_utf8_lossy(&client_output.stderr);
    println!("--- Client Stdout ---:\n{}", client_stdout);
    println!("--- Client Stderr ---:\n{}", client_stderr);
    println!("--- Client Status ---:\n{:?}", client_output.status);

    // Capture server output before ChildGuard drops and potentially closes pipes
    let mut server_stdout_str = String::new();
    if let Some(mut stdout) = server_guard.0.stdout.take() { 
        stdout.read_to_string(&mut server_stdout_str).unwrap_or_default();
    }
    let mut server_stderr_str = String::new();
    if let Some(mut stderr) = server_guard.0.stderr.take() { 
        stderr.read_to_string(&mut server_stderr_str).unwrap_or_default();
    }
    println!("--- Server Stdout (captured before server_guard drop) ---:\n{}", server_stdout_str);
    println!("--- Server Stderr (captured before server_guard drop) ---:\n{}", server_stderr_str);

    // Server is killed by ChildGuard drop when server_guard goes out of scope here

    assert!(client_output.status.success(), "Client process did not exit successfully. Check stderr/stdout above.");
    println!("Test finished successfully.");
}

