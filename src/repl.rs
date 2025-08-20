use crate::protocol::{ClientMessage, ServerMessage};
use crate::secure_connection::SecureConnection;
use anyhow::{Result, Context};
use log::{debug, error, info, warn};
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::validate::{ValidationContext, ValidationResult, Validator};
use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::{Editor, Helper, Context as RlContext};
use rustyline::hint::{Hinter, HistoryHinter};
use rustyline::highlight::Highlighter;
use std::borrow::Cow::{self, Borrowed, Owned};
use std::sync::Arc;
use tokio::sync::Mutex;

const BUILTIN_COMMANDS: [&str; 7] = ["cd", "pwd", "ls", "env", "export", "exit", "history"];

// --- Rustyline Helper Implementation (All Traits) --- 

struct ReplHelper {
    completer: FilenameCompleter,
    hinter: HistoryHinter, 
}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _ctx: &RlContext<'_>,
    ) -> Result<(usize, Vec<Self::Candidate>), ReadlineError> {
        let (start, word) = rustyline::completion::extract_word(line, pos, None, |c| c.is_whitespace());

        let trimmed_line_before_cursor = line[..pos].trim_start();
        let is_command_completion_point = !trimmed_line_before_cursor.contains(char::is_whitespace);

        if is_command_completion_point {
            let mut candidates = Vec::new();
            for &cmd in BUILTIN_COMMANDS.iter() {
                if cmd.starts_with(word) {
                    candidates.push(Pair { display: cmd.to_string(), replacement: cmd.to_string() });
                }
            }
            if !candidates.is_empty() {
                return Ok((start, candidates));
            }
        }

        // Fallback to filename completion
        self.completer.complete(line, pos, _ctx)
    }
}

impl Hinter for ReplHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &RlContext<'_>) -> Option<String> {
        // Delegate to HistoryHinter
        self.hinter.hint(line, pos, ctx).map(String::from)
    }
}

impl Highlighter for ReplHelper {
    // No highlighting
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> Cow<'l, str> {
        Borrowed(line)
    }
    fn highlight_char(&self, _line: &str, _pos: usize, _forced: bool) -> bool {
        false
    }
    // Use default hint highlighting (no change)
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Borrowed(hint)
    }
}

impl Validator for ReplHelper {
    // No validation
    fn validate(&self, _ctx: &mut ValidationContext) -> Result<ValidationResult, ReadlineError> {
        Ok(ValidationResult::Valid(None))
    }
}

// Implement the umbrella Helper trait now that all subtraits are implemented
impl Helper for ReplHelper {}

/// Structure principale pour le REPL côté client
pub struct Repl {
    connection: Arc<Mutex<SecureConnection>>,
    editor: Editor<ReplHelper, DefaultHistory>,
}

impl Repl {
    pub fn new(connection: SecureConnection) -> Result<Self> {
        let helper = ReplHelper {
             completer: FilenameCompleter::new(),
             hinter: HistoryHinter::new(),
        };
        
        let mut editor = Editor::new().context("Failed to create Rustyline editor")?;
        editor.set_helper(Some(helper)); // Use the combined helper
        
        editor.load_history("history.txt").ok(); 
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            editor,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        info!("Starting REPL. Type 'exit' or 'history' to view commands.");
        loop {
            let readline = self.editor.readline("$> ");
            match readline {
                Ok(line) => {
                    let line_trimmed = line.trim();
                    if line_trimmed.is_empty() {
                        continue;
                    }
                    
                    self.editor.add_history_entry(line_trimmed)?; 

                    let mut parts = line_trimmed.split_whitespace();
                    let command = parts.next().unwrap_or("");
                    let args: Vec<String> = parts.map(String::from).collect();

                    if command == "history" {
                        for (i, entry) in self.editor.history().iter().enumerate() {
                             println!("{:>5}  {}", i + 1, entry);
                        }
                        continue;
                    }

                    let msg = match command {
                        "exit" => ClientMessage::Disconnect,
                        "pwd" => ClientMessage::GetCurrentDirectory,
                        "env" => ClientMessage::GetEnvironment,
                        "cd" => {
                            if let Some(path) = args.get(0) {
                                ClientMessage::ChangeDirectory { path: path.clone() }
                            } else {
                                eprintln!("cd: missing operand");
                                continue;
                            }
                        },
                        "ls" => {
                             ClientMessage::ListDirectory { path: args.get(0).cloned() }
                        },
                         "export" => {
                             if let Some(var_assignment) = args.get(0) {
                                 if let Some((key, value)) = var_assignment.split_once('=') {
                                     ClientMessage::SetEnvironment { key: key.to_string(), value: value.to_string() }
                                 } else {
                                     eprintln!("export: invalid format. Use VAR=value");
                                     continue;
                                 }
                            } else {
                                 eprintln!("export: missing operand. Use VAR=value");
                                 continue;
                             }
                         },
                        _ => ClientMessage::ExecuteCommand { command: command.to_string(), args },
                    };

                    let mut conn = self.connection.lock().await;
                    conn.send_message(&msg).await.context("Failed to send message to server")?;

                    if let ClientMessage::Disconnect = msg {
                        info!("Disconnecting...");
                                break;
                            }

                    match conn.receive_server_message().await {
                        Ok(response) => self.handle_server_response(response),
                        Err(e) => {
                             error!("Error receiving message from server: {:?}", e);
                            if e.root_cause().is::<std::io::Error>() && 
                               e.root_cause().downcast_ref::<std::io::Error>().unwrap().kind() == std::io::ErrorKind::UnexpectedEof {
                                 eprintln!("Connection closed by server.");
                                 break; 
                            } else {
                                eprintln!("Failed to receive response from server: {}", e);
                                break; 
                            }
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                     info!("Received Ctrl-C. Type 'exit' to quit.");
                }
                Err(ReadlineError::Eof) => {
                    info!("Received Ctrl-D. Disconnecting...");
                    let mut conn = self.connection.lock().await;
                    let _ = conn.send_message(&ClientMessage::Disconnect).await; 
                    break;
                }
                Err(err) => {
                    error!("Readline error: {:?}", err);
                    break;
                }
            }
        }
        self.editor.save_history("history.txt").context("Failed to save history")
    }

    fn handle_server_response(&self, response: ServerMessage) {
        match response {
            ServerMessage::CommandOutput { stdout, stderr, exit_code } => {
                if !stdout.is_empty() {
                    println!("{}", stdout);
                }
                if !stderr.is_empty() {
                    eprintln!("{}", stderr);
                }
                if let Some(code) = exit_code {
                    debug!("Command exit code: {}", code);
                    if code != 0 {
                         eprintln!("Process exited with status: {}", code);
                    }
                } else {
                    eprintln!("Process terminated without exit code (likely signal).");
                }
            }
            ServerMessage::DirectoryListing { entries, error } => {
                if let Some(err_msg) = error {
                     eprintln!("ls error: {}", err_msg);
                } else {
                    for entry in entries {
                        println!("{}", entry);
                    }
                }
            }
            ServerMessage::CurrentDirectory { path } => {
                println!("{}", path);
            }
            ServerMessage::EnvironmentVariables { vars } => {
                for (key, value) in vars {
                    println!("{}={}", key, value);
                }
            }
            ServerMessage::Acknowledge => {
                 debug!("Received Acknowledge from server.");
             }
            ServerMessage::Error { message } => {
                eprintln!("Server error: {}", message);
             }
             ServerMessage::AuthenticationResult { .. } | ServerMessage::AuthChallenge { .. } | ServerMessage::PublicKey { .. } => {
                 warn!("Received unexpected authentication-related message from server post-authentication: {:?}", response);
            }
        }
    }
}