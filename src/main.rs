#![windows_subsystem = "windows"]

mod crypto;

use arboard::Clipboard;
use iced::widget::{
    Space, button, column, container, row, scrollable, text, text_editor, text_input,
};
use iced::{Element, Length, Task};
use std::env;
use std::fs;
use std::path::Path;

use crate::crypto::{decode_custom, decode_custom_bytes, encode_custom, encode_custom_bytes};

#[derive(Debug, Clone)]
pub enum Message {
    InputChanged(text_editor::Action),
    PasswordChanged(String),
    CopyInput,
    CopyOutput,
    PasteInput,
    ToggleMode,
    Clear,
    SelectFile,
    FileSelected(Option<std::path::PathBuf>),
    SaveFileSelected(std::path::PathBuf, Option<std::path::PathBuf>),
    OperationComplete(Result<String, String>),
    UpdateCryptoResult(u64, Result<(String, std::time::Duration), String>),
}

#[derive(Debug, Clone, PartialEq)]
enum Mode {
    Encrypt,
    Decrypt,
}

pub struct App {
    plaintext_content: text_editor::Content,
    ciphertext_content: text_editor::Content,
    password: String,
    mode: Mode,
    status: String,
    last_duration: Option<std::time::Duration>,
    is_loading: bool,
    generation: u64,
}

impl Default for App {
    fn default() -> Self {
        Self {
            plaintext_content: text_editor::Content::new(),
            ciphertext_content: text_editor::Content::new(),
            password: String::new(),
            mode: Mode::Encrypt,
            status: String::from("Ready"),
            last_duration: None,
            is_loading: false,
            generation: 0,
        }
    }
}

impl App {
    fn perform_crypto(&mut self) -> Task<Message> {
        self.is_loading = true;
        self.last_duration = None;
        self.generation += 1;
        let generation = self.generation;

        let mode = self.mode.clone();
        let password = self.password.clone();
        let input = match mode {
            Mode::Encrypt => self.plaintext_content.text(),
            Mode::Decrypt => self.ciphertext_content.text(),
        };

        if input.is_empty() {
            self.is_loading = false;
            match mode {
                Mode::Encrypt => self.ciphertext_content = text_editor::Content::new(),
                Mode::Decrypt => self.plaintext_content = text_editor::Content::new(),
            }
            return Task::none();
        }

        // Clear output while loading to show placeholder
        match mode {
            Mode::Encrypt => self.ciphertext_content = text_editor::Content::new(),
            Mode::Decrypt => self.plaintext_content = text_editor::Content::new(),
        }

        Task::perform(
            async move {
                let start = std::time::Instant::now();
                let result = tokio::task::spawn_blocking(move || -> Result<String, String> {
                    match mode {
                        Mode::Encrypt => Ok(encode_custom(&input, &password)),
                        Mode::Decrypt => decode_custom(&input, &password)
                            .map_err(|_| "Decryption failed".to_string()),
                    }
                })
                .await
                .expect("Tokio task failed");

                match result {
                    Ok(text) => Ok((text, start.elapsed())),
                    Err(e) => Err(e),
                }
            },
            move |res| Message::UpdateCryptoResult(generation, res),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::InputChanged(action) => {
                match self.mode {
                    Mode::Encrypt => self.plaintext_content.perform(action),
                    Mode::Decrypt => self.ciphertext_content.perform(action),
                }
                return self.perform_crypto();
            }
            Message::PasswordChanged(value) => {
                self.password = value;
                return self.perform_crypto();
            }
            Message::CopyInput => {
                if let Ok(mut clipboard) = Clipboard::new() {
                    let text = match self.mode {
                        Mode::Encrypt => self.plaintext_content.text(),
                        Mode::Decrypt => self.ciphertext_content.text(),
                    };
                    let _ = clipboard.set_text(text);
                }
            }
            Message::PasteInput => {
                if let Ok(mut clipboard) = Clipboard::new() {
                    if let Ok(text) = clipboard.get_text() {
                        match self.mode {
                            Mode::Encrypt => {
                                self.plaintext_content = text_editor::Content::with_text(&text);
                            }
                            Mode::Decrypt => {
                                self.ciphertext_content = text_editor::Content::with_text(&text);
                            }
                        }
                        return self.perform_crypto();
                    }
                }
            }
            Message::CopyOutput => {
                if let Ok(mut clipboard) = Clipboard::new() {
                    let text = match self.mode {
                        Mode::Encrypt => self.ciphertext_content.text(),
                        Mode::Decrypt => self.plaintext_content.text(),
                    };
                    let _ = clipboard.set_text(text);
                }
            }
            Message::ToggleMode => {
                self.mode = match self.mode {
                    Mode::Encrypt => Mode::Decrypt,
                    Mode::Decrypt => Mode::Encrypt,
                };
                return self.perform_crypto();
            }
            Message::Clear => {
                self.plaintext_content = text_editor::Content::new();
                self.ciphertext_content = text_editor::Content::new();
                self.status = "Cleared".to_string();
            }
            Message::SelectFile => {
                self.status = "Selecting input file...".to_string();
                let dialog = if self.mode == Mode::Encrypt {
                    rfd::AsyncFileDialog::new()
                } else {
                    rfd::AsyncFileDialog::new().add_filter("gcy", &["gcy"])
                };

                return Task::perform(
                    async move {
                        dialog
                            .pick_file()
                            .await
                            .map(|handle| handle.path().to_owned())
                    },
                    Message::FileSelected,
                );
            }
            Message::FileSelected(path_opt) => {
                if let Some(in_path) = path_opt {
                    self.status = "Selecting output location...".to_string();
                    let default_name = if self.mode == Mode::Encrypt {
                        format!(
                            "{}.gcy",
                            in_path.file_name().unwrap_or_default().to_string_lossy()
                        )
                    } else {
                        let s = in_path.file_name().unwrap_or_default().to_string_lossy();
                        if s.ends_with(".gcy") {
                            s.trim_end_matches(".gcy").to_string()
                        } else {
                            format!("{}.decrypted", s)
                        }
                    };

                    let dialog = rfd::AsyncFileDialog::new().set_file_name(&default_name);

                    return Task::perform(
                        async move {
                            dialog
                                .save_file()
                                .await
                                .map(|handle| handle.path().to_owned())
                        },
                        move |out| Message::SaveFileSelected(in_path.clone(), out),
                    );
                } else {
                    self.status = "File selection cancelled.".to_string();
                }
            }
            Message::SaveFileSelected(in_path, out_opt) => {
                if let Some(out_path) = out_opt {
                    let password = self.password.clone();
                    let mode = self.mode.clone();

                    self.status = if mode == Mode::Encrypt {
                        "Encrypting..."
                    } else {
                        "Decrypting..."
                    }
                    .to_string();

                    return Task::perform(
                        async move {
                            let start = std::time::Instant::now();
                            match std::fs::read(&in_path) {
                                Ok(bytes) => match mode {
                                    Mode::Encrypt => {
                                        let encrypted_str = encode_custom_bytes(&bytes, &password);
                                        match std::fs::write(&out_path, encrypted_str.as_bytes()) {
                                            Ok(_) => Ok(format!(
                                                "Encrypted to {:?} ({:.2?})",
                                                out_path,
                                                start.elapsed()
                                            )),
                                            Err(e) => Err(format!("Write failed: {e}")),
                                        }
                                    }
                                    Mode::Decrypt => {
                                        let content = String::from_utf8_lossy(&bytes);
                                        match decode_custom_bytes(&content, &password) {
                                            Ok(decrypted_bytes) => {
                                                match std::fs::write(&out_path, decrypted_bytes) {
                                                    Ok(_) => Ok(format!(
                                                        "Decrypted to {:?} ({:.2?})",
                                                        out_path,
                                                        start.elapsed()
                                                    )),
                                                    Err(e) => Err(format!("Write failed: {e}")),
                                                }
                                            }
                                            Err(e) => Err(format!("Decryption error: {e}")),
                                        }
                                    }
                                },
                                Err(e) => Err(format!("Read failed: {e}")),
                            }
                        },
                        Message::OperationComplete,
                    );
                } else {
                    self.status = "Output selection cancelled.".to_string();
                }
            }
            Message::OperationComplete(res) => match res {
                Ok(msg) => self.status = msg,
                Err(e) => self.status = format!("Error: {e}"),
            },
            Message::UpdateCryptoResult(gen_id, result) => {
                if gen_id == self.generation {
                    self.is_loading = false;
                    match result {
                        Ok((text, duration)) => {
                            self.last_duration = Some(duration);
                            match self.mode {
                                Mode::Encrypt => {
                                    self.ciphertext_content = text_editor::Content::with_text(&text)
                                }
                                Mode::Decrypt => {
                                    self.plaintext_content = text_editor::Content::with_text(&text)
                                }
                            }
                        }
                        Err(_) => {
                            self.last_duration = None;
                            // Keep output empty (cleared in perform_crypto)
                        }
                    }
                }
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let (
            input_content,
            output_content,
            input_label,
            output_label,
            input_placeholder,
            output_placeholder,
        ) = match self.mode {
            Mode::Encrypt => (
                &self.plaintext_content,
                &self.ciphertext_content,
                "Plaintext",
                "Encrypted",
                "Enter text to encrypt...",
                if self.is_loading {
                    "Encrypting..."
                } else {
                    "Encrypted output will appear here..."
                },
            ),
            Mode::Decrypt => (
                &self.ciphertext_content,
                &self.plaintext_content,
                "Encrypted",
                "Plaintext",
                "Enter encrypted text to decrypt...",
                if self.is_loading {
                    "Decrypting..."
                } else {
                    "Decrypted output will appear here..."
                },
            ),
        };

        let input_editor = text_editor(input_content)
            .on_action(Message::InputChanged)
            .placeholder(input_placeholder);

        // Output editor is read-only (no on_action to prevent edits)
        let output_editor = text_editor(output_content).placeholder(output_placeholder);

        let password_input = text_input("Password...", &self.password)
            .on_input(Message::PasswordChanged)
            .secure(true)
            .padding(10);

        let top_section = column![
            row![
                text(input_label).size(16),
                button("Copy").on_press(Message::CopyInput),
                button("Paste").on_press(Message::PasteInput),
                button("Select File").on_press(Message::SelectFile),
            ]
            .spacing(10)
            .align_y(iced::Alignment::Center),
            scrollable(input_editor)
        ]
        .spacing(10)
        .width(Length::Fill)
        .height(Length::FillPortion(1));

        let mut copy_btn = button("Copy");
        if !self.is_loading {
            copy_btn = copy_btn.on_press(Message::CopyOutput);
        }

        let bottom_section = column![
            row![text(output_label).size(16), copy_btn]
                .spacing(10)
                .align_y(iced::Alignment::Center),
            scrollable(output_editor)
        ]
        .spacing(10)
        .width(Length::Fill)
        .height(Length::FillPortion(1));

        let toggle_button = button(if self.mode == Mode::Encrypt {
            "Switch to Decrypt"
        } else {
            "Switch to Encrypt"
        })
        .on_press(Message::ToggleMode);

        let clear_button = button("Clear All").on_press(Message::Clear);

        let content = column![
            container(text("GenCrypt").size(24)).center_x(Length::Fill),
            container(toggle_button).center_x(Length::Fill).padding(5),
            container(password_input).width(Length::Fill).padding(5),
            top_section,
            bottom_section,
            container(clear_button).center_x(Length::Fill).padding(5),
            row![
                text(&self.status).size(14),
                Space::new().width(Length::Fill),
                text(if let Some(d) = self.last_duration {
                    format!("Time: {:?}", d)
                } else {
                    String::new()
                })
                .size(12)
            ]
            .width(Length::Fill)
            .align_y(iced::Alignment::Center)
            .padding(5),
        ]
        .spacing(20)
        .padding(20)
        .width(Length::Fill)
        .height(Length::Fill);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
}

fn main() -> iced::Result {
    let mut input_path: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut decrypt_mode = false;

    let mut password = String::new();
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--password" => {
                if let Some(p) = args.next() {
                    password = p;
                } else {
                    eprintln!("Error: --password requires a value");
                    std::process::exit(1);
                }
            }
            "--input" => {
                if let Some(path) = args.next() {
                    input_path = Some(path);
                } else {
                    eprintln!("Error: --input requires a filepath");
                    std::process::exit(1);
                }
            }
            "--output" => {
                if let Some(path) = args.next() {
                    output_path = Some(path);
                } else {
                    eprintln!("Error: --output requires a filepath");
                    std::process::exit(1);
                }
            }
            "--decrypt" => {
                decrypt_mode = true;
            }
            other if other.starts_with('-') => {
                eprintln!("Unknown option: {other}");
                std::process::exit(1);
            }
            _ => {}
        }
    }

    if let Some(in_path) = input_path {
        // CLI mode
        let in_path_p = Path::new(&in_path);
        let input_bytes = match fs::read(&in_path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("Failed to read input file: {e}");
                std::process::exit(1);
            }
        };
        let result = if decrypt_mode {
            // Base64 input: decode to Vec<u8> (raw)
            let input_str = String::from_utf8_lossy(&input_bytes);
            match decode_custom_bytes(&input_str, &password) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Decryption error: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            // Raw bytes to encoded base64
            encode_custom_bytes(&input_bytes, &password).into_bytes()
        };

        // Determine output filename
        let out_path = if let Some(out) = output_path {
            out
        } else if decrypt_mode {
            // Remove .gcy extension if present
            let fname = match in_path_p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.strip_suffix(".gcy").unwrap_or(n),
                None => "output",
            };
            let out_path_buf = in_path_p.with_file_name(fname);
            out_path_buf.to_string_lossy().to_string()
        } else {
            // Encrypt mode: append .gcy
            let fname = match in_path_p.file_name().and_then(|n| n.to_str()) {
                Some(n) => format!("{n}.gcy"),
                None => "output.gcy".to_string(),
            };
            let out_path_buf = in_path_p.with_file_name(fname);
            out_path_buf.to_string_lossy().to_string()
        };

        if let Err(e) = fs::write(&out_path, &result) {
            eprintln!("Failed to write output file: {e}");
            std::process::exit(1);
        }
        println!(
            "{} complete: {} → {}",
            if decrypt_mode {
                "Decryption"
            } else {
                "Encryption"
            },
            in_path,
            out_path
        );
        std::process::exit(0);
    }

    // GUI mode as default
    iced::run(App::update, App::view)
}
