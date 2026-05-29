#![windows_subsystem = "windows"]

mod crypto;

use arboard::Clipboard;
use iced::futures::SinkExt;
use iced::widget::{
    Space, button, column, container, progress_bar, row, scrollable, text, text_editor, text_input,
};
use iced::{Element, Length, Task};
use mimalloc::MiMalloc;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{decode_custom, decode_custom_bytes, encode_custom, encode_custom_bytes};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

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
    FileSelected(Option<PathBuf>),
    SaveFileSelected(PathBuf, Option<PathBuf>),
    FileOperationUpdate(u64, FileOperationEvent),
    UpdateCryptoResult(u64, Result<(String, std::time::Duration), String>),
    GeneratePassword,
    CopyPassword,
}

#[derive(Debug, Clone)]
pub enum FileOperationEvent {
    Progress(f32),
    Finished(Result<String, String>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
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
    file_generation: u64,
    file_progress: Option<f32>,
    is_file_processing: bool,
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
            file_generation: 0,
            file_progress: None,
            is_file_processing: false,
        }
    }
}

fn validate_password(password: &str) -> Result<(), &'static str> {
    if password.len() <= 10 {
        return Err("Password must be > 10 chars");
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_number = false;
    let mut has_special = false;

    for c in password.chars() {
        if c.is_uppercase() {
            has_upper = true;
        } else if c.is_lowercase() {
            has_lower = true;
        } else if c.is_numeric() {
            has_number = true;
        } else {
            has_special = true;
        }
    }

    if !has_upper {
        return Err("Password needs uppercase");
    }
    if !has_lower {
        return Err("Password needs lowercase");
    }
    if !has_number {
        return Err("Password needs number");
    }
    if !has_special {
        return Err("Password needs special char");
    }

    Ok(())
}

fn generate_secure_password() -> String {
    use rand::TryRng;
    let mut rng = rand::rngs::SysRng;
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";

    loop {
        let password: String = (0..20)
            .map(|_| {
                let zone = usize::MAX - (usize::MAX % CHARSET.len());
                loop {
                    let value = rng
                        .try_next_u64()
                        .expect("system random number generation failed")
                        as usize;
                    if value < zone {
                        break CHARSET[value % CHARSET.len()] as char;
                    }
                }
            })
            .collect();

        if validate_password(&password).is_ok() {
            return password;
        }
    }
}

fn file_operation_task(
    generation: u64,
    in_path: PathBuf,
    out_path: PathBuf,
    password: String,
    mode: Mode,
) -> Task<Message> {
    Task::run(
        iced::stream::channel(16, async move |mut output| {
            let start = std::time::Instant::now();
            let _ = output.send(FileOperationEvent::Progress(2.0)).await;

            let read_path = in_path.clone();
            let bytes = match tokio::task::spawn_blocking(move || std::fs::read(read_path)).await {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(e)) => {
                    let _ = output
                        .send(FileOperationEvent::Finished(Err(format!(
                            "Read failed: {e}"
                        ))))
                        .await;
                    return;
                }
                Err(e) => {
                    let _ = output
                        .send(FileOperationEvent::Finished(Err(format!(
                            "Read task failed: {e}"
                        ))))
                        .await;
                    return;
                }
            };
            let _ = output.send(FileOperationEvent::Progress(25.0)).await;

            let processed = match tokio::task::spawn_blocking(move || -> Result<Vec<u8>, String> {
                match mode {
                    Mode::Encrypt => Ok(encode_custom_bytes(&bytes, &password).into_bytes()),
                    Mode::Decrypt => {
                        let content = String::from_utf8_lossy(&bytes);
                        decode_custom_bytes(&content, &password)
                            .map_err(|e| format!("Decryption error: {e}"))
                    }
                }
            })
            .await
            {
                Ok(Ok(processed)) => processed,
                Ok(Err(e)) => {
                    let _ = output.send(FileOperationEvent::Finished(Err(e))).await;
                    return;
                }
                Err(e) => {
                    let _ = output
                        .send(FileOperationEvent::Finished(Err(format!(
                            "Crypto task failed: {e}"
                        ))))
                        .await;
                    return;
                }
            };
            let _ = output.send(FileOperationEvent::Progress(85.0)).await;

            let write_path = out_path.clone();
            match tokio::task::spawn_blocking(move || std::fs::write(write_path, processed)).await {
                Ok(Ok(())) => {
                    let _ = output.send(FileOperationEvent::Progress(100.0)).await;
                    let action = if mode == Mode::Encrypt {
                        "Encrypted"
                    } else {
                        "Decrypted"
                    };
                    let _ = output
                        .send(FileOperationEvent::Finished(Ok(format!(
                            "{action} to {:?} ({:.2?})",
                            out_path,
                            start.elapsed()
                        ))))
                        .await;
                }
                Ok(Err(e)) => {
                    let _ = output
                        .send(FileOperationEvent::Finished(Err(format!(
                            "Write failed: {e}"
                        ))))
                        .await;
                }
                Err(e) => {
                    let _ = output
                        .send(FileOperationEvent::Finished(Err(format!(
                            "Write task failed: {e}"
                        ))))
                        .await;
                }
            }
        }),
        move |event| Message::FileOperationUpdate(generation, event),
    )
}

impl App {
    fn perform_crypto(&mut self) -> Task<Message> {
        self.is_loading = true;
        self.last_duration = None;
        self.generation += 1;
        let generation = self.generation;

        let mode = self.mode;
        let password = self.password.clone();
        let input = match mode {
            Mode::Encrypt => self.plaintext_content.text(),
            Mode::Decrypt => self.ciphertext_content.text(),
        };

        if let Err(e) = validate_password(&password) {
            self.status = format!("Invalid Password: {}", e);
            self.is_loading = false;
            match mode {
                Mode::Encrypt => self.ciphertext_content = text_editor::Content::new(),
                Mode::Decrypt => self.plaintext_content = text_editor::Content::new(),
            }
            return Task::none();
        }

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
                if let Ok(mut clipboard) = Clipboard::new()
                    && let Ok(text) = clipboard.get_text()
                {
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
                self.file_progress = None;
                self.is_file_processing = false;
                self.status = "Cleared".to_string();
            }
            Message::SelectFile => {
                self.file_progress = None;
                self.is_file_processing = false;
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
                    self.file_progress = None;
                    self.is_file_processing = false;
                }
            }
            Message::SaveFileSelected(in_path, out_opt) => {
                if let Some(out_path) = out_opt {
                    let password = self.password.clone();

                    if let Err(e) = validate_password(&password) {
                        self.status = format!("Cannot process file: Invalid Password ({})", e);
                        return Task::none();
                    }

                    let mode = self.mode;
                    self.file_generation += 1;
                    let file_generation = self.file_generation;
                    self.file_progress = Some(0.0);
                    self.is_file_processing = true;

                    self.status = if mode == Mode::Encrypt {
                        "Encrypting..."
                    } else {
                        "Decrypting..."
                    }
                    .to_string();

                    return file_operation_task(file_generation, in_path, out_path, password, mode);
                } else {
                    self.status = "Output selection cancelled.".to_string();
                    self.file_progress = None;
                    self.is_file_processing = false;
                }
            }
            Message::FileOperationUpdate(gen_id, event) => {
                if gen_id == self.file_generation {
                    match event {
                        FileOperationEvent::Progress(progress) => {
                            self.file_progress = Some(progress);
                        }
                        FileOperationEvent::Finished(res) => {
                            self.is_file_processing = false;
                            match res {
                                Ok(msg) => {
                                    self.file_progress = Some(100.0);
                                    self.status = msg;
                                }
                                Err(e) => {
                                    self.file_progress = None;
                                    self.status = format!("Error: {e}");
                                }
                            }
                        }
                    }
                }
            }
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
            Message::GeneratePassword => {
                self.password = generate_secure_password();
                return self.perform_crypto();
            }
            Message::CopyPassword => {
                if let Ok(mut clipboard) = Clipboard::new() {
                    let _ = clipboard.set_text(self.password.clone());
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

        let password_row = row![
            password_input,
            button("Generate").on_press(Message::GeneratePassword),
            button("Copy").on_press(Message::CopyPassword),
        ]
        .spacing(10);

        let mut select_file_button = button("Select File");
        if !self.is_file_processing {
            select_file_button = select_file_button.on_press(Message::SelectFile);
        }

        let top_section = column![
            row![
                text(input_label).size(16),
                button("Copy").on_press(Message::CopyInput),
                button("Paste").on_press(Message::PasteInput),
                select_file_button,
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
        let status_row = row![
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
        .padding(5);

        let mut status_section = column![status_row].spacing(6).width(Length::Fill);
        if let Some(progress) = self.file_progress {
            status_section = status_section.push(
                progress_bar(0.0..=100.0, progress)
                    .girth(8)
                    .length(Length::Fill),
            );
        }

        let content = column![
            container(text("GenCrypt").size(24)).center_x(Length::Fill),
            container(toggle_button).center_x(Length::Fill).padding(5),
            container(password_row).width(Length::Fill).padding(5),
            top_section,
            bottom_section,
            container(clear_button).center_x(Length::Fill).padding(5),
            status_section,
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
