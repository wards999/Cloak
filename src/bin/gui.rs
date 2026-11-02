//! cloak-gui — a password-protected drive manager (VeraCrypt-ish, much simpler).
//!
//! Home shows a remembered list of your drives; pick one and unlock it, or
//! create/open another. An open drive gives an in-process file browser (no
//! driver needed) and an optional "Mount as a drive" section (needs FUSE/WinFsp).
//! The password is held only while a drive is open and cleared on close.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("cloak-gui requires `--features gui`.");
    std::process::exit(1);
}

#[cfg(feature = "gui")]
fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([600.0, 540.0])
            .with_min_inner_size([460.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "cloak",
        options,
        Box::new(|cc| {
            imp::setup_style(&cc.egui_ctx);
            Ok(Box::new(imp::CloakGui::default()))
        }),
    )
}

#[cfg(feature = "gui")]
mod imp {
    use cloak::Store;
    use eframe::egui::{self, Color32, RichText};
    use serde::{Deserialize, Serialize};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};

    const REGION: u64 = 64 * 1024;
    const ACCENT: Color32 = Color32::from_rgb(123, 108, 246);
    const BG: Color32 = Color32::from_rgb(15, 17, 22);
    const PANEL: Color32 = Color32::from_rgb(26, 29, 36);
    const BORDER: Color32 = Color32::from_rgb(42, 46, 56);
    const TEXT: Color32 = Color32::from_rgb(231, 233, 238);
    const MUTED: Color32 = Color32::from_rgb(150, 156, 168);
    const OK_GREEN: Color32 = Color32::from_rgb(74, 200, 130);
    const ERR_RED: Color32 = Color32::from_rgb(235, 110, 110);

    /// Apply a clean dark theme: accent color, rounded widgets, roomy spacing,
    /// slightly larger type.
    pub fn setup_style(ctx: &egui::Context) {
        use egui::{FontFamily, FontId, Rounding, Stroke, TextStyle};

        let mut style = (*ctx.style()).clone();
        let mut v = egui::Visuals::dark();
        v.panel_fill = BG;
        v.window_fill = PANEL;
        v.extreme_bg_color = Color32::from_rgb(12, 13, 17);
        v.override_text_color = Some(TEXT);
        v.selection.bg_fill = ACCENT.linear_multiply(0.45_f32);
        v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
        v.hyperlink_color = ACCENT;
        v.window_stroke = Stroke::new(1.0_f32, BORDER);

        let rounding = Rounding::same(9.0_f32);
        for w in [
            &mut v.widgets.noninteractive,
            &mut v.widgets.inactive,
            &mut v.widgets.hovered,
            &mut v.widgets.active,
            &mut v.widgets.open,
        ] {
            w.rounding = rounding;
        }
        v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
        v.widgets.inactive.bg_fill = PANEL;
        v.widgets.inactive.weak_bg_fill = PANEL;
        v.widgets.hovered.bg_fill = Color32::from_rgb(36, 40, 49);
        v.widgets.hovered.weak_bg_fill = Color32::from_rgb(36, 40, 49);
        v.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, ACCENT);
        v.widgets.active.bg_fill = Color32::from_rgb(40, 44, 54);
        v.window_rounding = Rounding::same(12.0_f32);
        style.visuals = v;

        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.text_styles = [
            (TextStyle::Heading, FontId::new(28.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(15.0, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(15.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
            (TextStyle::Small, FontId::new(12.5, FontFamily::Proportional)),
        ]
        .into();
        ctx.set_style(style);
    }

    // ---- adapter / platform helpers -------------------------------------

    fn adapter_name() -> &'static str {
        if cfg!(windows) {
            "cloak-winmount.exe"
        } else {
            "cloak-mount"
        }
    }

    fn locate_adapter() -> PathBuf {
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let c = dir.join(adapter_name());
                if c.exists() {
                    return c;
                }
            }
        }
        PathBuf::from(adapter_name())
    }

    fn default_mount_point() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        format!("{home}/cloak-mnt")
    }

    fn free_drive_letters() -> Vec<String> {
        #[cfg(windows)]
        {
            ('D'..='Z')
                .filter(|c| !std::path::Path::new(&format!("{c}:\\")).exists())
                .map(|c| format!("{c}:"))
                .collect()
        }
        #[cfg(not(windows))]
        {
            Vec::new()
        }
    }

    fn human_size(n: u64) -> String {
        const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
        let mut v = n as f64;
        let mut i = 0;
        while v >= 1024.0 && i < U.len() - 1 {
            v /= 1024.0;
            i += 1;
        }
        if i == 0 {
            format!("{n} B")
        } else {
            format!("{v:.1} {}", U[i])
        }
    }

    fn join(dir: &str, name: &str) -> String {
        if dir.is_empty() {
            name.to_string()
        } else {
            format!("{dir}/{name}")
        }
    }

    fn parent_of(path: &str) -> String {
        match path.rfind('/') {
            Some(i) => path[..i].to_string(),
            None => String::new(),
        }
    }

    fn basename(path: &str) -> String {
        PathBuf::from(path)
            .file_name()
            .and_then(|s| s.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| path.to_owned())
    }

    // ---- remembered drive list ------------------------------------------

    #[derive(Clone, Serialize, Deserialize)]
    struct DriveEntry {
        name: String,
        path: String,
    }

    fn config_path() -> Option<PathBuf> {
        let base = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
        Some(PathBuf::from(base).join(".cloak").join("drives.json"))
    }

    fn load_recents() -> Vec<DriveEntry> {
        config_path()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_recents(recents: &[DriveEntry]) {
        if let Some(p) = config_path() {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(json) = serde_json::to_vec_pretty(recents) {
                let _ = std::fs::write(p, json);
            }
        }
    }

    #[derive(PartialEq, Eq)]
    enum Screen {
        Home,
        Create,
        Open,
        Drive,
    }

    pub struct CloakGui {
        screen: Screen,
        location: String,
        password: String,
        confirm: String,
        msg: String,
        recents: Vec<DriveEntry>,

        opened: Option<Store>,

        cwd: String,
        entries: Vec<(String, bool, u64)>,
        selected: Option<String>,
        new_folder: String,
        rename_to: String,

        mount_point: String,
        child: Option<Child>,
        drive_letters: Vec<String>,
        mount_status: String,
    }

    impl Default for CloakGui {
        fn default() -> Self {
            let drive_letters = free_drive_letters();
            let mount_point = if cfg!(windows) {
                drive_letters
                    .iter()
                    .find(|d| d.as_str() == "X:")
                    .or_else(|| drive_letters.first())
                    .cloned()
                    .unwrap_or_else(|| "X:".to_string())
            } else {
                default_mount_point()
            };
            Self {
                screen: Screen::Home,
                location: String::new(),
                password: String::new(),
                confirm: String::new(),
                msg: String::new(),
                recents: load_recents(),
                opened: None,
                cwd: String::new(),
                entries: Vec::new(),
                selected: None,
                new_folder: String::new(),
                rename_to: String::new(),
                mount_point,
                child: None,
                drive_letters,
                mount_status: String::new(),
            }
        }
    }

    impl CloakGui {
        fn reset_inputs(&mut self) {
            self.location.clear();
            self.password.clear();
            self.confirm.clear();
            self.msg.clear();
        }

        fn remember(&mut self) {
            let path = self.location.clone();
            let name = basename(&path);
            self.recents.retain(|d| d.path != path);
            self.recents.insert(0, DriveEntry { name, path });
            self.recents.truncate(8);
            save_recents(&self.recents);
        }

        fn create_drive(&mut self) {
            if self.location.trim().is_empty() {
                self.msg = "Choose a location for the drive.".into();
                return;
            }
            if self.password.is_empty() {
                self.msg = "Enter a password.".into();
                return;
            }
            if self.password != self.confirm {
                self.msg = "Passwords don't match.".into();
                return;
            }
            match Store::create_with_passphrase(&self.location, &self.password, REGION) {
                Ok(store) => {
                    self.opened = Some(store);
                    self.cwd.clear();
                    self.selected = None;
                    self.confirm.clear();
                    self.msg.clear();
                    self.mount_status.clear();
                    self.remember();
                    self.screen = Screen::Drive;
                    self.refresh();
                }
                Err(e) => self.msg = format!("Couldn't create drive: {e}"),
            }
        }

        fn open_drive(&mut self) {
            if self.location.trim().is_empty() {
                self.msg = "Choose the drive location.".into();
                return;
            }
            if self.password.is_empty() {
                self.msg = "Enter the password.".into();
                return;
            }
            match Store::open_with_passphrase(&self.location, &self.password) {
                Ok(store) => {
                    self.opened = Some(store);
                    self.cwd.clear();
                    self.selected = None;
                    self.msg.clear();
                    self.mount_status.clear();
                    self.remember();
                    self.screen = Screen::Drive;
                    self.refresh();
                }
                Err(e) => self.msg = format!("{e}"),
            }
        }

        fn close_drive(&mut self) {
            self.unmount();
            self.opened = None;
            self.entries.clear();
            self.selected = None;
            self.cwd.clear();
            self.password.clear();
            self.confirm.clear();
            self.msg.clear();
            self.screen = Screen::Home;
        }

        fn refresh(&mut self) {
            let cwd = self.cwd.clone();
            let mut list = match &self.opened {
                Some(s) => s.list_dir(&cwd).unwrap_or_default(),
                None => Vec::new(),
            };
            list.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.to_lowercase().cmp(&b.0.to_lowercase())));
            self.entries = list;
        }

        fn navigate_into(&mut self, name: &str) {
            self.cwd = join(&self.cwd, name);
            self.selected = None;
            self.refresh();
        }

        fn navigate_up(&mut self) {
            self.cwd = parent_of(&self.cwd);
            self.selected = None;
            self.refresh();
        }

        fn import_file(&mut self, src: PathBuf) {
            let cwd = self.cwd.clone();
            let Some(name) = src.file_name().and_then(|s| s.to_str()).map(str::to_owned) else {
                self.msg = "Bad source filename.".into();
                return;
            };
            let data = match std::fs::read(&src) {
                Ok(d) => d,
                Err(e) => {
                    self.msg = format!("Read failed: {e}");
                    return;
                }
            };
            let path = join(&cwd, &name);
            let result = self.opened.as_mut().map(|s| {
                s.create(&path)?;
                s.write_at(&path, 0, &data)
            });
            match result {
                Some(Ok(())) => {
                    self.msg = format!("Imported {name}");
                    self.refresh();
                }
                Some(Err(e)) => self.msg = format!("Import failed: {e}"),
                None => {}
            }
        }

        fn make_folder(&mut self) {
            let name = self.new_folder.trim().to_string();
            if name.is_empty() {
                return;
            }
            let path = join(&self.cwd, &name);
            match self.opened.as_mut().map(|s| s.mkdir(&path)) {
                Some(Ok(())) => {
                    self.new_folder.clear();
                    self.msg = format!("Created folder {name}");
                    self.refresh();
                }
                Some(Err(e)) => self.msg = format!("mkdir failed: {e}"),
                None => {}
            }
        }

        fn extract_selected(&mut self, dest: PathBuf) {
            let Some(name) = self.selected.clone() else {
                return;
            };
            let path = join(&self.cwd, &name);
            match self.opened.as_ref().map(|s| s.read_all(&path)) {
                Some(Ok(bytes)) => match std::fs::write(&dest, bytes) {
                    Ok(()) => self.msg = format!("Extracted to {}", dest.display()),
                    Err(e) => self.msg = format!("Write failed: {e}"),
                },
                Some(Err(e)) => self.msg = format!("Extract failed: {e}"),
                None => {}
            }
        }

        fn delete_selected(&mut self) {
            let Some(name) = self.selected.clone() else {
                return;
            };
            let path = join(&self.cwd, &name);
            match self.opened.as_mut().map(|s| s.remove(&path)) {
                Some(Ok(())) => {
                    self.selected = None;
                    self.msg = format!("Deleted {name}");
                    self.refresh();
                }
                Some(Err(e)) => self.msg = format!("Delete failed: {e}"),
                None => {}
            }
        }

        fn rename_selected(&mut self) {
            let Some(name) = self.selected.clone() else {
                return;
            };
            let new = self.rename_to.trim().to_string();
            if new.is_empty() {
                return;
            }
            let old_path = join(&self.cwd, &name);
            let new_path = join(&self.cwd, &new);
            match self.opened.as_mut().map(|s| s.rename_path(&old_path, &new_path)) {
                Some(Ok(())) => {
                    self.selected = Some(new.clone());
                    self.rename_to.clear();
                    self.msg = format!("Renamed to {new}");
                    self.refresh();
                }
                Some(Err(e)) => self.msg = format!("Rename failed: {e}"),
                None => {}
            }
        }

        fn is_mounted(&self) -> bool {
            self.child.is_some()
        }

        fn mount(&mut self) {
            let adapter = locate_adapter();
            let spawn = Command::new(&adapter)
                .arg(&self.location)
                .arg(&self.mount_point)
                .env("CLOAK_PASSPHRASE", &self.password)
                .stdin(Stdio::piped())
                .spawn();
            match spawn {
                Ok(child) => {
                    self.child = Some(child);
                    self.mount_status = format!("Mounted at {}", self.mount_point);
                }
                Err(e) => {
                    self.mount_status = format!(
                        "Couldn't launch {} ({e}). Is the mount driver/adapter installed?",
                        adapter.display()
                    )
                }
            }
        }

        fn unmount(&mut self) {
            if let Some(mut child) = self.child.take() {
                // Closing stdin asks the adapter to unmount and save its
                // pending changes; give it a few seconds before forcing it.
                drop(child.stdin.take());
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while matches!(child.try_wait(), Ok(None)) && std::time::Instant::now() < deadline {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                let _ = child.kill();
                let _ = child.wait();
                self.mount_status = "Unmounted.".into();
            }
        }
    }

    impl eframe::App for CloakGui {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            if let Some(store) = self.opened.as_mut() {
                // Save list changes made while browsing; errors resurface on
                // the next save.
                let _ = store.tick();
            }
            egui::CentralPanel::default().show(ctx, |ui| {
                // Centered, fixed-width content column for a modern app feel.
                let full = ui.available_width();
                let w = full.min(470.0);
                let pad = ((full - w) * 0.5).max(0.0);
                ui.horizontal(|ui| {
                    ui.add_space(pad);
                    ui.vertical(|ui| {
                        ui.set_width(w);
                        match self.screen {
                            Screen::Home => self.home_ui(ui),
                            Screen::Create => self.create_ui(ui),
                            Screen::Open => self.open_ui(ui),
                            Screen::Drive => self.drive_ui(ui),
                        }
                    });
                });
            });
        }

        fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
            self.unmount();
        }
    }

    impl CloakGui {
        fn header(&self, ui: &mut egui::Ui, subtitle: &str) {
            ui.add_space(18.0);
            ui.heading(RichText::new("cloak").color(ACCENT).strong());
            ui.add_space(2.0);
            ui.label(RichText::new(subtitle).color(MUTED));
            ui.add_space(16.0);
        }

        fn home_ui(&mut self, ui: &mut egui::Ui) {
            self.header(ui, "Encrypted drives, unlocked by a password.");

            if !self.recents.is_empty() {
                ui.label(RichText::new("Your drives").strong());
                ui.add_space(4.0);
                let recents = self.recents.clone();
                let mut open_path: Option<String> = None;
                let mut forget: Option<String> = None;
                egui::Frame::none()
                    .fill(PANEL)
                    .stroke(egui::Stroke::new(1.0, BORDER))
                    .rounding(10.0)
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        for (i, d) in recents.iter().enumerate() {
                            if i > 0 {
                                ui.separator();
                            }
                            ui.horizontal(|ui| {
                                if ui.button("Unlock").clicked() {
                                    open_path = Some(d.path.clone());
                                }
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(&d.name).strong());
                                    ui.label(RichText::new(&d.path).weak().small());
                                });
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.small_button("remove").clicked() {
                                            forget = Some(d.path.clone());
                                        }
                                    },
                                );
                            });
                        }
                    });
                if let Some(path) = open_path {
                    self.reset_inputs();
                    self.location = path;
                    self.screen = Screen::Open;
                }
                if let Some(path) = forget {
                    self.recents.retain(|d| d.path != path);
                    save_recents(&self.recents);
                }
                ui.add_space(14.0);
            }

            ui.horizontal(|ui| {
                if ui
                    .add_sized([190.0, 38.0], egui::Button::new("Create new drive").fill(ACCENT))
                    .clicked()
                {
                    self.reset_inputs();
                    self.screen = Screen::Create;
                }
                if ui
                    .add_sized([150.0, 38.0], egui::Button::new("Open other…"))
                    .clicked()
                {
                    self.reset_inputs();
                    self.screen = Screen::Open;
                }
            });
        }

        fn location_row(&mut self, ui: &mut egui::Ui, hint: &str) {
            ui.label("Location");
            ui.add(egui::TextEdit::singleline(&mut self.location).hint_text(hint).desired_width(260.0));
            if ui.button("Choose…").clicked() {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    self.location = dir.display().to_string();
                }
            }
            ui.end_row();
        }

        fn create_ui(&mut self, ui: &mut egui::Ui) {
            self.header(ui, "Create a new encrypted drive.");
            egui::Grid::new("create").num_columns(3).spacing([8.0, 10.0]).show(ui, |ui| {
                self.location_row(ui, "empty folder to hold the new drive");
                ui.label("Password");
                ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(260.0));
                ui.label("");
                ui.end_row();
                ui.label("Confirm");
                ui.add(egui::TextEdit::singleline(&mut self.confirm).password(true).desired_width(260.0));
                ui.label("");
                ui.end_row();
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new("Create drive").fill(ACCENT)).clicked() {
                    self.create_drive();
                }
                if ui.button("Back").clicked() {
                    self.reset_inputs();
                    self.screen = Screen::Home;
                }
            });
            self.msg_line(ui);
        }

        fn open_ui(&mut self, ui: &mut egui::Ui) {
            self.header(ui, "Unlock an existing drive.");
            egui::Grid::new("open").num_columns(3).spacing([8.0, 10.0]).show(ui, |ui| {
                self.location_row(ui, "folder of an existing drive");
                ui.label("Password");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.password)
                        .password(true)
                        .desired_width(260.0),
                );
                // Enter in the password field unlocks.
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    self.open_drive();
                }
                ui.label("");
                ui.end_row();
            });
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new("Unlock").fill(ACCENT)).clicked() {
                    self.open_drive();
                }
                if ui.button("Back").clicked() {
                    self.reset_inputs();
                    self.screen = Screen::Home;
                }
            });
            self.msg_line(ui);
        }

        fn msg_line(&self, ui: &mut egui::Ui) {
            if !self.msg.is_empty() {
                ui.add_space(8.0);
                ui.colored_label(ERR_RED, &self.msg);
            }
        }

        fn drive_ui(&mut self, ui: &mut egui::Ui) {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new(basename(&self.location)).color(ACCENT).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Close drive").clicked() {
                        self.close_drive();
                    }
                });
            });
            if self.screen != Screen::Drive {
                return; // closed
            }
            ui.label(RichText::new(&self.location).weak().small());
            ui.add_space(8.0);
            ui.separator();
            self.browse_section(ui);
            ui.add_space(6.0);
            egui::CollapsingHeader::new("Mount as a drive")
                .default_open(false)
                .show(ui, |ui| self.mount_section(ui));
        }

        fn browse_section(&mut self, ui: &mut egui::Ui) {
            ui.horizontal(|ui| {
                if ui.add_enabled(!self.cwd.is_empty(), egui::Button::new("⬆ Up")).clicked() {
                    self.navigate_up();
                }
                let crumb = if self.cwd.is_empty() { "/" } else { self.cwd.as_str() };
                ui.monospace(crumb);
            });
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new("Import file…").fill(ACCENT)).clicked() {
                    if let Some(src) = rfd::FileDialog::new().pick_file() {
                        self.import_file(src);
                    }
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_folder)
                        .desired_width(130.0)
                        .hint_text("new folder"),
                );
                if ui.button("Create folder").clicked() {
                    self.make_folder();
                }
            });

            ui.add_space(4.0);
            egui::Frame::none().fill(PANEL).stroke(egui::Stroke::new(1.0, BORDER)).rounding(10.0).inner_margin(10.0).show(ui, |ui| {
                let entries = self.entries.clone();
                let mut navigate: Option<String> = None;
                egui::ScrollArea::vertical().max_height(210.0).auto_shrink([false, false]).show(
                    ui,
                    |ui| {
                        if entries.is_empty() {
                            ui.weak("(empty)");
                        }
                        for (name, is_dir, size) in &entries {
                            ui.horizontal(|ui| {
                                let selected = self.selected.as_deref() == Some(name.as_str());
                                let label = if *is_dir {
                                    RichText::new(format!("{name}/")).strong()
                                } else {
                                    RichText::new(name)
                                };
                                if ui.selectable_label(selected, label).clicked() {
                                    self.selected = Some(name.clone());
                                }
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if *is_dir {
                                            if ui.small_button("open").clicked() {
                                                navigate = Some(name.clone());
                                            }
                                        } else {
                                            ui.weak(human_size(*size));
                                        }
                                    },
                                );
                            });
                        }
                    },
                );
                if let Some(n) = navigate {
                    self.navigate_into(&n);
                }
            });

            ui.add_space(6.0);
            let sel = self.selected.clone();
            let is_file = sel
                .as_ref()
                .and_then(|n| self.entries.iter().find(|(name, _, _)| name == n))
                .map(|(_, is_dir, _)| !*is_dir)
                .unwrap_or(false);
            let has_sel = sel.is_some();
            ui.horizontal(|ui| {
                if ui.add_enabled(is_file, egui::Button::new("Extract…")).clicked() {
                    if let Some(name) = &sel {
                        if let Some(dest) = rfd::FileDialog::new().set_file_name(name).save_file() {
                            self.extract_selected(dest);
                        }
                    }
                }
                if ui.add_enabled(has_sel, egui::Button::new("Delete")).clicked() {
                    self.delete_selected();
                }
                ui.add_enabled(
                    has_sel,
                    egui::TextEdit::singleline(&mut self.rename_to)
                        .desired_width(130.0)
                        .hint_text("rename to"),
                );
                if ui.add_enabled(has_sel, egui::Button::new("Rename")).clicked() {
                    self.rename_selected();
                }
            });

            if !self.msg.is_empty() {
                ui.add_space(4.0);
                let color = if self.msg.contains("failed") || self.msg.contains("Couldn't") {
                    ERR_RED
                } else {
                    OK_GREEN
                };
                ui.colored_label(color, &self.msg);
            }
        }

        fn mount_section(&mut self, ui: &mut egui::Ui) {
            let mounted = self.is_mounted();
            ui.horizontal(|ui| {
                ui.label("Mount point");
                if cfg!(windows) {
                    let letters = self.drive_letters.clone();
                    ui.add_enabled_ui(!mounted, |ui| {
                        egui::ComboBox::from_id_source("drive_letter")
                            .selected_text(if self.mount_point.is_empty() {
                                "(choose)".to_owned()
                            } else {
                                self.mount_point.clone()
                            })
                            .show_ui(ui, |ui| {
                                for d in &letters {
                                    ui.selectable_value(&mut self.mount_point, d.clone(), d);
                                }
                            });
                    });
                    if ui.add_enabled(!mounted, egui::Button::new("Refresh")).clicked() {
                        self.drive_letters = free_drive_letters();
                    }
                } else {
                    ui.add_enabled(
                        !mounted,
                        egui::TextEdit::singleline(&mut self.mount_point).hint_text("/path/to/mnt"),
                    );
                }
            });
            ui.horizontal(|ui| {
                if ui.add_enabled(!mounted, egui::Button::new("Mount").fill(ACCENT)).clicked() {
                    self.mount();
                }
                if ui.add_enabled(mounted, egui::Button::new("Unmount")).clicked() {
                    self.unmount();
                }
            });
            if !self.mount_status.is_empty() {
                ui.add_space(4.0);
                let color = if self.mount_status.starts_with("Mounted") {
                    OK_GREEN
                } else if self.mount_status.starts_with("Couldn't") {
                    ERR_RED
                } else {
                    Color32::GRAY
                };
                ui.colored_label(color, &self.mount_status);
            }
            ui.add_space(2.0);
            ui.small("Mounting needs the FUSE/WinFsp driver. Browsing above needs nothing.");
        }
    }
}
