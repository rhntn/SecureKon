use crate::{install, model::*, platform as p};
use anyhow::Result;
use eframe::egui::{self, Color32, Pos2, Rect, RichText, Stroke, Vec2};
use std::{
    collections::HashMap,
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};
const BG: Color32 = Color32::from_rgb(16, 21, 31);
const ACCENT: Color32 = Color32::from_rgb(104, 224, 188);
struct App {
    lang: String,
    strings: HashMap<String, Vec<String>>,
    setup: bool,
    installed: bool,
    enabled: bool,
    provider: usize,
    url: String,
    ip4: [String; 2],
    ip6: [String; 2],
    status: String,
    error: bool,
    busy: Option<Receiver<std::result::Result<String, String>>>,
    about: bool,
    remove: bool,
    last_poll: Instant,
}
impl App {
    fn new(setup: bool, remove: bool) -> Self {
        let conf = p::config();
        let error = !setup && conf.is_err();
        let status = if error {
            format!("{}", conf.as_ref().unwrap_err())
        } else {
            "Hazır".into()
        };
        let c = conf.unwrap_or_else(|_| presets()[0].clone());
        let provider = presets().iter().position(|x| x == &c).unwrap_or(3);
        let mut s = Self {
            lang: p::load_language(),
            strings: serde_json::from_str(include_str!("../assets/translations.json"))
                .expect("translation asset"),
            setup,
            installed: false,
            enabled: p::startup_enabled().unwrap_or(false),
            provider,
            url: String::new(),
            ip4: Default::default(),
            ip6: Default::default(),
            status,
            error,
            busy: None,
            about: false,
            remove,
            last_poll: Instant::now(),
        };
        s.fill(c);
        s
    }
    fn t(&self, k: &str) -> String {
        let i = match self.lang.as_str() {
            "en" => Some(0),
            "de" => Some(1),
            "zh" => Some(2),
            _ => None,
        };
        i.and_then(|i| self.strings.get(k).and_then(|v| v.get(i)))
            .cloned()
            .unwrap_or_else(|| k.into())
    }
    fn fill(&mut self, c: Config) {
        self.url = c.url;
        for i in 0..2 {
            self.ip4[i] = c.ipv4.get(i).cloned().unwrap_or_default();
            self.ip6[i] = c.ipv6.get(i).cloned().unwrap_or_default();
        }
    }
    fn config(&self) -> Config {
        Config {
            name: if self.provider < 3 {
                presets()[self.provider].name.clone()
            } else {
                "Custom".into()
            },
            url: self.url.trim().into(),
            ipv4: self
                .ip4
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            ipv6: self
                .ip6
                .iter()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
        }
    }
    fn work(
        &mut self,
        ctx: &egui::Context,
        label: &str,
        job: impl FnOnce() -> Result<String> + Send + 'static,
    ) {
        self.status = label.into();
        self.error = false;
        let (tx, rx) = mpsc::channel();
        self.busy = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = job().map_err(|e| format!("{e:#}"));
            let _ = tx.send(result);
            ctx.request_repaint();
        });
    }
    fn error(&mut self, e: impl std::fmt::Display) {
        self.error = true;
        self.status = e.to_string();
    }
    fn languages(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (code, title) in [
                ("tr", "Türkçe"),
                ("en", "English"),
                ("de", "Deutsch"),
                ("zh", "简体中文"),
            ] {
                if flag(ui, code, self.lang == code)
                    .on_hover_text(title)
                    .clicked()
                {
                    self.lang = code.into();
                    if let Err(e) = p::save_language(code) {
                        self.error(e);
                    }
                }
            }
        });
    }
    fn body(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.horizontal(|ui| {
            ui.label(RichText::new("SecureKon").size(32.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                self.languages(ui)
            });
        });
        ui.label(
            RichText::new(self.t("Şifreli DNS · Windows, Chrome ve Edge"))
                .color(Color32::from_rgb(156, 170, 190)),
        );
        ui.add_space(20.0);
        if self.setup {
            ui.label(self.t("Windows, Chrome ve Edge için DNS yönetimi.\n\nKurulumda bir kez yönetici izni gerekir.\nGünlük kullanımda tekrar izin istenmez.\nKısayol Başlat menüsüne eklenir."));
            ui.add_space(24.0);
            let label = self.t(if self.installed {
                "SecureKon'u aç"
            } else {
                "Kur"
            });
            if ui
                .add_sized(
                    [ui.available_width(), 42.0],
                    egui::Button::new(RichText::new(label).color(BG)).fill(ACCENT),
                )
                .clicked()
            {
                if self.installed {
                    match install::launch() {
                        Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                        Err(e) => self.error(e),
                    }
                } else {
                    self.work(
                        &ctx,
                        "SecureKon kuruluyor…\n\nWindows yönetici izni penceresini onaylayın.",
                        install::install_from_ui,
                    );
                }
            }
        } else {
            egui::Frame::new().fill(Color32::from_rgb(24,32,45)).inner_margin(16.0).corner_radius(10.0).show(ui,|ui|{ui.horizontal(|ui|{ui.vertical(|ui|{ui.label(RichText::new(self.t("Başlangıçta çalıştır")).strong());ui.label(RichText::new(self.t(if self.enabled{"Durum: Açık"}else{"Durum: Kapalı"})).color(if self.enabled{ACCENT}else{Color32::LIGHT_GRAY}));});ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),|ui|{if ui.button(self.t(if self.enabled{"Devre dışı bırak"}else{"Etkinleştir"})).clicked(){let on=!self.enabled;self.work(&ctx,"Başlangıç ayarı değiştiriliyor…",move||{p::set_startup(on)?;Ok(if on{"Başlangıç denetimi etkinleştirildi."}else{"Başlangıç denetimi devre dışı."}.into())});}});});ui.add_space(8.0);ui.label(RichText::new(self.t("Oturum açıldığında DNS ayarlarını kontrol eder ve düzeltir.\nKapatmak mevcut DNS ayarlarını değiştirmez.")).size(12.0).color(Color32::LIGHT_GRAY));});
            ui.add_space(16.0);
            ui.label(self.t("DNS sağlayıcısı"));
            let old = self.provider;
            let names = [
                "AdGuard".to_string(),
                "Google".into(),
                "Cloudflare".into(),
                self.t("Özel DNS"),
            ];
            egui::ComboBox::from_id_salt("provider")
                .width(ui.available_width())
                .selected_text(&names[self.provider])
                .show_ui(ui, |ui| {
                    for (i, n) in names.iter().enumerate() {
                        ui.selectable_value(&mut self.provider, i, n);
                    }
                });
            if old != self.provider && self.provider < 3 {
                self.fill(presets()[self.provider].clone());
            }
            ui.add_space(12.0);
            let custom = self.provider == 3;
            ui.label(self.t("Şifreli DNS adresi (HTTPS)"));
            ui.add_enabled(
                custom,
                egui::TextEdit::singleline(&mut self.url).desired_width(f32::INFINITY),
            );
            ui.add_space(10.0);
            ui.columns(2, |cols| {
                for (col, i) in cols.iter_mut().zip(0..2) {
                    col.label(self.t(if i == 0 {
                        "Birincil IPv4"
                    } else {
                        "İkincil IPv4 (isteğe bağlı)"
                    }));
                    col.add_enabled(
                        custom,
                        egui::TextEdit::singleline(&mut self.ip4[i]).desired_width(f32::INFINITY),
                    );
                    col.add_space(8.0);
                    col.label(self.t(if i == 0 {
                        "Birincil IPv6"
                    } else {
                        "İkincil IPv6 (isteğe bağlı)"
                    }));
                    col.add_enabled(
                        custom,
                        egui::TextEdit::singleline(&mut self.ip6[i]).desired_width(f32::INFINITY),
                    );
                }
            });
            ui.add_space(18.0);
            if ui
                .add_sized(
                    [ui.available_width(), 42.0],
                    egui::Button::new(RichText::new(self.t("Kaydet ve uygula")).color(BG).strong())
                        .fill(ACCENT),
                )
                .clicked()
            {
                let c = self.config();
                match c.validate() {
                    Err(e) => self.error(e),
                    Ok(()) => self.work(&ctx, "DNS ayarları uygulanıyor…", move || {
                        let r = p::submit(Action::Apply(c))?;
                        Ok(if r.state == "Offline" {
                            "Kaydedildi · Aktif bağlantı yok"
                        } else {
                            "DNS ayarları uygulandı"
                        }
                        .into())
                    }),
                }
            }
        }
    }
}
impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(rx) = &self.busy
            && let Ok(result) = rx.try_recv()
        {
            self.busy = None;
            match result {
                Ok(s) => {
                    if s == "Installed" {
                        self.installed = true;
                        self.status="Kurulum tamamlandı.\n\nDNS sağlayıcınızı seçmek ve ayarları uygulamak için\nSecureKon'u açın.".into();
                    } else {
                        self.status = s;
                    }
                    self.enabled = p::startup_enabled().unwrap_or(self.enabled);
                }
                Err(e) => self.error(e),
            }
        }
        if !self.setup && self.busy.is_none() && self.last_poll.elapsed() > Duration::from_secs(2) {
            match p::startup_enabled() {
                Ok(v) => self.enabled = v,
                Err(e) => self.error(e),
            }
            self.last_poll = Instant::now();
        }
        if self.busy.is_some() {
            ctx.request_repaint_after(Duration::from_millis(80));
            if ctx.input(|i| i.viewport().close_requested()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
        } else {
            ctx.request_repaint_after(Duration::from_secs(2));
        }
        egui::Frame::new()
            .fill(BG)
            .inner_margin(24.0)
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                let busy = self.busy.is_some();
                ui.add_enabled_ui(!busy, |ui| self.body(ui));
                ui.add_space(16.0);
                ui.horizontal_wrapped(|ui| {
                    if busy {
                        ui.spinner();
                    }
                    ui.label(
                        RichText::new(self.t(&self.status))
                            .size(12.0)
                            .color(if self.error {
                                Color32::from_rgb(255, 145, 145)
                            } else {
                                Color32::from_rgb(163, 183, 201)
                            }),
                    );
                });
                ui.add_space(14.0);
                ui.separator();
                ui.add_space(8.0);
                ui.add_enabled_ui(!busy, |ui| {
                    ui.horizontal(|ui| {
                        if !self.setup
                            && ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(self.t("SecureKon'u kaldır"))
                                            .color(Color32::WHITE),
                                    )
                                    .fill(Color32::from_rgb(48, 58, 73))
                                    .stroke(Stroke::new(1.0, Color32::GRAY)),
                                )
                                .clicked()
                        {
                            self.remove = true;
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.link(self.t("Hakkında")).clicked() {
                                self.about = true;
                            }
                        });
                    });
                });
            });
        if self.about {
            let mut open = true;
            egui::Window::new(self.t("Hakkında"))
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(&ctx, |ui| {
                    ui.heading("SecureKon");
                    ui.label("Simple Secure DNS Manager");
                    ui.label(format!("{} {} · Rust", self.t("Sürüm"), crate::VERSION));
                    if ui.link("Created by OMTY").clicked()
                        && let Err(e) = p::open_url()
                    {
                        self.error(e);
                    }
                });
            self.about = open;
        }
        if self.remove {
            let mut open = true;
            egui::Window::new(self.t("SecureKon kaldır")).collapsible(false).resizable(false).open(&mut open).show(&ctx,|ui|{ui.set_max_width(420.0);ui.label(self.t("SecureKon, görevleri ve kısayolları kaldırılacak.\n\nMevcut DNS ayarları korunacak. Devam edilsin mi?"));ui.add_space(12.0);if ui.button(self.t("SecureKon'u kaldır")).clicked(){match install::start_remove(){Ok(())=>ctx.send_viewport_cmd(egui::ViewportCommand::Close),Err(e)=>self.error(e)}self.remove=false;}});
            self.remove &= open;
        }
    }
}
fn star(p: &egui::Painter, c: Pos2, r: f32, color: Color32) {
    let pts = (0..10)
        .map(|i| {
            let a = -std::f32::consts::FRAC_PI_2 + i as f32 * std::f32::consts::PI / 5.0;
            c + Vec2::angled(a) * (if i % 2 == 0 { r } else { r * 0.4 })
        })
        .collect();
    p.add(egui::Shape::convex_polygon(pts, color, Stroke::NONE));
}
fn flag(ui: &mut egui::Ui, code: &str, selected: bool) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(36.0, 28.0), egui::Sense::click());
    let r = rect.shrink2(Vec2::new(3.0, 5.0));
    let p = ui.painter();
    let red = Color32::from_rgb(218, 34, 48);
    let white = Color32::WHITE;
    match code {
        "tr" => {
            p.rect_filled(r, 1.0, red);
            let c = Pos2::new(r.left() + 11.0, r.center().y);
            p.circle_filled(c, 6.0, white);
            p.circle_filled(c + Vec2::new(2.0, 0.0), 4.8, red);
            star(p, Pos2::new(r.left() + 22.0, r.center().y), 4.0, white);
        }
        "de" => {
            for (i, c) in [Color32::BLACK, red, Color32::from_rgb(255, 204, 0)]
                .into_iter()
                .enumerate()
            {
                p.rect_filled(
                    Rect::from_min_size(
                        r.min + Vec2::new(0.0, i as f32 * r.height() / 3.0),
                        Vec2::new(r.width(), r.height() / 3.0),
                    ),
                    0.0,
                    c,
                );
            }
        }
        "zh" => {
            p.rect_filled(r, 1.0, red);
            let yellow = Color32::from_rgb(255, 221, 0);
            star(p, r.min + Vec2::new(7.0, 6.0), 4.0, yellow);
            for v in [
                Vec2::new(13.0, 3.0),
                Vec2::new(15.0, 6.0),
                Vec2::new(15.0, 10.0),
                Vec2::new(12.0, 12.0),
            ] {
                star(p, r.min + v, 1.3, yellow);
            }
        }
        _ => {
            p.rect_filled(r, 1.0, Color32::from_rgb(25, 45, 105));
            p.line_segment([r.left_top(), r.right_bottom()], Stroke::new(5.0, white));
            p.line_segment([r.right_top(), r.left_bottom()], Stroke::new(5.0, white));
            p.line_segment([r.left_top(), r.right_bottom()], Stroke::new(2.0, red));
            p.line_segment([r.right_top(), r.left_bottom()], Stroke::new(2.0, red));
            p.line_segment([r.left_center(), r.right_center()], Stroke::new(7.0, white));
            p.line_segment([r.center_top(), r.center_bottom()], Stroke::new(7.0, white));
            p.line_segment([r.left_center(), r.right_center()], Stroke::new(4.0, red));
            p.line_segment([r.center_top(), r.center_bottom()], Stroke::new(4.0, red));
        }
    }
    if selected || response.hovered() {
        p.rect_stroke(
            rect,
            3.0,
            Stroke::new(1.5, if selected { ACCENT } else { Color32::GRAY }),
            egui::StrokeKind::Inside,
        );
    }
    response
}
pub fn run(setup: bool, remove: bool) -> Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, if setup { 430.0 } else { 650.0 }])
            .with_min_inner_size([550.0, if setup { 400.0 } else { 620.0 }])
            .with_icon(eframe::icon_data::from_png_bytes(include_bytes!(
                "../assets/icon.png"
            ))?),
        ..Default::default()
    };
    eframe::run_native(
        "SecureKon",
        options,
        Box::new(move |cc| {
            let mut style = egui::Style {
                visuals: egui::Visuals::dark(),
                ..Default::default()
            };
            style.visuals.panel_fill = BG;
            style.visuals.window_fill = Color32::from_rgb(24, 32, 45);
            style.visuals.selection.bg_fill = Color32::from_rgb(30, 95, 80);
            style.spacing.item_spacing = Vec2::new(10.0, 7.0);
            cc.egui_ctx.set_theme(egui::Theme::Dark);
            cc.egui_ctx.set_style_of(egui::Theme::Dark, style);
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "cjk".into(),
                egui::FontData::from_static(include_bytes!("../assets/SecureKon-CJK.ttf")).into(),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .push("cjk".into());
            cc.egui_ctx.set_fonts(fonts);
            Ok(Box::new(App::new(setup, remove)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

pub fn translate(key: &str) -> String {
    let strings: HashMap<String, Vec<String>> =
        serde_json::from_str(include_str!("../assets/translations.json"))
            .expect("translation asset");
    let lang = p::load_language();
    let i = match lang.as_str() {
        "en" => Some(0),
        "de" => Some(1),
        "zh" => Some(2),
        _ => None,
    };
    i.and_then(|i| strings.get(key).and_then(|v| v.get(i)))
        .cloned()
        .unwrap_or_else(|| key.into())
}
