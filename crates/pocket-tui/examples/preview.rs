//! `cargo xtask preview-tui [SCENE…]`: renders dashboard scenes offline, no daemon needed.

use pocket_tui::scenes;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (w, h) = match (std::env::var("COLUMNS"), std::env::var("LINES")) {
        (Ok(c), Ok(l)) => (c.parse().unwrap_or(120), l.parse().unwrap_or(36)),
        _ => (120, 36),
    };
    let plain = args.iter().any(|a| a == "--plain");
    let names: Vec<&str> = if args.iter().all(|a| a.starts_with("--")) {
        scenes::SCENES.to_vec()
    } else {
        args.iter()
            .filter(|a| !a.starts_with("--"))
            .map(String::as_str)
            .collect()
    };
    for n in names {
        let Some(mut app) = scenes::scene(n) else {
            eprintln!("unknown scene {n}; scenes: {}", scenes::SCENES.join(", "));
            std::process::exit(2);
        };
        let buf = scenes::render(&mut app, w, h);
        println!("── scene: {n} ({w}×{h}, frame {} µs) ──", app.frame_us);
        if plain {
            print!("{}", scenes::text(&buf));
        } else {
            print!("{}", scenes::ansi(&buf));
        }
    }
}
