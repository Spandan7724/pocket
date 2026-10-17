//! A session's screen (vt100 mirror) drawn into a ratatui area. The pane never changes the
//! session's size: when it is smaller than the session, it shows the part around the cursor.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};

use crate::theme::{Mode, Theme};

fn color(c: vt100::Color) -> Color {
    match c {
        vt100::Color::Default => Color::Reset,
        vt100::Color::Idx(i) => Color::Indexed(i),
        vt100::Color::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

/// First row and column of the session screen to show in `area`.
pub fn viewport(screen: &vt100::Screen, area: Rect) -> (u16, u16) {
    let (rows, cols) = screen.size();
    let (cr, cc) = screen.cursor_position();
    let top = if rows > area.height {
        (cr + 1).saturating_sub(area.height).min(rows - area.height)
    } else {
        0
    };
    let left = if cols > area.width {
        (cc + 1).saturating_sub(area.width).min(cols - area.width)
    } else {
        0
    };
    (top, left)
}

pub fn draw(screen: &vt100::Screen, area: Rect, buf: &mut Buffer, theme: &Theme, cursor: bool) {
    let (rows, cols) = screen.size();
    let (top, left) = viewport(screen, area);
    for y in 0..area.height.min(rows.saturating_sub(top)) {
        for x in 0..area.width.min(cols.saturating_sub(left)) {
            let Some(c) = screen.cell(top + y, left + x) else {
                continue;
            };
            let Some(cell) = buf.cell_mut((area.x + x, area.y + y)) else {
                continue;
            };
            if c.is_wide_continuation() {
                continue;
            }
            if c.has_contents() {
                cell.set_symbol(c.contents());
            } else {
                cell.set_symbol(" ");
            }
            let mut m = Modifier::empty();
            if c.bold() {
                m |= Modifier::BOLD;
            }
            if c.italic() {
                m |= Modifier::ITALIC;
            }
            if c.underline() {
                m |= Modifier::UNDERLINED;
            }
            if c.inverse() {
                m |= Modifier::REVERSED;
            }
            if c.dim() {
                m |= Modifier::DIM;
            }
            let style = match theme.mode {
                Mode::Mono => Style::reset().add_modifier(m),
                _ => Style::reset()
                    .fg(color(c.fgcolor()))
                    .bg(color(c.bgcolor()))
                    .add_modifier(m),
            };
            cell.set_style(style);
        }
    }
    if cursor && !screen.hide_cursor() {
        let (cr, cc) = screen.cursor_position();
        if cr >= top
            && cc >= left
            && cr - top < area.height
            && cc - left < area.width
            && let Some(cell) = buf.cell_mut((area.x + cc - left, area.y + cr - top))
        {
            cell.set_style(Style::default().add_modifier(Modifier::REVERSED));
        }
    }
}
