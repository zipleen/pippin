//! Builders for client→server RFB messages and parsers for the server
//! messages that arrive on the encrypted control channel.

use super::auth::ecb_block;
use super::wire::{Cursor, be16, be32};

pub const PROTOCOL_VERSION: &[u8; 12] = b"RFB 003.889\n";

/// Apple's HP-mode encoding list, sent once in plaintext and once encrypted.
pub const HP_ENCODINGS: [i32; 13] =
    [1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110];

pub const ENC_RECORD_KEYS: i32 = 1103;
pub const ENC_CURSOR: i32 = 1104;
pub const ENC_DISPLAY_LAYOUT: i32 = 0x451;
pub const ENC_MEDIA_BLOB: i32 = 1010;
/// Pseudo-encodings whose payload is `u16 len || data` and which we skip.
pub const ENC_SKIPPABLE: [i32; 11] =
    [1010, 1011, 1107, 1109, 1110, 0x3f2, 0x3f3, 0x3ea, 0x453, 0x455, 0x456];

pub const BTN_LEFT: u8 = 1 << 0;
pub const BTN_RIGHT: u8 = 1 << 1;
pub const BTN_MIDDLE: u8 = 1 << 2;
pub const BTN_SCROLL_UP: u8 = 1 << 3;
pub const BTN_SCROLL_DOWN: u8 = 1 << 4;

/// 0x21 ViewerInfo followed by Apple's 12-byte 0x12 follow-up. The 32-byte
/// command mask matches Screen Sharing.app and unlocks clipboard push and
/// heartbeat notifications.
pub fn viewer_info() -> Vec<u8> {
    let mut m = Vec::with_capacity(66 + 12);
    m.extend_from_slice(&[0x21, 0]);
    m.extend_from_slice(&0x3Eu16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    for v in [2u32, 6, 1, 0, 15, 3, 0] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    let mut mask = [0u8; 32];
    mask[0] = 0xb0;
    mask[2] = 0x0c;
    mask[3] = 0x03;
    mask[4] = 0x90;
    mask[10] = 0x40;
    m.extend_from_slice(&mask);
    m.extend_from_slice(&[0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1]);
    m
}

pub fn set_encodings() -> Vec<u8> {
    let mut m = vec![0x02, 0];
    m.extend_from_slice(&(HP_ENCODINGS.len() as u16).to_be_bytes());
    for e in HP_ENCODINGS {
        m.extend_from_slice(&e.to_be_bytes());
    }
    m
}

/// SetEncryption cmd=2: switches the server onto the enc1103 record layer.
pub fn post_encryption_toggle() -> Vec<u8> {
    vec![0x12, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00]
}

/// Geometry for the virtual display we ask the host to create.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DisplayRequest {
    /// Logical (point) size.
    pub width: u32,
    pub height: u32,
    /// Backing pixels per point. 1.0 = flat, 2.0 = Retina.
    pub scale: f64,
}

/// Attributes of the virtual displays we ask for (offset 0x7E of a display
/// info): 4 is what Screen Sharing.app sends.
static DISPLAY_ATTRIBUTES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(4);

static MAX_BACKING_W: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(3840);
static MAX_BACKING_H: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(2160);

impl DisplayRequest {
    /// Default backing-store cap.
    pub const MAX_BACKING: (u32, u32) = (3840, 2160);

    /// Changes the backing-store cap for the whole process: what
    /// [`for_pixels`](Self::for_pixels) fits into and what
    /// SetDisplayConfiguration offers the host (default
    /// [`MAX_BACKING`](Self::MAX_BACKING)). For a wider virtual display,
    /// e.g. 7680x2160; whether a host accepts more than 3840x2160 is
    /// not known.
    pub fn set_max_backing(width: u32, height: u32) {
        use std::sync::atomic::Ordering::Relaxed;
        MAX_BACKING_W.store(width.max(1), Relaxed);
        MAX_BACKING_H.store(height.max(1), Relaxed);
    }

    /// Changes the attributes field of the virtual displays asked for, for
    /// the whole process (default 4, as Screen Sharing.app). rootshell-vnc
    /// sends 0. What each bit does is not documented; 4 may make the
    /// virtual display replace the Mac's own display (not verified).
    pub fn set_display_attributes(attributes: u32) {
        DISPLAY_ATTRIBUTES.store(attributes, std::sync::atomic::Ordering::Relaxed);
    }

    /// The backing-store cap in use (see [`set_max_backing`](Self::set_max_backing)).
    pub fn max_backing() -> (u32, u32) {
        use std::sync::atomic::Ordering::Relaxed;
        (MAX_BACKING_W.load(Relaxed), MAX_BACKING_H.load(Relaxed))
    }

    /// Picks the logical size and scale so the host's backing store matches
    /// `pixels` as closely as the cap allows (3840×2160 unless changed with
    /// [`set_max_backing`](Self::set_max_backing)).
    pub fn for_pixels(px_w: u32, px_h: u32, scale: f64) -> Self {
        Self::for_pixels_capped(px_w, px_h, scale, Self::max_backing())
    }

    fn for_pixels_capped(px_w: u32, px_h: u32, scale: f64, (max_w, max_h): (u32, u32)) -> Self {
        let scale = scale.clamp(0.5, 3.0);
        let fit = (max_w as f64 / px_w.max(1) as f64)
            .min(max_h as f64 / px_h.max(1) as f64)
            .min(1.0);
        let even = |v: f64| ((v / 2.0).round() as u32 * 2).max(2);
        let width = even(px_w as f64 * fit / scale).max(640);
        let height = even(px_h as f64 * fit / scale).max(360);
        Self { width, height, scale }
    }

    pub fn backing(&self) -> (u32, u32) {
        (
            (self.width as f64 * self.scale).round() as u32,
            (self.height as f64 * self.scale).round() as u32,
        )
    }
}

/// 0x1d SetDisplayConfiguration. Used for the initial virtual display and,
/// identically, for mid-session dynamic resolution changes.
pub fn set_display_configuration(req: &DisplayRequest) -> Vec<u8> {
    display_configuration_capped(std::slice::from_ref(req), DisplayRequest::max_backing())
}

/// SetDisplayConfiguration for several virtual displays at once (the
/// message has a display count). With one display it is the same message as
/// [`set_display_configuration`]. With more, every record is as Apple's
/// Screen Sharing sends for "two virtual displays" (seen in the unified logs
/// of screensharingd, macOS 27): display flags 0 (no dynamic resolution),
/// native and preferred mode index 0 and rotations 7, the same in each
/// record. The host places the displays side by side itself. Apple's viewer
/// sends it before SetEncodings; the host then offers one video stream per
/// display.
pub fn set_display_configurations(reqs: &[DisplayRequest]) -> Vec<u8> {
    display_configuration_capped(reqs, DisplayRequest::max_backing())
}

fn display_configuration_capped(reqs: &[DisplayRequest], cap: (u32, u32)) -> Vec<u8> {
    let attributes = DISPLAY_ATTRIBUTES.load(std::sync::atomic::Ordering::Relaxed);
    let several = reqs.len() > 1;
    let infos: Vec<Vec<u8>> =
        reqs.iter().enumerate().map(|(i, r)| display_info(r, cap, i, attributes, several)).collect();
    let body: usize = infos.iter().map(Vec::len).sum();
    let mut msg = vec![0x1d, 0];
    msg.extend_from_slice(&((8 + body) as u16).to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // version
    msg.extend_from_slice(&(reqs.len() as u16).to_be_bytes()); // display count
    msg.extend_from_slice(&0u32.to_be_bytes()); // flags
    for di in infos {
        msg.extend_from_slice(&di);
    }
    msg
}

/// One display's info block. Display `index` gets its own name. `several`:
/// one of several displays, so no dynamic resolution (as Apple's viewer).
/// The u16 fields at 0x92 and 0x94 are the native and preferred mode index
/// and the u32 at 0x96 the rotations, as the host logs them: they are the
/// same for every display (an older version put the display's x position
/// and 8 there, a mode index past the end of the list, and the host reset
/// the connection).
fn display_info(req: &DisplayRequest, (max_w, max_h): (u32, u32), index: usize, attributes: u32, several: bool)
    -> Vec<u8> {
    const MODES: [(f64, f64); 5] =
        [(1920.0, 1080.0), (1440.0, 900.0), (1920.0, 1080.0), (1440.0, 810.0), (1312.0, 848.0)];
    let mode_count = MODES.len();
    let di_size = 0x9C + 28 * mode_count;
    let mut di = vec![0u8; di_size];
    let put16 = |d: &mut [u8], off: usize, v: u16| d[off..off + 2].copy_from_slice(&v.to_be_bytes());
    let put32 = |d: &mut [u8], off: usize, v: u32| d[off..off + 4].copy_from_slice(&v.to_be_bytes());

    put16(&mut di, 0, di_size as u16);
    let name = match index {
        0 => "pippin Virtual Display".to_owned(),
        i => format!("pippin Virtual Display {}", i + 1),
    };
    di[2..2 + name.len()].copy_from_slice(name.as_bytes());
    put32(&mut di, 0x7A, (!several) as u32); // dynamic resolution
    put32(&mut di, 0x7E, attributes);
    di[0x82..0x86].copy_from_slice(&369.454_56_f32.to_be_bytes());
    di[0x86..0x8A].copy_from_slice(&207.818_17_f32.to_be_bytes());
    put32(&mut di, 0x8A, max_w);
    put32(&mut di, 0x8E, max_h);
    put16(&mut di, 0x92, 0); // native mode index
    put16(&mut di, 0x94, 0); // preferred mode index
    put32(&mut di, 0x96, 7); // rotations
    put16(&mut di, 0x9A, mode_count as u16);

    let sx = req.width as f64 / 1920.0;
    let sy = req.height as f64 / 1080.0;
    for (i, (bw, bh)) in MODES.iter().enumerate() {
        let lw = (bw * sx + 0.5) as u32;
        let lh = (bh * sy + 0.5) as u32;
        let pw = (lw as f64 * req.scale + 0.5) as u32;
        let ph = (lh as f64 * req.scale + 0.5) as u32;
        let m = 0x9C + 28 * i;
        put32(&mut di, m, pw);
        put32(&mut di, m + 4, ph);
        put32(&mut di, m + 8, lw);
        put32(&mut di, m + 12, lh);
        di[m + 16..m + 24].copy_from_slice(&60.0f64.to_be_bytes());
        put32(&mut di, m + 24, 0);
    }
    di
}

pub fn fbu_request(incremental: bool, x: u16, y: u16, w: u16, h: u16) -> Vec<u8> {
    let mut m = vec![0x03, incremental as u8];
    for v in [x, y, w, h] {
        m.extend_from_slice(&v.to_be_bytes());
    }
    m
}

/// Most note bytes the server takes; a longer session visibility message is
/// rejected whole (rootshell-vnc, `AppleCurtainProtocol`, MIT).
pub const CURTAIN_NOTE_MAX: usize = 512;

/// msg 12 session visibility (curtain mode): `visible` false hides the
/// session from the Mac's own display (a lock screen showing `note`), true
/// shows it again. Layout: type, pad, u16 visible, u16 note length, note
/// (UTF-8, no NUL). The server answers with no message; the state shows in
/// its next display info. Layout from rootshell-vnc (MIT).
pub fn session_visibility(visible: bool, note: &str) -> Vec<u8> {
    let mut end = note.len().min(CURTAIN_NOTE_MAX);
    while !note.is_char_boundary(end) {
        end -= 1;
    }
    let note = if visible { "" } else { &note[..end] };
    let mut m = vec![12, 0];
    m.extend_from_slice(&(visible as u16).to_be_bytes());
    m.extend_from_slice(&(note.len() as u16).to_be_bytes());
    m.extend_from_slice(note.as_bytes());
    m
}

pub fn key_event(down: bool, keysym: u32) -> Vec<u8> {
    let mut m = vec![0x04, down as u8, 0, 0];
    m.extend_from_slice(&keysym.to_be_bytes());
    m
}

/// msg 0x10 HandleEncryptedEventMessage carrying a pointer event, the form
/// Screen Sharing.app uses for every pointer event in HP mode. The block is
/// AES-128-ECB under the record-layer key; byte 10 must be 0xff.
pub fn encrypted_pointer_event(record_key: &[u8; 16], buttons: u8, x: u16, y: u16) -> Vec<u8> {
    let mut block = [0u8; 16];
    block[10] = 0xff;
    block[11] = buttons;
    block[12..14].copy_from_slice(&x.to_be_bytes());
    block[14..16].copy_from_slice(&y.to_be_bytes());
    ecb_block(record_key, &mut block);
    let mut m = vec![0x10, 0];
    m.extend_from_slice(&block);
    m
}

/// One rect from a FramebufferUpdate on the control channel.
#[derive(Debug)]
pub enum Rect<'a> {
    Cursor(CursorRect<'a>),
    Layout(DisplayLayout),
    /// 1010 media blob; carries the 0x1c answer bplist.
    MediaBlob(&'a [u8]),
    RecordKeys(&'a [u8]),
    Skipped(i32),
}

#[derive(Debug)]
pub struct CursorRect<'a> {
    pub hotspot: (u16, u16),
    pub size: (u16, u16),
    pub cache_id: u32,
    /// zlib (sync-flush) BGRA pixmap followed by an 8-bit alpha mask.
    /// Empty means "reuse cache entry `cache_id`".
    pub compressed: &'a [u8],
}

#[derive(Debug, Clone, PartialEq)]
pub struct DisplayLayout {
    pub scaled: (u16, u16),
    pub backing: (u16, u16),
    pub displays: Vec<DisplayRect>,
    /// DisplayInfo2 screen flags (see [`SessionFlags`]), if found.
    pub session_flags: Option<u32>,
}

/// DisplayInfo2 screen flags, as rootshell-vnc (MIT) reads them.
pub struct SessionFlags;

impl SessionFlags {
    /// The host accepts curtain commands.
    pub const CURTAIN_AVAILABLE: u32 = 0x02;
    /// The session is drawn on the Mac's own display (not curtained).
    pub const ON_CONSOLE: u32 = 0x04;
    pub const LOCK_SCREEN: u32 = 0x08;
    pub const LOGIN_WINDOW: u32 = 0x10;
}

/// The screen flags of a DisplayInfo2 payload. macOS has sent them in both
/// byte orders; the defined bits are in the low byte, so both readings are
/// combined (as rootshell-vnc does). With a two-byte length prefix the
/// version is at 2 and the flags at 16, else at 0 and 14.
fn session_flags(p: &[u8]) -> Option<u32> {
    let version_ok = |off: usize| {
        let (be, le) = (p.get(off..off + 2)?, p.get(off..off + 2)?);
        let (be, le) = (u16::from_be_bytes([be[0], be[1]]), u16::from_le_bytes([le[0], le[1]]));
        ((4..=16).contains(&be) || (4..=16).contains(&le)).then_some(())
    };
    let at = if p.len() >= 20 && version_ok(2).is_some() {
        16
    } else if version_ok(0).is_some() {
        14
    } else {
        return None;
    };
    let b: [u8; 4] = p.get(at..at + 4)?.try_into().ok()?;
    Some((u32::from_be_bytes(b) | u32::from_le_bytes(b)) & 0xff)
}

#[derive(Debug, Clone, PartialEq)]
pub struct DisplayRect {
    pub id: u32,
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

fn parse_layout(p: &[u8]) -> Option<DisplayLayout> {
    if p.len() < 10 {
        return None;
    }
    let scaled = (be16(p, 2), be16(p, 4));
    let backing = (be16(p, 6), be16(p, 8));
    let mut displays = Vec::new();
    if p.len() >= 20 {
        let count = be16(p, 18) as usize;
        for i in 0..count {
            let off = 20 + 56 * i;
            if off + 56 > p.len() {
                break;
            }
            let (y0, x0, y1, x1) =
                (be16(p, off + 28), be16(p, off + 30), be16(p, off + 32), be16(p, off + 34));
            if x1 > x0 && y1 > y0 {
                displays.push(DisplayRect { id: be32(p, off + 16), x: x0, y: y0, w: x1 - x0, h: y1 - y0 });
            }
        }
    }
    Some(DisplayLayout { scaled, backing, displays, session_flags: session_flags(p) })
}

/// Walks a FramebufferUpdate (type 0x00). Stops at the first rect whose
/// encoding we cannot size; everything parsed before it is returned.
pub fn parse_fbu(msg: &[u8]) -> Vec<Rect<'_>> {
    let mut rects = Vec::new();
    let mut c = Cursor::at(msg, 2);
    let Some(n) = c.u16() else { return rects };
    for _ in 0..n {
        let Some((f0, f1, f2, f3, enc)) = (|| Some((c.u16()?, c.u16()?, c.u16()?, c.u16()?, c.i32()?)))()
        else {
            break;
        };
        let rect = match enc {
            ENC_CURSOR => {
                let Some((cache_id, len)) = (|| Some((c.u32()?, c.u32()?)))() else { break };
                let Some(data) = c.take(len as usize) else { break };
                Rect::Cursor(CursorRect { hotspot: (f0, f1), size: (f2, f3), cache_id, compressed: data })
            }
            ENC_RECORD_KEYS => match c.take(36) {
                Some(d) => Rect::RecordKeys(d),
                None => break,
            },
            ENC_DISPLAY_LAYOUT | ENC_MEDIA_BLOB => {
                let Some(len) = c.u16() else { break };
                let Some(data) = c.take(len as usize) else { break };
                if enc == ENC_MEDIA_BLOB {
                    Rect::MediaBlob(data)
                } else {
                    match parse_layout(data) {
                        Some(l) => Rect::Layout(l),
                        None => Rect::Skipped(enc),
                    }
                }
            }
            e if ENC_SKIPPABLE.contains(&e) => {
                let Some(len) = c.u16() else { break };
                if c.skip(len as usize).is_none() {
                    break;
                }
                Rect::Skipped(e)
            }
            other => {
                tracing::debug!(encoding = other, "unknown FBU encoding; stopping walk");
                break;
            }
        };
        rects.push(rect);
    }
    rects
}

#[cfg(test)]
mod tests {

    #[test]
    fn max_backing_can_be_raised() {
        // The capped forms, so the process-wide cap is never changed under other tests.
        assert_eq!(DisplayRequest::max_backing(), DisplayRequest::MAX_BACKING);
        let r = DisplayRequest::for_pixels(7680, 2160, 2.0);
        assert_eq!(r.backing(), (3840, 1080), "fits the default cap");
        let r = DisplayRequest::for_pixels_capped(7680, 2160, 2.0, (7680, 2160));
        assert_eq!(r.backing(), (7680, 2160));
        let m = display_configuration_capped(&[r], (7680, 2160));
        // Header 12 bytes (type, pad, length, version, count, flags), then the display info: the cap at 0x8A and 0x8E.
        assert_eq!(u32::from_be_bytes(m[12 + 0x8A..12 + 0x8E].try_into().unwrap()), 7680);
        assert_eq!(u32::from_be_bytes(m[12 + 0x8E..12 + 0x92].try_into().unwrap()), 2160);
    }

    #[test]
    fn session_flags_in_both_byte_orders() {
        let mut p = vec![0u8; 24];
        p[2..4].copy_from_slice(&5u16.to_be_bytes()); // version 5, prefixed form
        p[16..20].copy_from_slice(&(SessionFlags::CURTAIN_AVAILABLE | SessionFlags::ON_CONSOLE).to_be_bytes());
        assert_eq!(session_flags(&p), Some(0x06));
        p[16..20].copy_from_slice(&SessionFlags::CURTAIN_AVAILABLE.to_le_bytes());
        assert_eq!(session_flags(&p), Some(0x02));
        assert_eq!(session_flags(&[0u8; 6]), None, "no version: unknown");
    }

    #[test]
    fn two_displays_in_one_message() {
        let r = DisplayRequest::for_pixels(3840, 2160, 2.0);
        let one = set_display_configuration(&r);
        assert_eq!(set_display_configurations(&[r]), one, "one display: the same message");
        let two = set_display_configurations(&[r, r]);
        let di = one.len() - 12;
        assert_eq!(two.len(), 12 + 2 * di);
        assert_eq!(u16::from_be_bytes([two[2], two[3]]) as usize, 8 + 2 * di, "length");
        assert_eq!(u16::from_be_bytes([two[6], two[7]]), 2, "display count");
        let second = &two[12 + di..];
        assert_eq!(&second[2..2 + 24], b"pippin Virtual Display 2");
        assert_eq!(di, 296, "Apple's record size: 156 + 5 modes x 28");
        let u16_at = |r: &[u8], o: usize| u16::from_be_bytes([r[o], r[o + 1]]);
        let u32_at = |r: &[u8], o: usize| u32::from_be_bytes(r[o..o + 4].try_into().unwrap());
        for r in [&two[12..12 + di], second] {
            assert_eq!(u32_at(r, 0x7A), 0, "no dynamic resolution with two displays");
            assert_eq!((u32_at(r, 0x8A), u32_at(r, 0x8E)), (3840, 2160), "maximum");
            assert_eq!((u16_at(r, 0x92), u16_at(r, 0x94)), (0, 0), "native and preferred mode index");
            assert_eq!(u32_at(r, 0x96), 7, "rotations");
            assert_eq!(u16_at(r, 0x9A), 5, "mode count");
        }
        assert_eq!(u32_at(&one[12..], 0x7A), 1, "one display: dynamic resolution");
        assert_eq!(u32::from_be_bytes(two[12 + 0x7E..12 + 0x82].try_into().unwrap()), 4, "default attributes");
    }

    #[test]
    fn session_visibility_layout() {
        assert_eq!(session_visibility(true, "ignored"), vec![12, 0, 0, 1, 0, 0]);
        assert_eq!(session_visibility(false, "hi"), vec![12, 0, 0, 0, 0, 2, b'h', b'i']);
        // Cut at the limit on a character boundary: 'é' is 2 bytes.
        let long = "é".repeat(400);
        let m = session_visibility(false, &long);
        assert_eq!(u16::from_be_bytes([m[4], m[5]]) as usize, CURTAIN_NOTE_MAX);
        assert!(std::str::from_utf8(&m[6..]).is_ok());
    }

    use super::*;

    #[test]
    fn display_configuration_layout() {
        let req = DisplayRequest { width: 1920, height: 1080, scale: 2.0 };
        let m = set_display_configuration(&req);
        let di_size = 0x9C + 28 * 5;
        assert_eq!(m.len(), 12 + di_size);
        assert_eq!(&m[0..2], &[0x1d, 0]);
        assert_eq!(be16(&m, 2) as usize, 8 + di_size);
        let di = &m[12..];
        assert_eq!(be16(di, 0) as usize, di_size);
        assert_eq!(be32(di, 0x7A), 1);
        assert_eq!(be32(di, 0x7E), 4);
        assert_eq!(be32(di, 0x8A), 3840);
        assert_eq!(be32(di, 0x96), 7);
        assert_eq!(be16(di, 0x9A), 5);
        // First mode is the requested size at 2× backing.
        assert_eq!((be32(di, 0x9C), be32(di, 0xA0), be32(di, 0xA4), be32(di, 0xA8)), (3840, 2160, 1920, 1080));
        assert_eq!(f32::from_be_bytes(di[0x82..0x86].try_into().unwrap()), 369.454_56);
    }

    #[test]
    fn display_request_respects_cap() {
        let r = DisplayRequest::for_pixels(5120, 2880, 1.0);
        let (bw, bh) = r.backing();
        assert!(bw <= 3840 && bh <= 2160, "{bw}x{bh}");
        let r = DisplayRequest::for_pixels(2560, 1440, 2.0);
        assert_eq!((r.width, r.height), (1280, 720));
        assert_eq!(r.backing(), (2560, 1440));
    }

    #[test]
    fn viewer_info_shape() {
        let v = viewer_info();
        assert_eq!(v.len(), 4 + 0x3E + 12);
        assert_eq!(v[0], 0x21);
        assert_eq!(v[34], 0xb0);
    }

    #[test]
    fn fbu_walk() {
        let mut m = vec![0, 0, 0, 3];
        // 1011 skippable
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(&1011i32.to_be_bytes());
        m.extend_from_slice(&[0, 2, 0xaa, 0xbb]);
        // 0x451 layout, 20-byte header + one display
        m.extend_from_slice(&[0; 8]);
        m.extend_from_slice(&0x451i32.to_be_bytes());
        let mut p = vec![0u8; 20 + 56];
        p[2..4].copy_from_slice(&1280u16.to_be_bytes());
        p[4..6].copy_from_slice(&720u16.to_be_bytes());
        p[6..8].copy_from_slice(&2560u16.to_be_bytes());
        p[8..10].copy_from_slice(&1440u16.to_be_bytes());
        p[18..20].copy_from_slice(&1u16.to_be_bytes());
        p[20 + 32..20 + 34].copy_from_slice(&1440u16.to_be_bytes());
        p[20 + 34..20 + 36].copy_from_slice(&2560u16.to_be_bytes());
        m.extend_from_slice(&(p.len() as u16).to_be_bytes());
        m.extend_from_slice(&p);
        // cursor cache hit
        m.extend_from_slice(&[0, 4, 0, 5, 0, 16, 0, 16]);
        m.extend_from_slice(&1104i32.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 9, 0, 0, 0, 0]);
        let rects = parse_fbu(&m);
        assert_eq!(rects.len(), 3);
        match &rects[1] {
            Rect::Layout(l) => {
                assert_eq!(l.backing, (2560, 1440));
                assert_eq!(l.displays[0].w, 2560);
            }
            r => panic!("{r:?}"),
        }
        match &rects[2] {
            Rect::Cursor(c) => {
                assert_eq!(c.cache_id, 9);
                assert!(c.compressed.is_empty());
                assert_eq!(c.hotspot, (4, 5));
            }
            r => panic!("{r:?}"),
        }
    }
}
