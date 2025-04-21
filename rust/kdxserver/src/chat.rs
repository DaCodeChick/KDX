use chrono::Local;
use parking_lot::Mutex;
use rand::random_range;
use std::sync::Arc;

const DRM_MSG: [&[u8]; 10] = [
    b"Look, no bigger than a chestnut, but he eats as if his siesta depended on it!",
    br#"Never argue with a fool because he's doing the same."#,
    b"I am Gopher Boy, pondering reality",
    br#"Don't wish for everything unless you have a really big cupboard."#,
    b"To download, or not to download, that is the question.",
    b"So what is going on here?? Since when do Tim Tams come in fingers?!",
    b"May your progress bars smile at you.",
    b"How much wood would a woodchuck chuck if a woodchuck could chuck wood?",
    b"I program, therefore I am.",
    br#"Now I can't even remember what I forgot!"#,
];

const DRM_USER: [&[u8]; 6] = [
    b"??",
    b"Kevin",
    b"Files Window",
    b"KDX",
    b"A. Beaver",
    b"Diskartes",
];

pub struct Chat<'a> {
    created: i64,
    name: Vec<u8>,
    topic: Vec<u8>,
    drm_msg: Option<&'a [u8]>,
    drm_user: Option<&'a [u8]>,
}

impl Chat<'_> {
	pub fn new(name: &[u8], topic: &[u8]) -> Arc<Mutex<Self>> {
		let seed: usize = random_range(0, 300);
		let msg = if seed < 10 { Some(DRM_MSG[seed]) } else { None };
		let user = match seed {
			0, 1, 3, 5, 9 => Some(DRM_USER[0]),
			2 => Some(DRM_USER[1]),
			4 => Some(DRM_USER[2]),
			6 => Some(DRM_USER[3]),
			7 => Some(DRM_USER[4]),
			8 => Some(DRM_USER[5]),
			_ => None,
		};

		Arc::new(Mutex::new(Self {
			created: Local::now().timestamp(),
			name: name.to_vec(),
			topic: description.to_vec(),
			drm_msg: msg,
			drm_user: user,
		}))
	}
}
