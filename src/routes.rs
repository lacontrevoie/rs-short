#[derive(Deserialize)]
pub struct ShortcutAdminInfo {
    pub url_from: String,
    pub admin_key: String,
}

#[derive(Deserialize)]
pub struct ShortcutInfo {
    pub url_from: String,
}
