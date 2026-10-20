use std::process::Command;

pub fn ping(host: &str) -> String {
    let out = Command::new("sh").arg("-c").arg(format!("ping -c 1 {}", host)).output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}

pub fn ping_safe(host: &str) -> Option<String> {
    if !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return None;
    }
    let out = Command::new("ping").args(["-c", "1", host]).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

pub async fn user_by_name(pool: &sqlx::PgPool, name: &str) -> Vec<User> {
    let q = format!("SELECT * FROM users WHERE name = '{}'", name);
    sqlx::query_as::<_, User>(&q).fetch_all(pool).await.unwrap()
}

pub fn first_byte(buf: &[u8], i: usize) -> u8 {
    unsafe { *buf.get_unchecked(i) }
}
