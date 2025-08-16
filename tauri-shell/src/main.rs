#[tauri::command]
fn greet(name: &str) -> String {
    sentinel_core::greet(name)
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
