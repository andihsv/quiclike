use smog::dhpn_der::*;

fn main() {
    let full = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "XX+psk1".to_string());
    let (pat, psk) = parse_full(&full).unwrap();
    let flow = build_flow(pat, psk);
    println!("{}", serde_json::to_string_pretty(&flow).unwrap());
}
