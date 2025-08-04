use smog::dhpn::Tokens;

fn main() {
    let cases = ["IKfallback+psk3", "XX+psk0", "KN", "xxfallback+psk2"];
    for c in cases {
        println!("{:?}  →  {:?}", c, Tokens::new(c).expect("Unable to parse"));
    }
}
