use serde::Serialize;
use std::str::FromStr;

#[derive(Debug, Clone, Copy)]
enum Role {
    Initiator,
    Responder,
}
impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Initiator => "initiator",
            Role::Responder => "responder",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum HandshakePattern {
    N,
    K,
    X,
    NN,
    NK,
    NX,
    XN,
    XK,
    XX,
    KN,
    KK,
    KX,
    IN,
    IK,
    IX,
    XXfallback, // 目前官方唯一推荐 fallback
}

impl FromStr for HandshakePattern {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "N" => Ok(Self::N),
            "K" => Ok(Self::K),
            "X" => Ok(Self::X),
            "NN" => Ok(Self::NN),
            "NK" => Ok(Self::NK),
            "NX" => Ok(Self::NX),
            "XN" => Ok(Self::XN),
            "XK" => Ok(Self::XK),
            "XX" => Ok(Self::XX),
            "KN" => Ok(Self::KN),
            "KK" => Ok(Self::KK),
            "KX" => Ok(Self::KX),
            "IN" => Ok(Self::IN),
            "IK" => Ok(Self::IK),
            "IX" => Ok(Self::IX),
            "XXfallback" => Ok(Self::XXfallback),
            _ => Err("unsupported pattern"),
        }
    }
}

/// 解析 "XX+psk1" -> (XX, Some(1))   或 "XXfallback+psk0" -> (XXfallback, Some(0))
pub fn parse_full(s: &str) -> Result<(HandshakePattern, Option<usize>), &'static str> {
    let parts: Vec<&str> = s.split('+').collect();
    if parts.len() > 2 {
        return Err("invalid syntax");
    }
    let pat = HandshakePattern::from_str(parts[0])?;
    let psk = if parts.len() == 2 {
        let suffix = parts[1];
        if !suffix.starts_with("psk") {
            return Err("invalid psk suffix");
        }
        suffix[3..]
            .parse::<usize>()
            .ok()
            .ok_or("invalid psk number")?
    } else {
        usize::MAX
    };
    Ok((pat, if psk == usize::MAX { None } else { Some(psk) }))
}

/// 基础握手消息顺序（不含 psk）
fn base_order(pat: HandshakePattern) -> Vec<Role> {
    use HandshakePattern::*;
    use Role::*;
    match pat {
        N | K | X => vec![Initiator],
        NN | NK | NX | XN | KN | IN => vec![Initiator, Responder, Initiator],
        XK | XX | XXfallback | KK | KX | IK | IX => {
            vec![Initiator, Responder, Initiator, Responder]
        }
    }
}

/// 最终输出结构
#[derive(Debug, Serialize)]
pub struct Step {
    from: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    psk: Option<usize>,
    dhs: Vec<&'static str>,
}

/// 生成最终握手顺序（含 DH token 与 psk 事件）
pub fn build_flow(pat: HandshakePattern, psk: Option<usize>) -> Vec<Step> {
    use HandshakePattern::*;
    use Role::*;

    // 注意：统一写成 &[&str] 切片，避免数组长度推断错误
    let tokens: &[(usize, &[&str])] = match pat {
        N => &[(0, &["e", "es"])],
        K => &[(0, &["e", "es", "ss"])],
        X => &[(0, &["e", "es", "s", "ss"])],
        NN => &[(0, &["e"]), (1, &["e", "ee"])],
        NK => &[(0, &["e", "es"]), (1, &["e", "ee"])],
        NX => &[(0, &["e"]), (1, &["e", "ee", "s", "es"])],
        XN => &[(0, &["e"]), (1, &["e", "ee"]), (2, &["s", "se"])],
        XK => &[(0, &["e", "es"]), (1, &["e", "ee"]), (2, &["s", "se"])],
        XX => &[(0, &["e"]), (1, &["e", "ee", "s", "es"]), (2, &["s", "se"])],
        XXfallback => &[
            (0, &["e", "ee", "s", "es", "fallback"]),
            (1, &["e", "ee", "s", "se"]),
            (2, &["s", "se"]),
        ],
        KN => &[(0, &["e", "ss"]), (1, &["e", "ee", "se"])],
        KK => &[(0, &["e", "es", "ss"]), (1, &["e", "ee", "se"])],
        KX => &[(0, &["e", "ss"]), (1, &["e", "ee", "se", "s", "es"])],
        IN => &[(0, &["e", "s"]), (1, &["e", "ee", "se"])],
        IK => &[(0, &["e", "es", "s", "ss"]), (1, &["e", "ee", "se"])],
        IX => &[(0, &["e", "s"]), (1, &["e", "ee", "se", "s", "es"])],
    };

    let base = base_order(pat);
    let mut flow = Vec::new();

    for &(msg_idx, tkns) in tokens {
        let sender = base[msg_idx];

        // pskN 事件：在发送 msg_idx 之前插入
        if let Some(n) = psk {
            if n == msg_idx {
                flow.push(Step {
                    from: sender.as_str(),
                    psk: Some(n),
                    dhs: vec![],
                });
            }
        }

        // 真正的消息
        let dhs: Vec<_> = tkns
            .iter()
            .filter(|t| matches!(*t, &"ee" | &"es" | &"se" | &"ss"))
            .copied()
            .collect();
        flow.push(Step {
            from: sender.as_str(),
            psk: None,
            dhs,
        });
    }

    // pskN 如果等于消息总数，则追加在最后一条之后
    if let Some(n) = psk {
        if n == base.len() {
            let last_sender = *base.last().unwrap();
            flow.push(Step {
                from: last_sender.as_str(),
                psk: Some(n),
                dhs: vec![],
            });
        }
    }

    flow
}

// fn main() {
//     let full = std::env::args()
//         .nth(1)
//         .unwrap_or_else(|| "XX+psk1".to_string());
//     let (pat, psk) = parse_full(&full).unwrap();
//     let flow = build_flow(pat, psk);
//     println!("{}", serde_json::to_string_pretty(&flow).unwrap());
// }
