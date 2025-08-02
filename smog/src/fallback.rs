use super::hspn_der::ModeDescriptor;

/// A complete Noise Pipe Session State Machine (💩)
#[derive(Debug, Clone)]
pub enum PipeState {
    /// Trying zero-rtt (IK)
    Ik {
        ik: ModeDescriptor,
        xx_fallback: Option<ModeDescriptor>,
    },
    /// zero-rtt failed, fallback to one-rtt (XX)
    Xx { xx: ModeDescriptor },
}

impl PipeState {
    pub fn new_ik_with_fallback() -> Self {
        let ik = ModeDescriptor {
            pattern: ['I', 'K'],
            psk_delay: 2,
        };
        let xx_fallback = ModeDescriptor {
            pattern: ['X', 'X'],
            psk_delay: 3,
        };
        PipeState::Ik {
            ik,
            xx_fallback: Some(xx_fallback),
        }
    }

    /// Take the real ModeDescriptor depends on the current state.
    pub fn active_mode(&self) -> ModeDescriptor {
        match self {
            PipeState::Ik { ik, .. } => *ik,
            PipeState::Xx { xx } => *xx,
        }
    }

    /// If IK handshake failed, then fallback to XX
    pub fn fallback(&mut self) -> anyhow::Result<()> {
        match self {
            PipeState::Ik { xx_fallback, .. } => {
                let xx = xx_fallback.take().ok_or(anyhow::anyhow!("no fallback"))?;
                *self = PipeState::Xx { xx };
                tracing::info!("Falling back to XX");
                Ok(())
            }
            _ => Err(anyhow::anyhow!("already in fallback")),
        }
    }
}
