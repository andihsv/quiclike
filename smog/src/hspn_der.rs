use super::fallback::PipeState;

/// Handshake Pattern Derivation.
/// Action symbols: Client Side / Server Side of view about "What the fuck am i gonna do?"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStep {
    SendEphemeral,      // Send 'e'
    SendStatic,         // Send 's'
    SendPskTag,         // Send 'psk' (When 'psk' is enabled)
    RecvEphemeral,      // Receive 'e'
    RecvStatic,         // Receive 's'
    RecvPskTag,         // Receive 'psk'
    Done,               // Handshake is done.
}

/// Question: Who are you, and what do you do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Describe which pattern do you use and whether you are using 'psk' pattern modifier or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeDescriptor {
    /// e.g. IK
    pub pattern: [char; 2],
    /// Whether contain 'psk' modifier or not.
    pub psk_delay: u8,
}

impl ModeDescriptor {

    fn inject_psk(steps: &mut Vec<HandshakeStep>, delay: u8) {
        if delay == 0 {
            // psk0: Send in the first message.
            if let Some(pos) = steps.iter().position(|&s| s == HandshakeStep::SendEphemeral) {
                steps.insert(pos + 1, HandshakeStep::SendPskTag);
            }
            return;
        }

        // psk1 / psk2: Insert the message after No.'delay'.
        let mut msg_index = 0;
        for i in 0..steps.len() {
            match steps[i] {
                HandshakeStep::SendEphemeral | HandshakeStep::SendStatic => {
                    msg_index += 1;
                    if msg_index == delay {
                        steps.insert(i + 1, HandshakeStep::SendPskTag);
                        return;
                    }
                }
                _ => {}
            }
        }
    }

    /// Steps that the initiator needs to take.
    pub fn initiator_steps(&self) -> Vec<HandshakeStep> {
        let mut steps = self.base_initiator_steps();
        Self::inject_psk(&mut steps, self.psk_delay);
        steps
    }

    fn base_initiator_steps(&self) -> Vec<HandshakeStep> {
        let [a, b] = self.pattern;
        let mut out = vec![];

        if a == 'I' { out.push(HandshakeStep::SendStatic); }
        out.push(HandshakeStep::SendEphemeral);
        if a == 'N' || a == 'X' { out.push(HandshakeStep::SendStatic); }

        out.push(HandshakeStep::RecvEphemeral);

        match (a, b) {
            ('I', _) | ('X', _) => {} // Sent
            _ => {
                if b == 'K' || b == 'X' {
                    out.push(HandshakeStep::SendStatic);
                }
            }
        }
        out.push(HandshakeStep::Done);
        out
    }

    /// Steps that the responder needs to take.
    pub fn responder_steps(&self) -> Vec<HandshakeStep> {
        let mut steps = self.base_responder_steps();
        Self::inject_psk(&mut steps, self.psk_delay);
        steps
    }

    fn base_responder_steps(&self) -> Vec<HandshakeStep> {
        let [a, b] = self.pattern;
        let mut out = vec![HandshakeStep::RecvEphemeral];
        if a == 'I' { out.push(HandshakeStep::RecvStatic); }
        out.push(HandshakeStep::SendEphemeral);
        if b != 'K' { out.push(HandshakeStep::SendStatic); }
        out.push(HandshakeStep::Done);
        out
    }
}

/// A executable handshake session.
pub trait HandshakeSession {
    /// Returns the current role.
    fn role(&self) -> Role;

    fn pipe_state(&self) -> &PipeState;

    /// Returns the current mode descriptor.
    fn mode(&self) -> ModeDescriptor;

    /// Returns the index of the finished steps.
    fn cursor(&self) -> usize;

    /// Turn a step in a exact network behaviour.
    /// Async method available after rust-version 1.75
    #[allow(async_fn_in_trait)]
    async fn execute(&mut self, step: HandshakeStep) -> anyhow::Result<()>;

    fn active_steps(&self) -> Vec<HandshakeStep> {
        let mode = self.pipe_state().active_mode();
        match self.role() {
            Role::Initiator => mode.initiator_steps(),
            Role::Responder => mode.responder_steps(),
        }
    }

    /// Execute a handshake: execute the next step.
    #[allow(async_fn_in_trait)]
    async fn tick(&mut self) -> anyhow::Result<()> {
        let steps = self.active_steps();
        let idx = self.cursor();
        if idx >= steps.len() {
            return Ok(());
        }
        let step = steps[idx];
        self.execute(step).await?;
        *self.cursor_mut() += 1;
        Ok(())
    }

    /// A Borrow Mut cursor, used for trait objects.
    fn cursor_mut(&mut self) -> &mut usize;
}