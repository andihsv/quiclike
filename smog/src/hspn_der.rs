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
    pub psk: bool,
}

impl ModeDescriptor {
    /// Steps that the initiator needs to take.
    pub fn initiator_steps(&self) -> Vec<HandshakeStep> {
        let mut out = Vec::new();
        let [a, b] = self.pattern;

        // --- Step 1: If a == 'I', then send clear data 's'.
        if a == 'I' {
            out.push(HandshakeStep::SendStatic);
        }

        // --- Step 2: The initiator sends 'e' first.
        out.push(HandshakeStep::SendEphemeral);

        // --- Step 3: The intiator decides what to do next based on the pattern.
        match a {
            'N' | 'X' => {
                // Encrypt 's' before sending.
                out.push(HandshakeStep::SendStatic);
            }
            _ => {}
        }

        // --- Step 4: The initiator waits for the first reply.
        out.push(HandshakeStep::RecvEphemeral);

        // --- Step 5: This step depends on the pattern. The initiator sends 's' again.
        match a {
            'X' | 'I' => {
                // Already sent, does nothing here.
            }
            _ => {
                // e.g. NK, IK, the initiator have not sent 's' yet.
                if b == 'K' || b == 'X' {
                    out.push(HandshakeStep::SendStatic);
                }
            }
        }

        // --- Step 6: If contain 'psk' modifier, the initiator send 'psk' in the first message.
        if self.psk {
            out.insert(2, HandshakeStep::SendPskTag);
        }

        out.push(HandshakeStep::Done);
        out
    }

    /// Steps that the responder needs to take.
    pub fn responder_steps(&self) -> Vec<HandshakeStep> {
        let mut out = Vec::new();
        let [a, b] = self.pattern;

        // Step 1: Receive the intiator's 'e'
        out.push(HandshakeStep::RecvEphemeral);

        // if needed, receive 's'
        match a {
            'I' => out.push(HandshakeStep::RecvStatic),
            _ => {}
        }

        // The responder send 'e'
        out.push(HandshakeStep::SendEphemeral);

        // The responder send 's'
        match b {
            'K' => {} // The responder's 's' has been already send, does nothing. 
            _ => out.push(HandshakeStep::SendStatic),
        }

        // If contain 'psk' modifier, the responder send 'psk' in the second message.
        if self.psk {
            out.insert(3, HandshakeStep::SendPskTag);
        }

        out.push(HandshakeStep::Done);
        out
    }
}

/// A executable handshake session.
pub trait HandshakeSession {
    /// Returns the current role.
    fn role(&self) -> Role;

    /// Returns the current mode descriptor.
    fn mode(&self) -> ModeDescriptor;

    /// Returns the index of the finished steps.
    fn cursor(&self) -> usize;

    /// Turn a step in a exact network behaviour.
    /// Async method available after rust-version 1.75
    #[allow(async_fn_in_trait)]
    async fn execute(&mut self, step: HandshakeStep) -> anyhow::Result<()>;

    /// Execute a handshake: execute the next step.
    #[allow(async_fn_in_trait)]
    async fn tick(&mut self) -> anyhow::Result<()> {
        let seq = match self.role() {
            Role::Initiator => self.mode().initiator_steps(),
            Role::Responder => self.mode().responder_steps(),
        };
        if self.cursor() >= seq.len() {
            return Ok(());
        }
        let step = seq[self.cursor()];
        self.execute(step).await?;
        *self.cursor_mut() += 1;
        Ok(())
    }

    /// A Borrow Mut cursor, used for trait objects.
    fn cursor_mut(&mut self) -> &mut usize;
}