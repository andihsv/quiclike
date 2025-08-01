use smog::{fallback::PipeState, hspn_der::*};

struct MockPipe {
    role: Role,
    mode: ModeDescriptor,
    cursor: usize,
    state: PipeState,
}

impl HandshakeSession for MockPipe {
    fn role(&self) -> Role { self.role }
    fn mode(&self) -> ModeDescriptor { self.mode }
    fn pipe_state(&self) -> &smog::fallback::PipeState {
        &self.state
    }
    fn cursor(&self) -> usize { self.cursor }
    fn cursor_mut(&mut self) -> &mut usize { &mut self.cursor }
    // We don't execute any network I/O operations in this example.
    async fn execute(&mut self, step: HandshakeStep) -> anyhow::Result<()> {
        println!("{:?} in {:?} -> {:?}", self.role, self.state.active_mode(), step);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mode = ModeDescriptor { pattern: ['I', 'K'], psk_delay: 0 };
    let mut cli = MockPipe { role: Role::Initiator, mode, cursor: 0, state: PipeState::new_ik_with_fallback()};
    let mut srv = MockPipe { role: Role::Responder, mode, cursor: 0, state: PipeState::new_ik_with_fallback()};
    // Cli and Srv is 'turn based', cursor may not be synced, so expected output:
    //
    //          Initiator in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> SendStatic
    //          Responder in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> RecvEphemeral
    //          Initiator in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> SendEphemeral
    //          Responder in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> RecvStatic
    //          Initiator in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> SendPskTag
    //          Responder in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> SendEphemeral
    //          Initiator in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> RecvEphemeral
    //          Responder in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> Done
    //          Initiator in ModeDescriptor { pattern: ['I', 'K'], psk_delay: 2 } -> Done
    //          === Fallback to XX ===
    //          Initiator in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> SendEphemeral
    //          Responder in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> RecvEphemeral
    //          Initiator in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> SendPskTag
    //          Responder in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> SendEphemeral
    //          Initiator in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> SendStatic
    //          Responder in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> SendPskTag
    //          Initiator in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> RecvEphemeral
    //          Responder in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> SendStatic
    //          Initiator in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> Done
    //          Responder in ModeDescriptor { pattern: ['X', 'X'], psk_delay: 0 } -> Done
    // 
    // 
    // ------------------Explanation--------------------
    //
    // First: IKpsk2 stage (0-RTT)
    //      1. Initiator first executes SendStatic (pre message<- s for Noise has been completed 
    //         ahead of schedule, this is just a record)
    //      2. Continuing with SendEphedral (first message e)
    //      3. Then send PskTag (because psk_delay=2, PSK is only truly mixed after the second message, but it is placed in 
    //         the "before the second message" position in the step table, which complies with the Noise specification)
    //      4. Responder sequentially RecvEphemeric, RecvStatic, SendEphemeric (second message)
    //      5. Finally, both parties are done, shaking hands is complete
    // 
    // Second: Fallback to XXpsk0 stage (1-RTT)
    //      1. Initiator first sends Ephedral (the first message of XX)
    //      2. Subsequently, SendPskTag (mixed immediately because psk_delay=0)
    //      3. Continue SendStatic (third message)
    //      4. Responder receive/send in order, and both parties finally 'Done'
    //
    // -------------------------------------------------
    // 
    // But Noise handshake is executing as expected. Hope you get it. 😁

    // Use IK first
    while cli.cursor() < cli.active_steps().len()
        || srv.cursor() < srv.active_steps().len()
    {
        cli.tick().await?;
        srv.tick().await?;
    }

    // Simulate zero-rtt failure, fallback to XX.
    cli.state.fallback()?;
    srv.state.fallback()?;

    println!("=== Fallback to XX ===");
    cli.cursor = 0;
    srv.cursor = 0;

    while cli.cursor() < cli.active_steps().len()
        || srv.cursor() < srv.active_steps().len()
    {
        cli.tick().await?;
        srv.tick().await?;
    }

    Ok(())
}