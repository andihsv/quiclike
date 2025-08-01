use smog::hspn_der::*;

struct MockSession {
    role: Role,
    mode: ModeDescriptor,
    cursor: usize,
}

impl HandshakeSession for MockSession {
    fn role(&self) -> Role { self.role }
    fn mode(&self) -> ModeDescriptor { self.mode }
    fn cursor(&self) -> usize { self.cursor }
    fn cursor_mut(&mut self) -> &mut usize { &mut self.cursor }
    // We don't execute any network I/O operations in this example.
    async fn execute(&mut self, step: HandshakeStep) -> anyhow::Result<()> {
        println!("{:?} executing step: {:?}", self.role, step);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mode = ModeDescriptor { pattern: ['I', 'K'], psk: true };
    let mut cli = MockSession { role: Role::Initiator, mode, cursor: 0 };
    let mut srv = MockSession { role: Role::Responder, mode, cursor: 0 };
    // Cli and Srv is 'turn based', cursor may not be synced, so expected log:
    // Initiator executing step: SendStatic
    //
    //          Responder executing step: RecvEphemeral
    //          Initiator executing step: SendEphemeral
    //          Responder executing step: RecvStatic
    //          Initiator executing step: SendPskTag
    //          Responder executing step: SendEphemeral
    //          Initiator executing step: RecvEphemeral
    //          Responder executing step: SendPskTag
    //          Initiator executing step: Done
    //          Responder executing step: Done
    // 
    // But Noise handshake is executing as expected.
    while cli.cursor() < cli.mode().initiator_steps().len()
        || srv.cursor() < srv.mode().responder_steps().len()
    {
        cli.tick().await?;
        srv.tick().await?;
    }
    Ok(())
}