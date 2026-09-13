//! Verify a supplied key, digest and signature. No accounts or replay state.

use solana_account_info::AccountInfo;
use solana_program_entrypoint::entrypoint;
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;
use solana_winternitz::{MESSAGE_LEN, PUBLIC_KEY_LEN, VerifyingKey, winternitz, xmss};

entrypoint!(process_instruction);

// [tag: 1][public key: 41][digest: 32][signature: 849 or 1037].
fn process_instruction(_: &Pubkey, _: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&tag, data) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let (key, data) = data
        .split_first_chunk::<PUBLIC_KEY_LEN>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let (digest, signature) = data
        .split_first_chunk::<MESSAGE_LEN>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let key = VerifyingKey::from_bytes(key);
    match tag {
        0 => key.verify(
            digest,
            winternitz::Signature::ref_from_bytes(signature)
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ),
        1 => key.verify(
            digest,
            xmss::Signature::ref_from_bytes(signature)
                .map_err(|_| ProgramError::InvalidInstructionData)?,
        ),
        _ => return Err(ProgramError::InvalidInstructionData),
    }
    .map_err(|_| ProgramError::Custom(1))
}
