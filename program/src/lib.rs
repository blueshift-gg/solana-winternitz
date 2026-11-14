//! Register a one-time public key, then verify one signature and spend the key.

use solana_account_info::AccountInfo;
use solana_program_entrypoint::entrypoint;
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;
use solana_winternitz::{MESSAGE_LEN, PUBLIC_KEY_LEN, Signature, VerifyingKey};

entrypoint!(process_instruction);

/// State byte (0 empty, 1 registered, 2 spent), then the public key.
pub const KEY_ACCOUNT_LEN: usize = 1 + PUBLIC_KEY_LEN;
const REGISTERED: u8 = 1;
const SPENT: u8 = 2;

fn process_instruction(id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let account = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if account.owner != id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !account.is_writable || account.data_len() != KEY_ACCOUNT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    let (&tag, data) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        0 => create(account, data),
        1 => verify(account, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// [0][public key: 41]. Allocate with the System Program first.
fn create(account: &AccountInfo, data: &[u8]) -> ProgramResult {
    if !account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let key =
        VerifyingKey::ref_from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut bytes = account.try_borrow_mut_data()?;
    if bytes[0] != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    bytes[0] = REGISTERED;
    bytes[1..].copy_from_slice(key.as_bytes());
    Ok(())
}

// [1][digest: 32][signature: 849]. A key verifies once, then is spent.
fn verify(account: &AccountInfo, data: &[u8]) -> ProgramResult {
    let (digest, signature) = data
        .split_first_chunk::<MESSAGE_LEN>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let signature =
        Signature::ref_from_bytes(signature).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut bytes = account.try_borrow_mut_data()?;
    match bytes[0] {
        0 => return Err(ProgramError::UninitializedAccount),
        REGISTERED => {}
        SPENT => return Err(ProgramError::Custom(2)),
        _ => return Err(ProgramError::InvalidAccountData),
    }
    VerifyingKey::ref_from_bytes(&bytes[1..])
        .map_err(|_| ProgramError::InvalidAccountData)?
        .verify(digest, signature)
        .map_err(|_| ProgramError::Custom(1))?;
    bytes[0] = SPENT;
    Ok(())
}
