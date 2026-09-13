//! Register a public key, then verify and record used leaves in its account.

use solana_account_info::AccountInfo;
use solana_program_entrypoint::entrypoint;
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;
use solana_winternitz::{MESSAGE_LEN, PUBLIC_KEY_LEN, VerifyingKey, winternitz, xmss};

entrypoint!(process_instruction);

const KEY_END: usize = 1 + PUBLIC_KEY_LEN;
/// Instance tag, public key, and a 256-bit used-leaf bitmap.
pub const KEY_ACCOUNT_LEN: usize = KEY_END + 32;

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
        0 | 1 => create(account, tag, data),
        2 => verify(account, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// [0: Winternitz or 1: XMSS][public key: 41]. Allocate with the System Program first.
fn create(account: &AccountInfo, tag: u8, data: &[u8]) -> ProgramResult {
    if !account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let key =
        VerifyingKey::ref_from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut bytes = account.try_borrow_mut_data()?;
    if bytes[0] != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    bytes[0] = tag + 1;
    bytes[1..KEY_END].copy_from_slice(key.as_bytes());
    bytes[KEY_END..].fill(0);
    Ok(())
}

// [2][digest: 32][signature: 849 or 1037]. The stored instance selects the encoding.
fn verify(account: &AccountInfo, data: &[u8]) -> ProgramResult {
    let (digest, signature) = data
        .split_first_chunk::<MESSAGE_LEN>()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let mut bytes = account.try_borrow_mut_data()?;
    let key = VerifyingKey::from_slice(&bytes[1..KEY_END])
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let (leaf, result) = match bytes[0] {
        0 => return Err(ProgramError::UninitializedAccount),
        1 => (
            0,
            key.verify(
                digest,
                winternitz::Signature::ref_from_bytes(signature)
                    .map_err(|_| ProgramError::InvalidInstructionData)?,
            ),
        ),
        2 => {
            let signature = xmss::Signature::ref_from_bytes(signature)
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            (signature.leaf() as usize, key.verify(digest, signature))
        }
        _ => return Err(ProgramError::InvalidAccountData),
    };
    // Verification checks the leaf bound before it is used to index the bitmap.
    result.map_err(|_| ProgramError::Custom(1))?;
    let used = &mut bytes[KEY_END + leaf / 8];
    let mask = 1 << (leaf % 8);
    if *used & mask != 0 {
        return Err(ProgramError::Custom(2));
    }
    *used |= mask;
    Ok(())
}
