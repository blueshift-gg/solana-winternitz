use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_system_interface::{instruction::create_account, program::ID as SYSTEM_PROGRAM};
use solana_winternitz::{winternitz, xmss};
use solana_winternitz_example::KEY_ACCOUNT_LEN;

#[test]
fn create_sign_and_verify_both_instances() {
    let program = Address::new_from_array([1; 32]);
    let payer = Address::new_from_array([2; 32]);
    let key = Address::new_from_array([3; 32]);
    let elf = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../target/deploy/solana_winternitz_example");
    let svm = Mollusk::new(&program, elf.to_str().unwrap());
    let directory = std::env::temp_dir().join(format!("winternitz-program-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    for tag in [0, 1] {
        let path = directory.join(format!("{tag}.key"));
        let digest = [7; 32];
        // Secrets remain in the host key file. Only public keys and signatures go on-chain.
        let (public_key, signed) = if tag == 0 {
            let mut signer = winternitz::SigningKey::create(&path).unwrap();
            let signature = signer.sign(&digest).unwrap();
            (
                signer.verifying_key(),
                vec![(digest, signature.as_bytes().to_vec())],
            )
        } else {
            let mut signer = xmss::SigningKey::create(&path).unwrap();
            let first = signer.sign(&digest).unwrap();
            let second_digest = [8; 32];
            let second = signer.sign(&second_digest).unwrap();
            // A bitmap allows unused leaves to arrive out of order.
            (
                signer.verifying_key(),
                vec![
                    (second_digest, second.as_bytes().to_vec()),
                    (digest, first.as_bytes().to_vec()),
                ],
            )
        };
        let accounts = vec![
            (payer, Account::new(1_000_000_000, 0, &SYSTEM_PROGRAM)),
            (key, Account::default()),
        ];
        let data = [&[tag][..], public_key.as_bytes()].concat();
        let create = Instruction::new_with_bytes(program, &data, vec![AccountMeta::new(key, true)]);
        let instructions = [
            create_account(
                &payer,
                &key,
                svm.sysvars.rent.minimum_balance(KEY_ACCOUNT_LEN),
                KEY_ACCOUNT_LEN as u64,
                &program,
            ),
            create.clone(),
        ];
        let created = svm.process_transaction_instructions(&instructions, &accounts, Some(&payer));
        assert_eq!(created.raw_result, Ok(()));
        let stored = &created
            .resulting_accounts
            .iter()
            .find(|(a, _)| a == &key)
            .unwrap()
            .1;
        assert_eq!(stored.data[0], tag + 1);
        assert_eq!(&stored.data[1..42], public_key.as_bytes());
        assert_eq!(&stored.data[42..], &[0; 32]);
        eprintln!("create {tag}: {} CU", created.compute_units_consumed);
        assert!(
            svm.process_instruction(&create, &created.resulting_accounts)
                .program_result
                .is_err()
        );

        for (owner, len, signer, writable) in [
            (SYSTEM_PROGRAM, KEY_ACCOUNT_LEN, true, true),
            (program, KEY_ACCOUNT_LEN - 1, true, true),
            (program, KEY_ACCOUNT_LEN, false, true),
            (program, KEY_ACCOUNT_LEN, true, false),
        ] {
            let mut bad = create.clone();
            bad.accounts[0].is_signer = signer;
            bad.accounts[0].is_writable = writable;
            let account = Account::new(svm.sysvars.rent.minimum_balance(len), len, &owner);
            assert!(
                svm.process_instruction(&bad, &[(key, account)])
                    .program_result
                    .is_err()
            );
        }
        let mut current = created.resulting_accounts;
        for (digest, signature) in signed {
            let data = [&[2][..], &digest, &signature].concat();
            let verify =
                Instruction::new_with_bytes(program, &data, vec![AccountMeta::new(key, false)]);
            for offset in [1, 37, data.len() - 1] {
                let mut bad = verify.clone();
                bad.data[offset] ^= 1;
                let rejected = svm.process_instruction(&bad, &current);
                assert!(rejected.program_result.is_err());
                assert_eq!(rejected.resulting_accounts, current);
            }
            let mut short = verify.clone();
            short.data.pop();
            assert!(
                svm.process_instruction(&short, &current)
                    .program_result
                    .is_err()
            );
            let mut trailing = verify.clone();
            trailing.data.push(0);
            assert!(
                svm.process_instruction(&trailing, &current)
                    .program_result
                    .is_err()
            );
            let mut readonly = verify.clone();
            readonly.accounts[0].is_writable = false;
            assert!(
                svm.process_instruction(&readonly, &current)
                    .program_result
                    .is_err()
            );
            let blank = Account::new(
                svm.sysvars.rent.minimum_balance(KEY_ACCOUNT_LEN),
                KEY_ACCOUNT_LEN,
                &program,
            );
            assert!(
                svm.process_instruction(&verify, &[(key, blank)])
                    .program_result
                    .is_err()
            );
            let mut missing = verify.clone();
            missing.accounts.clear();
            assert!(
                svm.process_instruction(&missing, &[])
                    .program_result
                    .is_err()
            );
            if tag == 1 {
                let mut invalid_leaf = verify.clone();
                invalid_leaf.data[33..37].copy_from_slice(&256u32.to_be_bytes());
                assert!(
                    svm.process_instruction(&invalid_leaf, &current)
                        .program_result
                        .is_err()
                );
            }
            let verified = svm.process_instruction(&verify, &current);
            assert!(
                verified.program_result.is_ok(),
                "{:?}",
                verified.program_result
            );
            assert!(verified.compute_units_consumed < 45_000);
            eprintln!("verify {tag}: {} CU", verified.compute_units_consumed);
            current = verified.resulting_accounts;
            let replay = svm.process_instruction(&verify, &current);
            assert!(replay.program_result.is_err());
            assert_eq!(replay.resulting_accounts, current);
        }
        let mut bad = instructions;
        bad[1].data.pop();
        let rejected = svm.process_transaction_instructions(&bad, &accounts, Some(&payer));
        assert!(rejected.raw_result.is_err());
        assert_eq!(rejected.resulting_accounts, accounts);
    }
    std::fs::remove_dir_all(directory).unwrap();
}
