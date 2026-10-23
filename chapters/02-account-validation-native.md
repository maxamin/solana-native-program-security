# Account Validation in Native Programs

Chapter 1 showed that a native program must authenticate every account it receives. This chapter turns that into a checklist and a code structure that makes missing checks hard to write.

## The checklist for every account

| Check | Native code |
|---|---|
| Owner | `if acc.owner != program_id { return Err(...) }` |
| Signer | `if !acc.is_signer { ... }` |
| Writable | `if !acc.is_writable { ... }` |
| Type / discriminator | first bytes of data match the expected type tag |
| PDA derivation | `Pubkey::create_program_address(&[seeds, &[bump]], program_id) == acc.key`, with canonical bump |
| Relationship | e.g. `vault.authority == authority.key`, `token_account.mint == expected_mint` |
| Sysvars / programs | `acc.key == sysvar::instructions::ID`, `token_program.key == spl_token::ID` |
| Initialised state | account is initialised exactly once (no re-initialisation) |
| Duplicate accounts | the same account passed twice in different roles |

Not every row applies to every account, but every row should be consciously accepted or rejected for every account in every instruction. A review table with one row per (instruction, account) pair and one column per check is tedious and effective.

## Classic bug patterns

- **Type cosplay:** two account types with compatible layouts; without a discriminator, a `User` account can be passed as an `Admin` account.
- **Duplicate mutable accounts:** passing the same account as `from` and `to` can double-count balances.
- **Non-canonical bump:** accepting any bump lets attackers derive alternate addresses.
- **Closing accounts:** transferring lamports out without zeroing data and marking closed; the account can be "revived" within the same transaction.
- **Unchecked token accounts:** trusting a token account's mint or owner fields without verifying the account is owned by the token program.
- **Token-2022 confusion:** accepting accounts owned by either the original SPL Token program or Token-2022 without handling extensions (transfer fees, hooks) that change amounts or add code paths.

## Pattern: validate in one place

Write a `validate()` function per instruction that returns typed, validated account structs. Business logic receives only validated types. This mirrors Anchor's design and makes reviews easier.

## Worked example

*Execution status: not executed in this book's CI; verify locally.*

We implement "validate in one place" for a `withdraw` instruction with three accounts, including discriminators that stop type cosplay and a duplicate-account check.

**Step 1: discriminated account types.**

```rust
pub const VAULT_TAG: [u8; 8] = *b"VAULT\0\0\0";
pub const USER_TAG:  [u8; 8] = *b"USER\0\0\0\0";

#[repr(C)]
pub struct Vault { pub authority: Pubkey, pub total: u64 }   // after 8-byte tag
#[repr(C)]
pub struct User  { pub owner: Pubkey, pub deposited: u64 }   // same size as Vault!

fn load<T: Copy>(acc: &AccountInfo, program_id: &Pubkey, tag: &[u8; 8]) -> Result<T, ProgramError> {
    if acc.owner != program_id { return Err(ProgramError::IncorrectProgramId); }
    let data = acc.try_borrow_data()?;
    if data.len() != 8 + core::mem::size_of::<T>() || &data[..8] != tag {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(*bytemuck::from_bytes::<T>(&data[8..]))   // T: bytemuck::Pod in real code
}
```

`Vault` and `User` have identical layouts. Without the tag, a user could pass their own `User` account (where `owner` is themselves) as the `Vault` and become its `authority`.

**Step 2: the validated context.**

```rust
pub struct WithdrawCtx<'a, 'info> {
    pub vault: &'a AccountInfo<'info>, pub vault_state: Vault,
    pub user: &'a AccountInfo<'info>,  pub user_state: User,
    pub signer: &'a AccountInfo<'info>,
}

pub fn validate_withdraw<'a, 'info>(program_id: &Pubkey, accs: &'a [AccountInfo<'info>])
    -> Result<WithdrawCtx<'a, 'info>, ProgramError>
{
    let [vault, user, signer] = accs else { return Err(ProgramError::NotEnoughAccountKeys) };
    if vault.key == user.key { return Err(ProgramError::InvalidArgument); }       // duplicates
    if !signer.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    if !vault.is_writable || !user.is_writable { return Err(ProgramError::InvalidArgument); }
    let vault_state: Vault = load(vault, program_id, &VAULT_TAG)?;
    let user_state:  User  = load(user,  program_id, &USER_TAG)?;
    if user_state.owner != *signer.key { return Err(ProgramError::IllegalOwner); }   // relationship
    let (pda, _) = Pubkey::find_program_address(&[b"vault"], program_id);
    if *vault.key != pda { return Err(ProgramError::InvalidSeeds); }
    Ok(WithdrawCtx { vault, vault_state, user, user_state, signer })
}
```

The business-logic function takes `WithdrawCtx` and nothing else, so it cannot touch an unvalidated account.

**Step 3: tests that try each attack.** With LiteSVM or `solana-program-test`:

| Test | Substitution | Expected error |
|---|---|---|
| type cosplay | pass a `User` account as `vault` | `InvalidAccountData` |
| wrong owner | pass a System-owned account with valid-looking bytes as `user` | `IncorrectProgramId` |
| duplicate | pass the same account as `vault` and `user` | `InvalidArgument` |
| missing signer | `signer` not signing | `MissingRequiredSignature` |
| foreign user | `user.owner` is someone else | `IllegalOwner` |
| fake vault | program-owned `Vault`-tagged account at a non-PDA address | `InvalidSeeds` |

Each row is one test. Chapter 5 shows how to generate these substitutions automatically for every instruction.

**Step 4: review question.** Does any *other* instruction create accounts with `VAULT_TAG`? If an `init_user` instruction lets the caller choose the tag or write arbitrary bytes, the discriminator is forgeable. Discriminators protect only if the program controls every write of the tag.

## Common pitfalls

- Discriminators that the program never checks on read, or that user-controlled writes can set.
- Duplicate-account checks on some account pairs but not all mutable ones.
- Re-deriving PDAs with `create_program_address` and a user-supplied bump instead of the stored canonical bump.
- Closing accounts by draining lamports without zeroing data or setting a closed tag.
- Validating token accounts' fields without checking their owner is the expected token program.
- Validation spread across business logic, so a new code path skips it.

## Exercises

1. Write a type-cosplay exploit against a program with two same-size account types and no discriminator.
2. Show a duplicate-account double-count bug and fix it.
3. Implement the "validate in one place" pattern for a three-account instruction.
4. Build the (instruction × account × check) review table for a small open-source native program and mark every empty cell.

## Further reading

- Sealevel attacks examples: <https://github.com/coral-xyz/sealevel-attacks>
- SPL Token program: <https://github.com/solana-program/token>
- Solana program security course material (Solana Foundation docs): <https://solana.com/developers>
- bytemuck (safe casting of plain-old-data): <https://docs.rs/bytemuck>
