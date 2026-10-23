# Glossary

- **Account:** Solana's unit of state, owned by a program.
- **Owner (account):** the program allowed to modify an account's data and debit its lamports.
- **PDA:** Program Derived Address, derived from seeds and a bump.
- **Canonical bump:** the highest bump producing a valid PDA.
- **Seed collision:** two different resources deriving the same PDA because seeds omit a distinguishing value or concatenate ambiguously.
- **CPI:** Cross-Program Invocation.
- **Arbitrary CPI:** invoking a program whose ID was supplied by the caller and not checked.
- **Signer privilege extension:** outer-transaction signers remaining signers inside a CPI.
- **Discriminator:** bytes identifying an account or instruction type.
- **Type cosplay:** passing one account type as another.
- **Account substitution testing:** replacing each account in a valid instruction with a wrong one and asserting failure.
- **Upgrade authority:** key allowed to replace an upgradeable program's code.
- **Verifiable build:** deterministic build whose hash can be compared with deployed program data.
- **sBPF:** Solana's variant of eBPF bytecode.
- **SVM:** Solana Virtual Machine/runtime.
- **Differential testing:** running identical inputs through independent implementations and comparing results.
- **Token-2022:** the newer SPL token program with extensions such as transfer fees and transfer hooks.
