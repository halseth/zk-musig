# zk-musig

Zero-knowledge proof generation and verification CLI for MuSig2 multi-signature operations with blinding factors.

This tool uses [RISC Zero zkVM](https://www.risczero.com/) to generate proofs for MuSig2 signature operations, allowing privacy-preserving participation in multi-signature schemes.

## Installation

```bash
cargo install --path host
```

This installs the `zk-musig` command to `~/.cargo/bin/`.

## Usage

The CLI provides two main commands: `prove` to generate proofs and `verify` to verify them.

### Generate a Proof

```bash
zk-musig prove --config config.json --output proof.json [--proof-type TYPE]
```

**Config JSON format:**
```json
{
  "coeff_salt": "64_character_hex_string",
  "blinding_factors": [
    ["alpha_hex", "beta_hex", "gamma_hex"],
    ["alpha_hex", "beta_hex", "gamma_hex"]
  ],
  "pubkeys": ["hex_pubkey1", "hex_pubkey2"],
  "pubnonces": ["hex_nonce1", "hex_nonce2"],
  "message": "message_to_sign",
  "signer_index": 0
}
```

**Proof types:**
- `default` - Default RISC Zero proof
- `fast` - Faster generation, larger size
- `succinct` - Smaller, takes longer
- `groth16` - Groth16 SNARK
- `composite` - Composite receipt

**Output format:**
```json
{
  "success": true,
  "verified": true,
  "proof": "hex_encoded_proof_data",
  "journal": {
    "pubkey": "...",
    "pubnonce": "...",
    "challenge_parity": 0,
    "nonce_parity": 1,
    "b": "...",
    "e": "..."
  },
  "proof_type": "fast"
}
```

### Verify a Proof

```bash
zk-musig verify --input proof.json
```

The verify command accepts the JSON output from the prove command and returns the same format with the `verified` field indicating whether verification succeeded.

### Examples

**Generate a fast proof:**
```bash
zk-musig prove --config my-config.json --proof-type fast --output proof.json
```

**Verify a proof:**
```bash
zk-musig verify --input proof.json
```

**Use stdin/stdout for piping:**
```bash
cat config.json | zk-musig prove --config - > proof.json
cat proof.json | zk-musig verify | jq '.verified'
```

### Help

For complete documentation, run:
```bash
zk-musig --help
zk-musig prove --help
zk-musig verify --help
```

## Input Validation

The tool validates configuration before proof generation:
- `coeff_salt` must be exactly 32 bytes (64 hex characters)
- Array lengths must match: `pubkeys.len() == pubnonces.len() == blinding_factors.len()`
- `signer_index` must be within bounds (`< pubkeys.len()`)
- All hex fields must be valid hexadecimal strings
- All scalar values must be valid

Validation errors exit with code 2 and provide clear error messages.

## Output Format

- **JSON output** goes to stdout
- **Progress messages** go to stderr
- This allows easy piping and redirection: `zk-musig prove --config config.json > proof.json 2> progress.log`

## Exit Codes

- `0` - Success
- `1` - Runtime error
- `2` - Invalid input/configuration

## Development

### Project Structure

```text
zk-musig/
├── host/           # CLI application (host code)
│   └── src/
│       └── main.rs
└── methods/        # zkVM guest code
    └── guest/
        └── src/
            └── main.rs
```

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run without installing
cargo run -- prove --config config.json
```

### Development Mode

For faster iteration during development:

```bash
RISC0_DEV_MODE=1 cargo run -- prove --config config.json
```

Note: Dev mode proofs have no cryptographic integrity and should only be used for testing.

## Technical Details

- **zkVM:** RISC Zero version 3.0.1
- **Signature scheme:** MuSig2 with taproot tweaking
- **Curve:** secp256k1 (via k256 crate)
- **Proof systems:** Supports multiple backends (STARK, Groth16, composite)

## License

See [LICENSE](LICENSE) file.
