Verify keplr signature
===

Usage: 
```rust
let signature: Signature = serde_json::from_str(your_serialized_signature_from_keplr);
let is_signature_ok = verify_arbitrary(wallet_pubkey, signature.pub_key.sig_value, b"your expected signed data", &signature);
```

