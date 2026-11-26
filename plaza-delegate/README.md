# Plaza Delegate (`plaza-delegate`)

`plaza-delegate` provides origin-isolated secret storage and Ed25519 signing operations for the FreeTalk-Plaza web application using Freenet's direct `DelegateCtx` host-function API (`get_secret`, `set_secret`, `remove_secret`).

## Security Model

1. **Attested WebApp Origin**: Only `MessageOrigin::WebApp(ContractInstanceId)` callers are accepted. Inter-delegate calls (`MessageOrigin::Delegate`), missing origins, and unknown origin variants are rejected.
2. **Disjoint Keyspace Namespacing**: All keys are partitioned per base58-encoded origin contract ID using disjoint namespace tags so arbitrary client keys can never collide with internal metadata or signing keys:
   - Data entries: `{origin_b58}:k:{hex(key_bytes)}`
   - Origin key index: `{origin_b58}:idx`
   - Board signing keys: `signing_key:{origin_b58}:{board_key_b58}`
3. **Private Key Containment**: Board Ed25519 signing keys stored via `StoreSigningKey` never leave the delegate. Clients only receive public keys (`GetPublicKey`) and signatures (`Sign*`). Key material is wiped from local stack/heap buffers after each operation, and all-zero signing keys are rejected.
4. **Bounds & Integrity**:
   - Key size cap: 1 KiB (`MAX_KEY_BYTES`)
   - Value size cap: 8 MiB (`MAX_VALUE_BYTES`)
   - Key index cap: 4,096 keys per origin (`MAX_INDEX_KEYS`)
   - Sign payload cap: 2 MiB (`MAX_SIGN_PAYLOAD_BYTES`)
   - Corrupt CBOR key indexes return `DelegateError::Deser` rather than silently resetting the index.

## Supported Operations (`ChatDelegateRequestMsg`)

- **Key-Value Store**: `StoreRequest`, `GetRequest`, `DeleteRequest`, `ListRequest`
- **Signing Keys**: `StoreSigningKey`, `GetPublicKey`
- **Signing**: `SignMessage`, `SignMember`, `SignBan`, `SignConfig`, `SignMemberInfo`, `SignSecretVersion`, `SignEncryptedSecret`, `SignUpgrade`, `SignAdmin` (correlated by `request_id`)
