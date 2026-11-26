# Strategia di upgrade senza perdita delle board (FreeTalk-Plaza)

Su Freenet l'identità (`ContractKey`) di un contratto è derivata da
`(hash(WASM), CBOR(parameters))`. Di conseguenza, qualsiasi modifica ai byte del
WASM di un contratto genera una **nuova** `ContractKey`. Questo documento
definisce le tre strategie che FreeTalk-Plaza combina per evitare la perdita
silenziosa di board, sezioni e discussioni quando il protocollo evolve.

## 1. Evoluzione compatibile senza re-key (preferita in produzione)

Quando il codice WASM non viene toccato (solo UI, layout, indicizzazione locale,
eviction LRU, viste o correzioni client-side):

- **Zero re-key**: nessun WASM cambia, tutte le board/sezioni/topic esistenti
  restano sulla stessa `ContractKey`.
- Quando uno schema futuro dovrà estendersi, tutti i nuovi campi opzionali
  devono usare `#[serde(default, skip_serializing_if = "...")]` per mantenere
  stabili le firme sui record firmati in precedenza (come già fatto per
  `AdminRevocation.appointed_at`, `Configuration.succession_timelock_secs`,
  `AuthorizedTopicPageListV1.authority`, `UpgradeV1.new_revision`).

## 2. Coesistenza multi-versione dei contratti topic (`protocol_version`)

Ogni entry nell'indice (`TopicEntryV1.protocol_version`) e nei parametri del
topic (`TopicParamsV1.protocol_version`) registra la versione di protocollo del
contratto che ospita la discussione.

- `ui/src/components/app/topic_contract.rs` espone la dispatch table
  `topic_code_for_version(protocol_version: u16) -> Option<&'static [u8]>` e
  `topic_key_for_version(...)`.
- Quando verrà introdotta una v2 di `plaza-topic`, il client continuerà a
  includere `plaza_topic_contract_v1.wasm` in sola-manutenzione per leggere e
  rispondere ai topic v1 esistenti, mentre i nuovi topic nasceranno con
  `protocol_version = 2` sul nuovo WASM — **senza mai rompere né ri-chiavare le
  discussioni storiche**.

## 3. Migrazione guidata della board madre (`AuthorizedUpgradeV1`)

Quando una breaking change della board madre rende inevitabile un bump di
`CONTRACT_REVISION` (e quindi un nuovo `ContractKey` per `plaza-contract`):

1. **Rilevamento automatico nel client** (`Boards::refresh_contract_keys` in
   `ui/src/board_data.rs`): confronta il `contract_key` salvato nel delegate con
   quello derivato dal WASM corrente.
2. **Pubblicazione del puntatore firmato** (`send_upgrade_pointers` in
   `ui/src/components/app/freenet_api/board_synchronizer.rs`):
   - L'owner corrente (anche **post-transfer o post-successione**, grazie a
     `AuthorizedUpgradeV1::verify_against` introdotto in rev 38) firma un
     `UpgradeV1 { owner_member_id, version, new_chatboard_address, new_revision, created_at }`
     e lo invia sul vecchio contratto board.
   - Il vecchio contratto verifica la firma contro la catena `OwnershipV1`
     corrente e conserva il puntatore in `board_state.upgrade`.
3. **Visibilità per i peer**: i client che aprono ancora la board precedente
   ricevono `board_state.upgrade` via sync e mostrano lo stato di upgrade verso
   la nuova revisione senza silenziare l'errore.
4. **Delegate stabile (`wasm-tool check`)**:
   - I delegate (`plaza-delegate`, `plaza-dm-delegate`) non devono **mai**
     essere ricompilati durante i normali bump dei contratti board/topic/feed
     (si usa sempre `wasm-tool sync --only ...`).
   - Se un aggiornamento del delegate è inevitabile, la sua vecchia chiave va
     registrata in `legacy_delegates.toml` tramite `cargo make add-migration`
     così il client migra automaticamente chiavi, profili, board e indice di
     ricerca dal delegate precedente.

## Checklist pre-release per ogni cambio di schema

1. Raggruppare tutti i cambi di schema del blocco in **un solo** bump di
   `CONTRACT_REVISION` in `common/src/lib.rs`.
2. Ricompilare solo i 7 contratti con `wasm-tool sync --only ...` (non i
   delegate) e verificare `wasm-tool check`.
3. Verificare la suite SLO automatica (`cargo test -p plaza-core --test scale_slo --release`).
4. Dichiarare esplicitamente il re-key nel commit e in `docs/HANDOFF.md`.
