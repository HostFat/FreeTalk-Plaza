# Specifica del contratto `plaza-topic`

Versione: 1 (bozza di implementazione).
Stato: Fase 0. Nessuna migrazione delle vecchie board.

## 1. Scopo

Un contratto per ogni discussione. La board contiene l'indice, le sezioni, i
membri, i ruoli e la moderazione; il topic contiene il titolo, il corpo, le
risposte e le azioni di moderazione della discussione.

Il contratto è autonomo: valida da solo partecipanti, post e azioni usando la
chiave dell'owner della board e i record di autorità che porta con sé. Non
legge lo stato della board.

## 2. Parametri e chiave

```rust
TopicParamsV1 {
    protocol_version: u16,      // 1
    board_owner: VerifyingKey,  // owner fondatore della board
    topic_id: [u8; 32],         // id casuale scelto dall'autore
    part: u32,                  // 0 per la prima parte
}
```

- La chiave è `ContractKey::from_params_and_code(params, code)`. I parametri
  non cambiano mai; `part` distingue le parti di un topic lungo.
- `TopicId = MessageId` e `SectionId = MessageId` (32 byte) per riusare i tipi
  esistenti.
- Un cambio di WASM cambia il code hash e quindi la chiave. Il campo
  `protocol_version` nell'indice della board permette al client di risolvere
  la chiave di un topic creato con una versione precedente.
- L'owner fondatore resta nei parametri anche dopo un trasferimento di
  ownership; la catena `OwnershipV1` dentro lo stato prova l'owner corrente.

## 3. Stato

```rust
TopicStateV1 {
    version: u16,
    header: AuthorizedTopicHeaderV1,
    section: AuthorizedSectionSnapshotV1,
    authority: TopicAuthorityV1,
    participants: Vec<AuthorizedParticipantV1>,
    trust: Vec<AuthorizedTrustV1>,
    posts: BTreeMap<MessageId, AuthorizedTopicPostV1>,
    actions: Vec<AuthorizedTopicActionV1>,
    approvals: Vec<AuthorizedTopicApprovalV1>,
    generation: TopicGenerationV1,
}
```

### 3.1 Header

```rust
TopicHeaderV1 {
    topic_id: [u8; 32],
    author: MemberId,
    author_key: VerifyingKey,
    section: Option<SectionId>,
    section_chain: Vec<SectionId>,
    title: SealedBytes,
    body: SealedBytes,
    auto_moderated: bool,
    created_at: i64,
    nonce: [u8; 16],
}

AuthorizedTopicHeaderV1 {
    header: TopicHeaderV1,
    signature: Signature,
}
```

- Firmato dall'autore. `author_key` deve corrispondere a `author`.
- `SealedBytes` è pubblico sulle board pubbliche e sigillato con la chiave
  della board o della sezione su quelle private.
- `topic_id` deve corrispondere ai parametri.
- `section_chain` è la catena di sezioni al momento della creazione; serve
  per lo scope dei moderatori e per l'ACL.
- `auto_moderated` abilita la cancellazione delle risposte da parte
  dell'autore del topic.

### 3.2 Snapshot della sezione

```rust
SectionSnapshotV1 {
    section: SectionId,
    parent: Option<SectionId>,
    chain: Vec<SectionId>,
    allowed_roles: Vec<RoleId>,
    sealed_name: Option<SealedBytes>,
    hidden: bool,
    images_allowed: bool,
    auto_moderated_topics: Option<bool>,
    generation: u64,
}

AuthorizedSectionSnapshotV1 {
    snapshot: SectionSnapshotV1,
    signer: MemberId,
    signature: Signature,
}
```

- Firmato dall'owner o da un admin al momento della creazione, oppure
  aggiornato con un'azione di moderazione.
- Il topic verifica l'accesso alla sezione confrontando `allowed_roles` con le
  assegnazioni di ruolo dei partecipanti.

### 3.3 Autorità

```rust
TopicAuthorityV1 {
    ownership: OwnershipV1,
    admins: AdminsV1,
    roles: RolesV1,
    bans: BansV1,
    ban_revocations: BanRevocationsV1,
    suspensions: SuspensionsV1,
    policy: AuthorizedTopicPolicyV1,
}
```

- Record firmati con gli stessi tipi della board.
- `roles` contiene tutte le definizioni; delle assegnazioni solo quelle dei
  partecipanti e dei moderatori. `bans` e `suspensions` solo per i
  partecipanti.
- `policy` è la configurazione che serve al topic: `read_only`,
  `approval_required`, rate limit, immagini, auto-moderazione, reaction,
  dimensione massima del post.

```rust
TopicPolicyV1 {
    read_only: bool,
    approval_required: bool,
    rate_window_ms: u64,
    max_posts_per_window: u32,
    images_allowed: bool,
    auto_moderated_topics: bool,
    reactions_enabled: bool,
    max_post_size: usize,
    generation: u64,
    updated_at: i64,
}
```

### 3.4 Partecipanti

```rust
ParticipantCertificateV1 {
    member: AuthorizedMember,
    chain: Vec<AuthorizedMember>,          // vuota se invited_by == owner
    token: Option<AuthorizedInviteToken>,  // per il join da link
    join_proof: Option<JoinProof>,
}

AuthorizedParticipantV1 {
    member_id: MemberId,
    member_vk: VerifyingKey,
    certificate: ParticipantCertificateV1,
    joined_at: i64,
    signature: Signature,
}
```

- `member` è il record firmato dall'inviter. La catena risale fino all'owner;
  ogni record è verificato con la chiave dell'inviter.
- Per il join da token, `member` è self-signed, `join_proof` prova il possesso
  della chiave del link e `token` è il record firmato dal manager con la sua
  authority.
- `member_id` deve essere `MemberId::from(member_vk)`.
- La firma del partecipante copre il record con la firma stessa esclusa.

```rust
TrustV1 {
    member_id: MemberId,
    trusted: bool,
    generation: u64,
    signed_by: MemberId,
}

AuthorizedTrustV1 {
    trust: TrustV1,
    authority: Option<AuthorityProof>,
    signature: Signature,
}
```

- Firmato da un moderatore con potere di approvazione/delete.
- `trusted` sblocca i post del partecipante nella coda di approvazione.
- La generazione più alta vince; un tombstone vince a parità.

### 3.5 Post

```rust
TopicPostV1 {
    author: MemberId,
    parent: Option<MessageId>, // None = risposta diretta al topic
    content: SealedBytes,      // testo o payload di poll
    images: Vec<ImageRef>,
    created_at: i64,
    nonce: [u8; 16],
}

AuthorizedTopicPostV1 {
    post: TopicPostV1,
    signature: Signature,
}
```

- L'id è l'hash BLAKE3 del post serializzato senza la firma; non è un campo
  separato.
- L'autore deve essere l'owner, un partecipante, o un post spostato con il
  record originale.
- I post sono in un `BTreeMap` per id; l'ordine cronologico si calcola in
  lettura, non si riordina lo stato a ogni update.
- `parent` deve esistere nello stesso topic (o essere `None`).
- Un post eliminato resta come record immutabile; l'eliminazione è un'azione
  `Delete` (o `Purge`) e i client non lo mostrano. La modifica è un'azione
  `Edit`: il contratto conserva il post originale e l'azione firmata.
- `images` contiene riferimenti a `plaza-blob`; i byte non entrano nello stato.

### 3.6 Azioni

```rust
TopicActionV1 {
    kind: TopicActionKind,
    target: MessageId,          // header o post
    payload: SealedBytes,       // edit, move, poll, ...
    generation: u64,
    created_at: i64,
    signer: MemberId,
}

TopicActionKind {
    Edit, Delete, Pin, Unpin, Close, Open, Announce, Unannounce,
    Move, Merge, Split, Hide, Restore, Purge, Approve, Reject,
    EditPoll, MovePost, SplitPost,
}

AuthorizedTopicActionV1 {
    action: TopicActionV1,
    authority: Option<AuthorityProof>,
    signature: Signature,
}
```

- L'autore può editare/eliminare i propri post.
- Un moderatore può agire con `AuthorityProof` e con lo scope della sezione;
  il topic verifica il potere (`Edit`, `Delete`, `Close`, `Pin`, `Move`) e la
  catena di sezioni.
- Un'azione di hide/purge nasconde il topic nella board e nel client; non
  cancella fisicamente il contratto dalla rete.
- Le generazioni rendono il merge deterministico: vince la generazione più
  alta, a parità vince il digest minore.

### 3.7 Approvazioni

```rust
TopicApprovalV1 {
    target: MessageId,
    approved: bool,
    generation: u64,
    scope: Option<SectionId>,
    signed_by: MemberId,
    created_at: i64,
}

AuthorizedTopicApprovalV1 {
    approval: TopicApprovalV1,
    authority: Option<AuthorityProof>,
    signature: Signature,
}
```

- Un post di un partecipante non `trusted` resta in attesa finché un
  moderatore non lo approva.
- L'approvazione di un post può rendere `trusted` l'autore nella sezione
  (stessa regola della board attuale, limitata al topic e alla sezione).
- Il client mostra i post in attesa solo all'autore e ai moderatori.

### 3.8 Generazione

```rust
TopicGenerationV1 {
    part: u32,
    post_count: u32,
    closed_at: Option<i64>,
    next_part: Option<u32>,
    previous_hash: Option<[u8; 32]>,
}
```

- Quando il topic raggiunge `MAX_POSTS` o `MAX_TOPIC_STATE_BYTES`, un client
  crea la parte `part + 1` con gli stessi header/partecipanti/autorità, un
  record `previous_hash` e `next_part` nella parte precedente.
- L'indice della board aggiorna `part`; il client legge dalla parte corrente e
  carica le precedenti su richiesta.
- La coerenza tra le parti è verificata dal client; i contratti non si
  vedono.

## 4. Limiti

| Limite | Valore |
|---|---|
| `MAX_TOPIC_STATE_BYTES` | 8 MiB |
| `MAX_POSTS` | 5.000 per parte |
| `MAX_PARTICIPANTS` | 512 |
| `MAX_POST_BYTES` | 16 KiB |
| `MAX_PARTS` | 64 |
| `MAX_TITLE_BYTES` | 512 |
| `MAX_BODY_BYTES` | 64 KiB |
| `MAX_IMAGES_PER_POST` | 4 |
| `MAX_ACTIONS` | 10.000 |
| Rate limit | dalla `TopicPolicyV1` |

- Un post oltre i limiti viene rifiutato dal contratto.
- Lo stato oltre `MAX_TOPIC_STATE_BYTES` viene rifiutato; serve una nuova
  parte.
- I timestamp sono firmati; il contratto non ha un orologio. La finestra del
  rate limit usa i tempi firmati, come la board.

## 5. Delta, merge e summary

`TopicDeltaV1` contiene solo record nuovi:

```rust
TopicDeltaV1 {
    header: Option<AuthorizedTopicHeaderV1>,
    section: Option<AuthorizedSectionSnapshotV1>,
    authority: Option<TopicAuthorityDeltaV1>,
    participants: Vec<AuthorizedParticipantV1>,
    trust: Vec<AuthorizedTrustV1>,
    posts: Vec<AuthorizedTopicPostV1>,
    actions: Vec<AuthorizedTopicActionV1>,
    approvals: Vec<AuthorizedTopicApprovalV1>,
    generation: Option<TopicGenerationV1>,
}
```

- `apply_delta` verifica i record nuovi e le invarianti risultanti; non
  rifirma né ricontrolla tutti i record storici.
- `merge` unisce due stati: per i post vince l'id (immutabile); per azioni,
  approvazioni, trust e autorità vince la generazione più alta, poi il digest
  minore.
- `summarize` restituisce `TopicStateSummaryV1` con `header_hash`,
  `(post_id, created_at, signature_prefix)` per ogni post e le generazioni di
  azioni/approvazioni/trust. Il summary cresce con i post ma resta molto più
  piccolo dello stato.
- `delta(summary)` restituisce i record mancanti.
- `validate_state` fa la verifica completa; `update_state` usa il percorso
  incrementale e poi verifica le invarianti.

## 6. Autorità e moderazione

- Owner: la chiave nei parametri, più la catena `OwnershipV1`.
- Admin: record firmato dall'owner, con revoca.
- Ruolo: definizione firmata dall'owner/admin, assegnazione firmata, scope di
  sezione. Il topic verifica `AuthorityProof` come la board.
- Ban: record firmato con la prova del target; il topic rifiuta i post
  dell'autore bannato dopo il timestamp del ban.
- Sospensione: come il ban, con una scadenza; blocca la scrittura ma non la
  lettura.
- Warning: restano nella board, non cambiano i permessi.
- Approvazioni: come in 3.7.
- Sezione: `SectionSnapshotV1` con ACL; il topic verifica che il partecipante
  abbia un ruolo ammesso.
- Propagazione: i client pubblicano i record di autorità aggiornati nei topic
  attivi. Un topic non aggiornato può accettare un post da un membro appena
  bannato finché il record non arriva. È un limite noto; la UI filtra comunque
  i post degli autori bannati e i client riprovano la propagazione.

## 7. Privacy

- Board pubblica: header e post possono essere in chiaro; `SealedBytes`
  pubblico.
- Board privata: titolo, corpo, post e payload delle azioni sono sigillati con
  la chiave della board o della sezione. Il contratto vede solo dimensioni,
  id, autori, timestamp e firme.
- Il contratto non decifra nulla e non può leggere il contenuto per validare
  il testo; la validazione del contenuto è del client.
- Le anteprime nell'indice sono sigillate allo stesso modo.

## 8. Versioning

- `protocol_version = 1` per la prima versione.
- Il topic è progettato con un envelope stabile: i campi nuovi sono opzionali
  e con `serde(default)`.
- Un cambio di schema che richiede una nuova validazione crea una nuova
  `protocol_version` e una nuova parte/continuation; il client mantiene la
  mappa versione → code hash e il WASM precedente per la lettura.
- Il contratto espone un revision marker per forzare il cambio di hash quando
  serve.

## 9. Test minimi

- Creazione, post, risposta, edit, delete.
- Due client convergenti; merge commutativo, associativo, idempotente.
- Catena di invito valida/invalida; token join; partecipante estraneo.
- Moderatore con e senza prova; scope di sezione; ruolo revocato.
- Ban prima e dopo il post; sospensione.
- Pin/close/announce; move/split/merge; hide/restore/purge.
- Poll e reaction; immagini.
- Contenuto sigillato illeggibile al contratto.
- Limiti di dimensione, numero post, partecipanti.
- Generazione e continuation.
- CBOR round-trip e firme manomesse.
