# Specifica del contratto `plaza-topic`

Versione: 1 (implementata).
Stato: fasi 0–4 completate; move e merge tra sezioni pubblicati nella build
locale v711. Le nuove board topic usano lo shard per sezione come default e i
topic usano una radice Merkle dell'autorita' con prove per membro.
Nessuna migrazione delle vecchie board.

## Stato dell'implementazione

- `topic-core`: tipi, validazione, delta, merge, summary e continuation.
- `topic-contract`: entry point Freenet (`validate_state`, `update_state`,
  `summarize_state`, `get_state_delta`) con il limite di 8 MiB.
- `plaza-core`: `BoardModeV1`, `SectionsV1`, `TopicIndexV1` con entry,
  attività, flag, report e risoluzioni.
- Client `ui/src/components/app/topic_contract.rs`; UI
  `topic_index_view.rs`, `topic_view.rs`, ricerca, notifiche e code in Manage.
- Test: 51 in `topic-core`, 330 in `plaza-core`, 15 scenari real-node dei
  topic (shard della sezione, ruolo-prima-del-topic, draft e parti precedenti
  inclusi) e 116 test statici Playwright.

Funzioni disponibili: topic creati dall'owner e dai membri, topic privati,
modifica di topic e risposte, flag owner (pin/close/announce/hide/approve),
sezioni, propagazione di ban/ruoli/sospensioni, approvazioni anche da
moderatori non owner, poll e reaction, move/merge/split, continuation,
report con risoluzione, ricerca sull'indice, notifiche dei topic non letti e
draft per topic.

La build v609 introduce la verifica incrementale dei delta e il percorso
rapido per gli aggiornamenti che toccano solo l'indice della board. La build
v608 aveva ridotto i limiti di topic e indice e aggiunto i rate limit. Ogni
cambio del WASM ri-chiave board e topic, quindi le board e i topic creati con
le build precedenti vanno ricreati.

Limiti noti: le approvazioni non-owner condividono il percorso owner ma non
hanno uno scenario e2e dedicato; lo stato di lettura è per board/dispositivo;
la ricerca copre i metadati dell'indice, non il testo completo; la radice
dell'autorità è un commitment Merkle non firmato, quindi un client può
scegliere un sottoinsieme (come già poteva fare con la copia completa); una
radice firmata dall'owner è il prossimo passo. La suite real-node è isolata da
un marker nel delegate e passa 15/15 in sequenza.

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
- Un cambio di WASM cambia il code hash e quindi la chiave. L'indice della
  board salva `protocol_version` per ogni topic; il client attuale supporta
  solo la versione 1. Una versione futura richiede una mappa versione → code
  hash nel client, non ancora implementata.
- L'owner fondatore resta nei parametri anche dopo un trasferimento di
  ownership; la catena `OwnershipV1` dentro lo stato prova l'owner corrente.

## 3. Stato

```rust
TopicStateV1 {
    version: u16,
    header: Option<AuthorizedTopicHeaderV1>,
    section: Option<AuthorizedSectionSnapshotV1>,
    authority: TopicAuthorityV1,
    participants: Vec<AuthorizedParticipantV1>,
    trust: Vec<AuthorizedTrustV1>,
    posts: BTreeMap<MessageId, AuthorizedTopicPostV1>,
    actions: Vec<AuthorizedTopicActionV1>,
    approvals: Vec<AuthorizedTopicApprovalV1>,
    generation: TopicGenerationV1,
}
```

`header` e `section` sono `Option` per permettere uno stato scheletro prima
dell'header; la creazione li riempie nello stesso update. `authority`,
`participants`, `trust`, `posts`, `actions`, `approvals` e `generation` hanno
`serde(default)` per la compatibilità in avanti.

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
    signed_at: i64,
}

AuthorizedSectionSnapshotV1 {
    snapshot: SectionSnapshotV1,
    signer: Option<MemberId>,
    signer_key: Option<VerifyingKey>,
    authority: Option<Box<AuthorityProof>>,
    signature: Signature,
}
```

- Firmato dall'owner o da un admin al momento della creazione, oppure
  aggiornato con un'azione di moderazione (lo snapshot più recente sostituisce
  il precedente).
- Il topic verifica l'accesso alla sezione confrontando `allowed_roles` con le
  assegnazioni di ruolo dei partecipanti.

### 3.3 Autorità

```rust
TopicAuthorityV1 {
    ownership: OwnershipV1,
    admins: AdminsV1,
    roles: RolesV1,                 // definizioni; le assegnazioni stanno nelle prove
    bans: BansV1,                   // vuoto nei topic nuovi
    ban_revocations: BanRevocationsV1,
    suspensions: SuspensionsV1,
    policy: Option<AuthorizedTopicPolicyV1>,
    source_configuration: Option<AuthorizedConfigurationV1>,
    root: Option<AuthorityRootV1>,
    member_proofs: Vec<MemberStatusProofV1>,
}
```

- Record firmati con gli stessi tipi della board.
- `roles` contiene le definizioni; delle assegnazioni solo quelle dei
  partecipanti e dei moderatori. `bans` e `suspensions` viaggiano nelle prove
  del membro, non in liste globali.
- `AuthorityRootV1 { version, epoch, content_hash, digest }` è la radice
  Merkle degli stati dei membri. `MemberStatusV1` raggruppa il record del
  membro, le definizioni dei suoi ruoli, le assegnazioni, i ban, le revoca e
  le sospensioni. Il topic conserva la radice e una prova per ogni
  partecipante/moderatore che referenzia.
- `epoch` è un timestamp monotono usato nel merge: una radice più vecchia non
  sostituisce quella corrente. `content_hash` identifica il contenuto
  dell'autorità e permette a `sync_topic_authority` di evitare un update
  quando radice e prove non cambiano.
- La radice non è firmata: il contratto verifica il percorso Merkle e i record
  firmati, ma non l'autenticità della radice. Il passo successivo è una radice
  firmata dall'owner pubblicata nella board, così anche i topic creati da un
  membro non possono scegliere un sottoinsieme.
- Una radice può includere un membro bannato che la board ha già rimosso:
  `AuthorityTreeV1::from_board` usa `UserBan.target_member` come foglia, così
  il topic mostra "Banned author" e rifiuta i post successivi.
- Le definizioni dei ruoli restano complete: un invito via token e un
  moderatore con ruolo hanno bisogno della definizione anche senza
  un'assegnazione firmata.
- `policy` è firmata dall'owner. Un membro che non può firmarla porta
  `source_configuration`, la configurazione owner-signed della board, e il
  topic deriva la policy effettiva da quella (`effective_policy`).
- La policy effettiva copre `read_only`, `approval_required`, rate limit,
  immagini, auto-moderazione, reaction e dimensione massima del post.

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

ParticipantRecordV1 {
    member_id: MemberId,
    member_vk: VerifyingKey,
    certificate: ParticipantCertificateV1,
    joined_at: i64,
}

AuthorizedParticipantV1 {
    record: ParticipantRecordV1,
    signature: Signature,
}
```

- `member` è il record firmato dall'inviter. La catena risale fino all'owner;
  ogni record è verificato con la chiave dell'inviter. La profondità massima
  della catena è `MAX_JOIN_DEPTH`.
- Per il join da token, `member` è self-signed, `join_proof` prova il possesso
  della chiave del link e `token` è il record firmato dal manager con la sua
  authority.
- `member_id` deve essere `MemberId::from(member_vk)`.
- La firma del partecipante copre `ParticipantRecordV1` con la firma stessa
  esclusa.

```rust
TrustV1 {
    member_id: MemberId,
    trusted: bool,
    generation: u64,
    signed_by: MemberId,
    created_at: i64,
}

AuthorizedTrustV1 {
    trust: TrustV1,
    signer_key: Option<VerifyingKey>,
    authority: Option<Box<AuthorityProof>>,
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

TopicPostContentV1 {
    Text(String),
    Poll(PollContentV1),
}
```

- `content` contiene il CBOR di `TopicPostContentV1` sigillato come il resto
  del post: il contratto vede solo i byte.
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
    Edit, Delete, Hide, Restore, Purge,
    Pin, Unpin, Close, Open, Announce, Unannounce,
    Move, Merge, Split, Approve, Reject, EditPoll,
    React, Unreact, Vote,
}

AuthorizedTopicActionV1 {
    action: TopicActionV1,
    signer_key: Option<VerifyingKey>,
    authority: Option<Box<AuthorityProof>>,
    signature: Signature,
}
```

- L'autore può editare/eliminare i propri post e modificare il proprio poll.
- Un moderatore può agire con `AuthorityProof` e con lo scope della sezione;
  il topic verifica il potere (`Edit`, `Delete`, `Close`, `Pin`, `Move`) e la
  catena di sezioni. `Hide`, `Restore`, `Approve` e `Reject` richiedono
  `Delete`; `Purge` richiede owner o admin.
- `Move` porta nel payload pubblico il nuovo `SectionSnapshotV1`;
  `Merge` porta l'id del topic di destinazione; `Split` porta l'id del nuovo
  topic per la risposta.
- `React`, `Unreact` e `Vote` sono riservate ai membri della board, non
  accettano `AuthorityProof` e vengono rifiutate per autori bannati o
  sospesi.
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
    signer_key: Option<VerifyingKey>,
    authority: Option<Box<AuthorityProof>>,
    signature: Signature,
}
```

- Un post di un partecipante non `trusted` resta in attesa finché un
  moderatore non lo approva. Vale il potere `Delete`: owner, admin o ruolo
  con `Delete` nella sezione; il moderatore non owner allega
  `AuthorityProof`.
- L'approvazione di un post può rendere `trusted` l'autore nella sezione
  (stessa regola della board attuale, limitata al topic e alla sezione).
- Il client mostra i post in attesa solo all'autore e ai moderatori.

### 3.8 Generazione

```rust
TopicGenerationV1 {
    part: u32,
    closed_at: Option<i64>,
    next_part: Option<u32>,
    previous_hash: Option<[u8; 32]>,
}
```

- Quando il topic raggiunge `MAX_POSTS` o 7/8 di `MAX_TOPIC_STATE_BYTES`, il
  client crea la parte `part + 1` con gli stessi header/partecipanti/autorità,
  un record `previous_hash` e `next_part` nella parte precedente. La
  continuation manuale usa lo stesso percorso. `previous_hash` è obbligatorio
  per `part > 0` e vietato per `part == 0`.
- L'indice della board aggiorna `part`; il client legge dalla parte corrente e
  carica le precedenti su richiesta.
- La coerenza tra le parti è verificata dal client; i contratti non si
  vedono.

## 4. Limiti

| Limite | Valore |
|---|---|
| `MAX_TOPIC_STATE_BYTES` | 512 KiB |
| `MAX_POSTS` | 200 per parte |
| `MAX_PARTICIPANTS` | 512 |
| `MAX_POST_BYTES` | 16 KiB |
| `MAX_PARTS` | 64 |
| `MAX_TITLE_BYTES` | 512 |
| `MAX_BODY_BYTES` | 64 KiB |
| `MAX_IMAGES_PER_POST` | 4 |
| `MAX_ACTIONS` | 2.000 |
| `MAX_APPROVALS` | 2.000 |
| `MAX_JOIN_DEPTH` | 64 |
| Rate limit post | dalla `TopicPolicyV1` |
| Creazione topic | 30 per autore/ora |
| Report | 60 per reporter/ora |

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
    authority: Option<TopicAuthorityV1>,
    participants: Vec<AuthorizedParticipantV1>,
    trust: Vec<AuthorizedTrustV1>,
    posts: Vec<AuthorizedTopicPostV1>,
    actions: Vec<AuthorizedTopicActionV1>,
    approvals: Vec<AuthorizedTopicApprovalV1>,
    generation: Option<TopicGenerationV1>,
}
```

- `apply_delta` mantiene la verifica completa per i chiamanti generici.
- `apply_delta_incremental` verifica solo i record del delta, più i controlli
  di forma, limiti e autorità quando cambiano. Il contratto lo usa per
  `UpdateData::Delta`; `UpdateData::State` fa ancora la verifica completa.
- `merge` unisce due stati: per i post vince l'id (immutabile); per azioni,
  approvazioni, trust e autorità vince la generazione più alta, poi il digest
  minore.
- `summarize` restituisce `TopicStateSummaryV1` con gli hash di header,
  sezione e autorità, gli hash dei partecipanti, le generazioni di trust, gli
  id dei post, gli id delle azioni, le generazioni delle approvazioni e la
  generazione del topic. Cresce con i post ma resta molto più piccolo dello
  stato.
- `delta(summary)` restituisce i record mancanti.
- `validate_state` fa la verifica completa; `update_state` usa
  `apply_delta_incremental` per i delta e riserva `verify` ai merge di stato
  completo.
- Sul lato board, un delta che non tocca solo l'indice passa da
  `verify_delta`: verifica le parti cambiate e le interazioni
  membri/ban/ruoli/admin, mentre non rifirma tutti i topic già validati.

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
- Approvazioni: come in 3.7; il moderatore non owner allega la prova.
- Reaction e voti: solo membri, senza prova di moderazione; un autore bannato
  o sospeso viene rifiutato.
- Report: vivono nell'indice della board, non nel topic. La risoluzione è un
  record firmato da un moderatore con potere `Delete`.
- Limiti di frequenza: 30 topic per autore/ora e 60 report per reporter/ora,
  verificati dal contratto sui timestamp firmati; il client rifiuta prima di
  pubblicare.
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
  `protocol_version` e una nuova chiave. Il client attuale supporta solo la
  versione 1: una versione futura richiede la mappa versione → code hash e il
  WASM precedente nel client, non ancora implementati.
- Il contratto espone un revision marker per forzare il cambio di hash quando
  serve.

## 9. Indice della board

Le nuove board topic usano `BoardModeV1::SectionedTopicIndex`; le board
`TopicIndex` esistenti restano leggibili e le board legacy restano
`LegacyMessages`. Nessuna migrazione automatica.

- `SectionsV1`: sezioni con parent, nome (sigillato sulle private), ruoli
  ammessi, `hidden`, `is_group`, `images_allowed`, `auto_moderated_topics`,
  generazione e tombstone.
- `TopicIndexV1`:
  - `entries`: topic_id, part, protocol_version, autore, sezione,
    section_chain, titolo e anteprima (sigillati sulle private), header_hash,
    created_at, generazione;
  - `activity`: last_activity, last_post_id, reply_count, pending_approvals;
  - `flags`: pin, close, announce, merge, hide, approve, section, part;
  - `reports` e `report_resolutions`.
- Le entry e l'activity sono firmate dall'autore; flag e risoluzioni
  richiedono l'autorità di moderazione. La sezione effettiva è quella
  dell'ultimo flag `Section`; la parte quella dell'ultimo flag `Part`.
- La board non contiene i post: conserva solo indice, sezioni e stato di
  moderazione. Ogni indice (madre o figlia) è limitato a 2.000 topic, 2.000
  righe di attività, 16.000 flag e 2.000 report, perché viaggia in pieno con
  ogni update della sua sezione.
- Con `BoardModeV1::SectionedTopicIndex` la board madre tiene solo le sezioni
  e l'autorità; ogni sezione è una board figlia (`plaza-section-contract`)
  con parametri `{ owner, section }`, la propria sezione e l'indice dei suoi
  topic. La madre rifiuta i topic nel proprio stato; la figlia rifiuta entry
  di altre sezioni.

## 10. Client e UI

- `topic_contract.rs` mantiene `TOPIC_CACHE`, crea i contratti, invia PUT/GET/
  UPDATE, applica i delta e propaga l'autorità della board ai topic.
- `TopicIndexView` mostra sezioni, argomenti e attività, i badge di
  approvazioni e report, e crea i topic.
- `TopicView` carica la parte corrente e le precedenti su richiesta, e
  gestisce composer, draft, reaction, poll, modifica, report, split e
  controlli di moderazione.
- Ricerca e notifiche hanno viste dedicate per le board `TopicIndex`; le board
  legacy usano le viste esistenti.
- Tutti gli invii al client API passano da `app::send_client_request`, che usa
  un mutex asincrono: nessun task tiene il guard di un segnale attraverso un
  await.
- Le modifiche locali della board vengono inviate come delta rispetto a
  `last_synced_state`; solo la prima sincronizzazione di una board usa lo
  stato completo. I delta del solo indice prendono il percorso rapido del
  contratto.
- Le modifiche di sola attività vengono salvate in locale con un debounce di
  1 secondo e inviate alla rete al massimo una volta ogni 10 secondi per
  board. Le altre modifiche (topic, flag, report, permessi) sincronizzano
  subito.
- `TOPIC_CACHE` tiene al massimo 24 topic, eliminando i più vecchi già
  sincronizzati. La sottoscrizione sul nodo resta attiva: la stdlib attuale
  non espone ancora un `Unsubscribe` nel client API.
- Se l'invio di un delta topic fallisce, il delta resta in una coda locale e
  viene ritentato ogni 20 secondi, fino a 5 volte. Lo stato locale è già
  applicato, quindi il post resta visibile; il retry è idempotente.
- Le nuove board topic sono `SectionedTopicIndex`: creano la board figlia
  quando si crea una sezione, registrano la sua chiave nel record firmato
  della sezione e la caricano all'apertura della board. Topic, risposte,
  attività, flag e report vengono scritti sulla figlia; la UI unisce gli
  indici delle figlie. Ricerca, notifiche e coda moderazione leggono lo stesso
  indice aggregato. Le board `TopicIndex` esistenti restano leggibili.
- La figlia non copia tutta l'autorità: conserva configurazione, admin,
  ownership, sezioni e solo i membri/ruoli/ban che il suo indice referenzia.
  La sincronizzazione dell'autorità viaggia come delta; un cambio di admin o
  ownership usa ancora lo stato completo. Contratto board alla revisione 26.
- L'attività della figlia viene accorpata per 10 s. Lo stato locale resta
  `dirty` fino all'`UpdateResponse` del nodo; un `Get` che porta ancora lo
  stato precedente fa merge invece di scartare l'entry o l'attività locale.
  Le attività ripristinate dal delegate vengono rimesse in coda al reload.
- Un membro può creare un topic in una sezione aperta (nessun ruolo
  richiesto, non nascosta, immagini ammesse, senza auto-moderazione). Il
  topic non porta lo snapshot firmato dall'owner, quindi le policy
  solo-sezione restano riservate all'owner. L'indice della board verifica
  comunque i ruoli della sezione per ogni entry (revisione 26).
- `authority_from_board` costruisce la radice Merkle degli stati dei membri e
  le prove per l'autore, i partecipanti e i firmatari di azioni/approvazioni.
  `sync_topic_authority` aggiorna un topic solo se `content_hash`, `digest` o
  le prove cambiano; `propagate_authority` carica ogni topic e invia la sua
  radice+prove, senza il limite di 100 topic. Il payload non cresce con i ban
  della board, ma la passata carica tutti i topic.
- La creazione di un topic attende la conferma del nodo prima di indicizzarlo:
  il nodo pu� rispondere con `PutResponse` oppure con il `GetResponse` che
  avvia la sottoscrizione (`subscribe: true`). `wait_topic_synced` accetta
  entrambi; senza conferma il topic viene rimosso dalla cache e l'utente vede
  l'errore.
- Il mark-read usa il timestamp dell'entry quando manca l'attività, per
  evitare un loop di render.

## 11. Test

`topic-core` ha 51 test: creazione, post, risposta, edit, delete, due client
convergenti, merge commutativo/associativo/idempotente, catena di invito e
token join, moderatori con e senza prova, scope di sezione, ruolo revocato,
ban prima e dopo il post, sospensione, pin/close/announce, move/merge/split,
hide/restore/purge, poll e reaction, contenuto sigillato illeggibile al
contratto, limiti di dimensione e numero, CBOR round-trip, firme manomesse e
continuation.

`plaza-core` ha 328 test, inclusi indice, sezioni, flag, report, risoluzioni,
limiti di frequenza e percorso rapido dell'indice.

La suite real-node `ui/tests/real-node/topics.spec.ts` ha 15 scenari: topic e
risposte (con draft che sopravvive al reload), topic privato, topic creato da
un membro, board e sezioni con membri, ruolo creato prima del topic,
approvazione, propagazione del ban, reaction e poll, move/merge/split,
continuation con caricamento delle parti precedenti, report con risoluzione,
report in una sezione e ricerca sull'indice. Con lo shard come default la
suite passa 15/15 in 5.6 minuti. La suite statica Playwright ha 116 test
passati e 12 saltati. Il contratto della board e' alla revisione 26: l'indice
verifica i ruoli della sezione per ogni entry.

Il reset di test scrive un marker nel delegate (`skip_legacy_migration`)
perché la shell sandboxata non espone `localStorage`: senza il marker i
delegati legacy ripopolano le vecchie board e i loro update con firma non
valida rallentano la suite. Con l'isolamento i 15 scenari passano in sequenza
in circa 5 minuti; il caso ruolo-prima-del-topic non resta più su "Loading
topic".

I benchmark di scala sono in `docs/plaza-scale-benchmark.md`: misurano
`verify`, `apply_delta`, `apply_delta_incremental`, serializzazione e
dimensione per 500/2.000 topic e 100/200 post. La verifica completa resta
costosa (455 ms per 200 post, 15,4 s per 2.000 topic), mentre il percorso
incrementale scende a 13 ms per un post e 2,5–3,6 ms per un delta del solo
indice.
