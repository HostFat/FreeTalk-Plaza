# plaza-dm — specifica del contratto

Stato: specifica di design, precedente al codice. Perimetro v1: conversazioni
1:1. Nessuna chat di gruppo.

Implementazione attuale:

- `dm-core` (crate `plaza-dm-core`): stato, delta, validazione, merge, cap e
  test di convergenza.
- `dm-contract` (crate `plaza-dm-contract`): entry point Freenet, validate,
  update, summarize, delta; wasm compilabile.
- `dm-delegate` (crate `plaza-dm-delegate`): API request/response in
  `dm-core::delegate`, stato persistente **per identità** (`identities` map),
  semi dei dispositivi, firme, chiavi di conversazione, indice locale,
  blocco/draft, export/import del backup; wasm compilabile.
- Client: registrazione del delegate all'avvio, envelope con request id,
  inizializzazione dell'identità dal profilo attivo, creazione del primo
  dispositivo, parser delle risposte nel message loop e reset dal Device
  drawer. Ogni richiesta porta l'`identity` attiva; cambiare profilo aggiunge
  una voce alla mappa senza perdere le altre.
- Sigillo ibrido: `DmDevice` include `x25519_pk`; il delegate conserva
  `x25519_seed` e `kem_seed`, espone `SealConversationKey`,
  `OpenConversationKey`, `EncryptMessage` e `DecryptMessage`. Il sigillo usa
  X25519 + ML-KEM-768, KDF BLAKE3 e XChaCha20-Poly1305; i messaggi usano la
  chiave di conversazione e AAD sui metadati.
- Non ancora implementati: client del contratto DM (create/get/subscribe/
  publish), invito e join end-to-end, Messages UI e deploy del contratto DM.

Documenti collegati:

- `docs/plaza-dm-design.md` — architettura e roadmap.
- `docs/plaza-dm-threat-model.md` — asset, attori, minacce, mitigazioni.
- `docs/email-mail-contract-vnext.md` — modifiche email 5+7 raggruppate.

## 1. Principi

1. **Un contratto per conversazione.** Nessun contratto globale, nessun inbox
   unico che serializza tutti i messaggi.
2. **La chiave del contratto è una capability.** Il parametro include un
   segreto casuale; senza il link non si richiede lo stato.
3. **Il contenuto è cifrato.** Il contratto vede ciphertext, chiavi pubbliche
   pseudonime, timestamp e dimensioni.
4. **Lo stato è piccolo.** La finestra recente vive nel contratto; la
   cronologia completa vive nel client e nel backup.
5. **La membership è verificabile.** Ogni record è firmato da una chiave di
   dispositivo autorizzata.
6. **Le generazioni evitano la crescita infinita.** A cap raggiunto si crea un
   nuovo contratto e il vecchio punta al nuovo.

## 2. Tipi e identificatori

```
DmIdentityId   = [u8; 32]   // chiave pubblica Ed25519 dell'identità DM
DmDeviceId     = [u8; 32]   // chiave pubblica Ed25519 del dispositivo
DmMessageId    = [u8; 32]   // BLAKE3 della firma del messaggio
DmContractKey  = ContractKey
DmInviteToken  = [u8; 32]   // segreto nel link, mai in chiaro nello stato
DmKeyVersion   = u32
DmGeneration   = u32
```

`DmIdentityId` è derivato dalla radice del profilo con contesto
`plaza-dm-identity-v1`. Non coincide con la chiave di firma della board.

## 3. Parametri del contratto

```
DmParamsV1 {
  protocol_version: u16,       // 1
  contract_secret: [u8; 32],   // casuale, rende la chiave non indovinabile
}
```

La chiave del contratto è `hash(wasm, params)`. Il link di invito contiene la
chiave completa e la versione del protocollo. Il client rifiuta una versione
che non conosce.

## 4. Stato

```
DmStateV1 {
  meta: DmMetaV1,
  members: DmMembersV1,
  invites: DmInvitesV1,
  keys: DmKeysV1,
  messages: DmMessagesV1,
  read: DmReadV1,
  generation: DmGenerationV1,
}
```

### 4.1 Meta

```
DmMetaV1 {
  conversation_id: [u8; 32],   // casuale, distinto dalla chiave del contratto
  created_at: i64,             // millisecondi
  name: Option<SealedBytes>,   // nome locale cifrato, opzionale
  state_version: u32,          // monotono a ogni update
}
```

`state_version` serve a rifiutare update fuori ordine. Non è una firma dello
stato intero: ogni record porta la propria firma.

### 4.2 Membri e dispositivi

```
DmMembersV1 { members: Vec<AuthorizedDmMember> }

AuthorizedDmMember {
  member: DmMember,
  signature: Signature,        // del creatore o del membro che accetta
}

DmMember {
  identity: DmIdentityId,
  version: u32,
  role: DmRole,                // Creator | Member
  joined_at: i64,
  devices: Vec<AuthorizedDmDevice>,
  left_at: Option<i64>,        // uscita volontaria
}

AuthorizedDmDevice {
  device: DmDevice,
  signature: Signature,        // della chiave di identità DM
}

DmDevice {
  device_id: DmDeviceId,
  signing_key: VerifyingKey,
  kem_ek: Vec<u8>,             // ML-KEM-768, 1184 byte
  created_at: i64,
  revoked_at: Option<i64>,
}
```

Regole:

- Il creatore è l'unico membro iniziale.
- Un invito accettato aggiunge un membro con `role = Member`.
- Un dispositivo è attivo finché `revoked_at` è `None`.
- La versione del membro cresce a ogni modifica di dispositivi o uscita.
- In v1 il numero massimo di membri è 2. Il formato resta generico.

### 4.3 Inviti

```
DmInvitesV1 { invites: Vec<DmInvite> }

DmInvite {
  invite_id: [u8; 32],
  token_hash: [u8; 32],        // BLAKE3 del token nel link
  created_at: i64,
  expires_at: i64,
  used_at: Option<i64>,
  used_by: Option<DmIdentityId>,
  bound_identity: Option<DmIdentityId>,
  signature: Signature,        // del creatore
}
```

Regole:

- Il token in chiaro vive solo nel link; lo stato conserva l'hash.
- Il token è monouso. Un secondo tentativo con lo stesso token viene rifiutato.
- `bound_identity` limita l'invito a una identità DM.
- Un invito scaduto non è accettabile; il creatore può revocarlo creando un
  invito con `used_at` valorizzato o rimuovendolo con un delta.
- Massimo 8 inviti per contratto.

### 4.4 Chiavi di conversazione

```
DmKeysV1 { keys: Vec<AuthorizedSealedDmKey> }

AuthorizedSealedDmKey {
  record: SealedDmKey,
  signature: Signature,        // del membro che sigilla
}

SealedDmKey {
  key_version: DmKeyVersion,
  member: DmIdentityId,
  device: DmDeviceId,
  suite: DmKeySuite,           // X25519MlKem768XChaCha20Poly1305
  ciphertext: Vec<u8>,
  nonce: [u8; 24],
  sealed_at: i64,
}
```

Regole:

- La chiave di conversazione è 32 byte casuali, per versione.
- Ogni dispositivo attivo riceve la chiave sigillata.
- Chi sigilla deve essere un dispositivo attivo di un membro.
- Una nuova versione si crea quando cambia la membership o un dispositivo
  viene revocato.
- I messaggi puntano alla `key_version` con cui sono cifrati.

### 4.5 Messaggi

```
DmMessagesV1 { messages: Vec<AuthorizedDmMessage> }

AuthorizedDmMessage {
  message: DmMessage,
  signature: Signature,        // del dispositivo mittente
}

DmMessage {
  id: DmMessageId,
  author: DmIdentityId,
  device: DmDeviceId,
  key_version: DmKeyVersion,
  created_at: i64,
  content_type: u16,           // text | system | attachment
  ciphertext: Vec<u8>,         // XChaCha20-Poly1305
  nonce: [u8; 24],
  reply_to: Option<DmMessageId>,
  declared_len: u32,
}
```

Regole:

- `id = BLAKE3(signature)`; due messaggi identici hanno lo stesso id.
- La firma copre tutti i campi del messaggio.
- Il mittente deve essere un dispositivo attivo di un membro.
- `reply_to` deve riferirsi a un messaggio presente o a un messaggio di una
  generazione precedente noto al client.
- `declared_len` <= 8192 byte.
- Massimo 500 messaggi o 1 MB di stato per contratto, il primo dei due.
- Il contratto non ordina i messaggi: il client ordina per
  `(created_at, id)`.

### 4.6 Stato di lettura

```
DmReadV1 { entries: Vec<AuthorizedDmRead> }

AuthorizedDmRead {
  entry: DmReadEntry,
  signature: Signature,        // del dispositivo
}

DmReadEntry {
  member: DmIdentityId,
  device: DmDeviceId,
  last_message: DmMessageId,
  version: u32,
  updated_at: i64,
}
```

LWW per `(member, device, version)`. Serve solo al badge non letti; non è
contenuto critico.

### 4.7 Generazioni

```
DmGenerationV1 {
  generation: u32,
  previous_contract: Option<ContractKey>,
  next_contract: Option<ContractKey>,
  closed_at: Option<i64>,
  signature: Signature,        // di un membro attivo
}
```

Regole:

- Quando un contratto raggiunge il cap, rifiuta nuovi messaggi.
- Un membro crea il contratto della generazione successiva con la stessa
  membership e la stessa chiave di conversazione, oppure con una nuova chiave
  sigillata ai dispositivi.
- Il vecchio contratto pubblica `next_contract`; il nuovo pubblica
  `previous_contract`.
- Il client segue il puntatore e verifica che il contratto successivo abbia la
  stessa `conversation_id`.
- In v1, con due membri, entrambi possono creare la generazione successiva;
  il client preferisce il puntatore firmato da un membro attivo e ignora i
  fork non firmati.

## 5. Delta

Un update porta un `DmStateDeltaV1`:

```
DmStateDeltaV1 {
  meta: Option<DmMetaV1>,
  members: Option<Vec<AuthorizedDmMember>>,
  invites: Option<Vec<DmInvite>>,
  keys: Option<Vec<AuthorizedSealedDmKey>>,
  messages: Option<Vec<AuthorizedDmMessage>>,
  read: Option<Vec<AuthorizedDmRead>>,
  generation: Option<DmGenerationV1>,
}
```

Il contratto:

1. decodifica il delta;
2. rifiuta campi sconosciuti critici o versioni non supportate;
3. verifica ogni record;
4. applica i record con merge deterministico;
5. aggiorna `state_version`;
6. controlla i cap;
7. serializza lo stato.

## 6. Merge e convergenza

- Membri: vince la `version` più alta; a parità di versione, il record con
  firma lessicograficamente minore. Due versioni uguali con contenuti diversi
  sono un errore di update.
- Dispositivi: per `device_id`; vince il record con `created_at` più alto;
  `revoked_at` è definitivo.
- Inviti: per `invite_id`; `used_at` è definitivo.
- Chiavi: per `(key_version, member, device)`; la prima valida vince.
- Messaggi: per `id`; deduplica.
- Read: LWW per `(member, device, version)`.
- Generazione: il puntatore con firma valida e `generation` più alta.
- Ordinamento finale deterministico per campi binari.

## 7. Invito e accettazione

### 7.1 Link

Formato:

```
https://<gateway>/v1/contract/web/<app_id>/#/dm/join?c=<contract_key_base58>&t=<invite_token_base58>&k=<key_version>:<conversation_key_base58>&v=1
```

Il frammento non viene inviato al server. Il link è un segreto: chi lo possiede
può leggere la conversazione finché la chiave non viene ruotata.

### 7.2 Flusso

1. Il creatore genera contratto, chiave di conversazione e token.
2. Il link contiene contratto, token, versione della chiave e chiave.
3. Il destinatario apre il link, verifica versione e chiave, scarica lo stato.
4. Il destinatario vede i messaggi già presenti, se la chiave li copre.
5. Il destinatario invia un `JoinRequest` firmato con la chiave di identità DM
   e con le chiavi dei suoi dispositivi; include il token in chiaro.
6. Il contratto verifica l'hash del token, la scadenza, l'eventuale binding e
   aggiunge il membro e i dispositivi.
7. Almeno un membro esistente sigilla la chiave di conversazione ai nuovi
   dispositivi e pubblica i record `keys`.
8. Il destinatario può inviare e ricevere.
9. Dopo l'ingresso, il creatore può ruotare la chiave e sigillarla ai membri;
   i messaggi nuovi usano la nuova versione. Il link vecchio non legge i nuovi
   messaggi.

### 7.3 Errori

- Link scaduto.
- Token già usato.
- Token non corrispondente.
- Contratto non raggiungibile.
- Versione del protocollo non supportata.
- Identità bloccata localmente.
- Chiave assente o non sigillata.

## 8. Crittografia

- **Identità DM:** Ed25519 derivata dal profilo.
- **Dispositivo:** Ed25519 casuale, approvato dall'identità.
- **Chiave di conversazione:** 32 byte casuali.
- **Sigillo della chiave:** X25519 + ML-KEM-768, KDF BLAKE3, AEAD
  XChaCha20-Poly1305. Riusa il pattern di `ui/src/util/pq.rs`.
- **Messaggio:** XChaCha20-Poly1305 con nonce casuale di 24 byte.
- **AAD:** `conversation_id`, `author`, `device`, `key_version`,
  `created_at`, `content_type`, `reply_to`.
- **Firma:** Ed25519 sul messaggio serializzato in modo canonico.
- **Forward secrecy:** assente per messaggio nella v1; rotazione per
  membership/revoca. Va dichiarato nel threat model.
- **Firme post-quantum:** rimandate. La v1 usa Ed25519; una versione futura può
  introdurre ML-DSA con un bump di protocollo.

## 9. Delegate e indice locale

Namespace del delegate: `plaza-dm-v1`. Contenuto:

```
DmLocalState {
  identity_seed_derived: bool,
  devices: Vec<LocalDevice>,
  conversations: Vec<DmConversationIndex>,
  keys: Vec<LocalConversationKey>,
  read: Vec<LocalRead>,
  drafts: Vec<LocalDraft>,
  blocked: Vec<DmIdentityId>,
}
```

`DmConversationIndex`:

```
contract_key: ContractKey,
conversation_id: [u8; 32],
peer: DmIdentityId,
title: Option<String>,        // nome locale, non on-chain
last_message_at: i64,
last_message_id: Option<DmMessageId>,
unread: u32,
key_versions: Vec<DmKeyVersion>,
generation: u32,
```

Il delegate custodisce le chiavi private dei dispositivi e le chiavi di
conversazione. Il browser non le mette in localStorage.

## 10. Backup

Il backup esistente (`util/backup.rs`) va esteso con:

- identità DM derivata (ricostruibile dal profilo, ma va marcata);
- dispositivi e relative chiavi;
- chiavi di conversazione per versione;
- indice locale, read state, bozze, blocco;
- puntatori alle generazioni.

Formato: `DmBackupV1` dentro `BackupV1`, con `format` versionato. Il restore
deve rifiutare un backup DM di versione futura e conservare le chiavi mancanti
come “non disponibili”, senza cancellare la conversazione.

## 11. Scoperta v2

### 11.1 Profilo DM

```
DmProfileParamsV1 { identity: DmIdentityId }
DmProfileStateV1 {
  identity: DmIdentityId,
  version: u16,
  device_keys: Vec<DmDevicePublic>,
  mailbox: ContractKey,
  protocol_version: u16,
  updated_at: i64,
  signature: Signature, // della chiave di identità
}
```

La chiave del contratto è derivabile dall'identità; il profilo è pubblico. Il
profilo non contiene nomi o board: solo chiavi pubbliche e mailbox.

### 11.2 Mailbox

```
DmInboxStateV1 { entries: Vec<DmInboxEntry> }

DmInboxEntry {
  id: [u8; 32],
  sender: DmIdentityId,
  created_at: i64,
  expires_at: i64,
  sealed_invite: Vec<u8>,      // cifrato ai dispositivi del destinatario
  work: u64,                   // proof-of-work verificabile
  signature: Signature,
}
```

Regole: massimo 20 entry, scadenza, proof-of-work minima, rate limit per
mittente, rimozione da parte del proprietario. Il destinatario accetta,
blocca o ignora.

## 12. UI v1

- Voce **Messages** nella barra superiore, badge non letti.
- Elenco conversazioni con peer, ultimo messaggio, non letti.
- Vista chat: messaggi, composer, invio, blocco, segnalazione locale.
- Schermata di join da link.
- Stato “in attesa della chiave” dopo l'accettazione, finché un membro non
  sigilla la chiave.
- Notifiche interne e OS tramite il bridge esistente.
- Mobile: drawer/lista a schermo intero, composer sticky.

## 13. Validazione e limiti

- `protocol_version` supportata.
- Massimo 2 membri in v1.
- Massimo 8 dispositivi per identità.
- Massimo 8 inviti pendenti.
- Massimo 500 messaggi o 1 MB per contratto.
- Massimo 8 KB per messaggio.
- Massimo 256 byte per nome cifrato.
- Timestamp entro ±10 minuti dall'orologio del nodo per i nuovi record;
  i record storici restano validi.
- Nessun campo sconosciuto critico.

## 14. Test

### Unit e proprietà

- Merge commutativo, associativo e idempotente.
- Tombstone di inviti e dispositivi.
- Versione membro e LWW.
- Cap messaggi e rollover.
- Firma mancante, firma errata, autore non membro, dispositivo revocato.
- Messaggio duplicato, reply inesistente, dimensione eccessiva.

### Contratto

- Stato vuoto, stato pieno, delta malformato, versione futura.
- Generazione successiva e puntatore.
- Dimensione massima dello stato.
- Fuzz su delta e record.

### Integrazione

- Due client: crea, invita, accetta, invia, ricarica, riapre.
- Terzo client senza link: non può richiedere il contratto.
- Link riusato: rifiutato.
- Link scaduto: rifiutato.
- Dispositivo aggiunto e revocato.
- Rotazione chiave e messaggi vecchi/nuovi.
- Backup e restore su un secondo dispositivo.
- Generazione successiva dopo il cap.

### Scala

- 10.000 identità simulate, 100.000 conversazioni.
- Misura: sottoscrizioni attive per client, tempo di update, dimensione stato,
  tempo di recupero cronologia, dimensione backup.
- Nessun nodo deve ospitare tutte le conversazioni.

## 15. Migrazione e versioning

- Il contratto DM nasce con `protocol_version = 1`; non ci sono dati legacy.
- Un cambio di wasm cambia la chiave. Le versioni future usano un puntatore di
  upgrade nello stato della generazione precedente, come per le board.
- Il delegate usa un namespace versionato; un cambio di schema richiede una
  migrazione esplicita e un backup.
- I link di invito includono la versione; un client vecchio rifiuta un link
  nuovo con un messaggio chiaro.

## 16. Fuori perimetro

- Chat di gruppo.
- Presenza, typing, chiamate.
- Push a app chiusa.
- Moderazione condivisa tra conversazioni.
- Firme post-quantum.
- Forward secrecy per messaggio.
- Ricerca globale.
