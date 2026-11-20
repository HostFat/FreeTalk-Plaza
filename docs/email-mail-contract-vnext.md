# Email — contratto board vNext (punti 5 + 7)

Stato: specifica di design, precedente al codice.

Obiettivo: raggruppare in **una sola versione del contratto**:

- **5. Cancellazione reale dell'indirizzo Mail.**
- **7. Indirizzo di contatto della board.**

Il punto **9** (pulsante Mail nella lista membri) è solo UI e può entrare nella
stessa release senza modificare il contratto. Il punto **1** (verifica con
fingerprint) resta una fase separata.

Questa versione sostituisce l'azione append-only `SetMailAddress` con uno stato
dedicato e aggiunge il contatto della board alla configurazione. Entrambe le
modifiche richiedono un nuovo wasm: una sola re-key per tutto.

## 1. Perché cambiare

Oggi l'indirizzo viaggia come azione firmata nel log dei messaggi. Impostare
Hidden aggiunge un'azione con indirizzo vuoto: l'indirizzo sparisce dallo stato
corrente, ma la vecchia azione resta nel log. Su una board pubblica resta
leggibile; su una privata resta il ciphertext.

Uno stato dedicato permette:

- un solo record per membro;
- una tombstone che impedisce la resurrezione di un record vecchio;
- la rimozione dell'indirizzo dallo stato corrente;
- un percorso di migrazione esplicito dalle vecchie azioni;
- un campo separato per il contatto della board, firmato dal proprietario.

## 2. Nuovo stato: `MailAddressesV1`

```
MailAddressesV1 {
  records: Vec<AuthorizedMailAddress>,
}

AuthorizedMailAddress {
  record: MailAddressRecord,
  signature: Signature,
}

MailAddressRecord {
  member_id: MemberId,
  version: u32,
  address: Option<SealedBytes>,  // None = tombstone
  updated_at: i64,
}
```

Regole:

- Un record per membro; lo stato conserva il più recente.
- `address = None` è una tombstone: l'indirizzo non è più nello stato corrente.
- La tombstone resta per i membri attuali, così un record vecchio non può
  tornare applicando un delta con versione inferiore.
- La firma è del membro; per il proprietario, della chiave owner.
- `address` ha un massimo di 256 byte dichiarati.
- Il contratto accetta sia `Public` sia `Private`; il client sigilla con la
  chiave della board quando la board è privata. Il contratto non impone il
  variant, perché la privacy mode può cambiare nel tempo.

### 2.1 ComposableState

`MailAddressesV1` implementa `ComposableState<ParentState = ChatBoardStateV1>`:

- `verify`: ogni record ha firma valida del membro o dell'owner; il membro
  esiste (o è l'owner); `version` è monotona; la lunghezza è entro il cap.
- `summarize`: `BTreeMap<MemberId, u32>` con la versione corrente.
- `delta`: record con versione maggiore del summary.
- `apply_delta`: per membro vince la versione più alta; a parità di versione
  vince il record con firma lessicograficamente minore; due record con la
  stessa versione e contenuto diverso sono un errore.
- `merge`: LWW per versione, con lo stesso tie-break.
- I record di membri non più presenti vengono rimossi; se il membro rientra,
  parte da una nuova versione.

### 2.2 Posizione nello stato

`ChatBoardStateV1` aggiunge il campo in fondo:

```
mail_addresses: MailAddressesV1,
```

Con `#[serde(default)]` per gli stati esistenti. Il campo partecipa a
`state_size`, `verify`, `summarize`, `delta` e `merge` come gli altri.

## 3. Contatto della board: `Configuration.contact_mail`

```
Configuration {
  // campi esistenti...
  contact_mail: Option<SealedBytes>,
}
```

Regole:

- `#[serde(default, skip_serializing_if = "Option::is_none")]` per mantenere
  valide le firme delle configurazioni esistenti quando il campo è `None`.
- Massimo 256 byte dichiarati.
- È firmato dal proprietario tramite `AuthorizedConfigurationV1`, come gli
  altri campi della configurazione.
- Sulle board private il client lo sigilla con la chiave della board; sulle
  pubbliche resta pubblico.
- Il contratto verifica solo lunghezza e firma della configurazione.

Uso:

- Board Settings: campo “Freenet Mail contact”, solo owner.
- About/Board Info: riga con indirizzo, Open Mail, Copy.
- Segnalazioni e appelli: il link apre Mail, non invia nulla da Plaza.

## 4. Migrazione dalle vecchie azioni

Le azioni `SetMailAddress` restano nel log dei messaggi: sono immutabili e non
vanno cancellate. La nuova UI **ignora** le vecchie azioni e legge solo
`mail_addresses`.

Migrazione:

1. Al primo caricamento della nuova versione, per il profilo attivo, se non
   esiste un record e c'è una vecchia azione con indirizzo, il client prefill
   il campo con quell'indirizzo e mostra un avviso.
2. L'utente preme **Save address**: il client pubblica il record nel nuovo
   stato. Nessuna scrittura automatica.
3. Gli altri membri ri-salvano l'indirizzo quando vogliono; il vecchio
   indirizzo resta nel log storico, ma non è più mostrato.
4. Il tipo `ACTION_TYPE_SET_MAIL_ADDRESS` resta definito per compatibilità;
   il client non lo scrive più. Il contratto continua ad accettarlo come
   messaggio, ma lo stato non lo usa.

## 5. Re-key e rollout

La nuova versione cambia il wasm del contratto board:

1. Costruire il nuovo `plaza_contract.wasm`.
2. Deploy locale e Oracle.
3. Le board esistenti cambiano chiave: il proprietario apre la board e firma
   il puntatore di upgrade.
4. I membri seguono il puntatore; i link vecchi continuano a funzionare
   tramite il puntatore.
5. Verificare una board creata prima del deploy e una creata dopo.
6. Aggiornare gli inviti solo se il puntatore non basta.

Poiché 5 e 7 sono nello stesso wasm, la re-key avviene una volta sola. Il
punto 9 non richiede wasm e può essere rilasciato insieme alla UI.

## 6. UI

### 6.1 Scheda Mail

- Salva l'indirizzo nel profilo locale.
- Se la visibilità è Hidden, pubblica una tombstone.
- Se la visibilità è Board/Public, pubblica un record `MailAddressesV1`.
- Mostra “Published on this board” leggendo lo stato, non le vecchie azioni.
- Copy e Open Mail restano invariati.

### 6.2 Board Settings

- Campo contatto Mail, visibile solo all'owner.
- Salva una nuova `Configuration` firmata.
- Su board privata, sigilla il valore.
- Mostra un avviso: “È un contatto, non un DM di Plaza”.

### 6.3 About/Board Info

- Riga “Freenet Mail contact” con indirizzo, Open Mail, Copy.
- Nessun invio automatico.

### 6.4 Lista membri (punto 9)

- Pulsante Mail nella riga del membro se `mail_addresses` ha un record.
- Apre Mail e copia l'indirizzo.
- Nessuna modifica al contratto.

### 6.5 Member Info e profilo

- Leggono `mail_addresses`, non le azioni.
- Mostrano “Freenet Mail” con Open/Copy.
- Se il record è una tombstone, la riga non compare.

## 7. Test

### Contratto

- Record valido, firma errata, membro inesistente, owner valido.
- Versione inferiore ignorata; versione uguale con contenuto diverso rifiutata.
- Tombstone: il record vecchio non ricompare.
- Rimozione del record per un membro uscito.
- Lunghezza oltre 256 byte rifiutata.
- Configurazione con `contact_mail` firmata; vecchia configurazione senza
  campo ancora valida.
- Dimensione dello stato entro il cap.

### UI e integrazione

- Salva indirizzo, pubblica, ricarica, resta visibile.
- Hidden pubblica la tombstone e la riga sparisce dopo reload.
- Board contact: owner salva, membro lo vede, non-owner non può modificarlo.
- Member list: pulsante Mail visibile solo con record.
- Board privata: il valore è sigillato e leggibile dai membri.
- Board pubblica: il valore è pubblico.
- Migrazione: vecchia azione -> nuovo record; toast; nessuna duplicazione.
- Re-key: board pre-deploy apre dopo l'upgrade del owner.

### Regressioni

- Nickname, member info, inviti, trash e notifiche continuano a funzionare.
- Le vecchie azioni non vengono interpretate come messaggi visibili.
- Il backup include `mail_addresses` e `contact_mail` come parte dello stato
  della board; il restore non perde la tombstone.

## 8. Decisioni

- Tombstone per i membri attuali; rimozione per i membri usciti.
- Contatto board in `Configuration`, non in un contratto separato.
- Migrazione automatica solo per il profilo attivo; gli altri ri-salvano.
- Vecchie azioni conservate nel log, ignorate dalla UI.
- Punto 9 nella stessa release UI, senza wasm aggiuntivo.

## 9. Fuori perimetro

- Verifica fingerprint/contact card (punto 1).
- QR.
- Deep link di composizione.
- Invio di email da Plaza.
- Cancellazione della storia dai nodi che conservano stati precedenti.
