# plaza-dm — design del contratto DM

Stato: bozza di design. Nessun codice ancora. Le decisioni in tabella sono
confermate; le voci “aperto” richiedono una scelta prima dell'implementazione.

Documenti collegati:

- `docs/plaza-dm-contract-spec.md` — stato, delta, validazione, inviti, generazioni.
- `docs/plaza-dm-threat-model.md` — asset, attori, minacce, mitigazioni.
- `docs/email-mail-contract-vnext.md` — modifiche email 5+7 raggruppate.

## Obiettivo

Messaggistica privata nativa di FreeTalk Plaza, separata dal contratto delle
board e scalabile in modo orizzontale fino a migliaia di utenti. Ogni
conversazione è un contratto indipendente; il client carica solo le
conversazioni attive.

Fuori ambito: chat di gruppo, videochiamate, presenza, typing indicator, push
a app chiusa, moderazione condivisa tra conversazioni.

## Decisioni confermate

| Tema | Scelta |
|---|---|
| Unità di scala | Un contratto `plaza-dm` per conversazione |
| Identità DM | Derivata dal profilo con domain separation, distinta dalle chiavi delle board |
| Multi-dispositivo | Modello dati device-ready; UI con un dispositivo nella v1 |
| Scoperta | Invito con link/QR nella v1; mailbox e pulsante “Message” nella v2 |
| Gruppi | Non previsti: solo conversazioni 1:1 |
| Allegati | Testo nella v1; blob cifrato nella v2 |
| Forward secrecy | Chiave di conversazione con rotazione; ratchet per messaggio in una fase successiva |
| Retention | 500 messaggi per contratto, poi nuova generazione |
| Moderazione | Blocco e segnalazione locale nella v1 |
| Notifiche | Sottoscrizione alle conversazioni attive e badge non letti |

## Componenti

1. **`plaza-dm`** — contratto di conversazione.
   - Chiave di contratto con parametro casuale: senza il link non si può
     richiedere lo stato.
   - Stato piccolo e verificabile: membri/dispositivi, messaggi cifrati,
     chiavi sigillate, stato di lettura, puntatore alla generazione successiva.
2. **`plaza-dm-profile`** — endpoint pubblico per utente (v2).
   - Bundle DM: chiave di firma, prekey X25519/ML-KEM, chiave della mailbox,
     versioni del protocollo.
   - Pubblicato nel member info della board o condiviso con un link.
3. **`plaza-dm-inbox`** — mailbox per richieste (v2).
   - Inviti cifrati, massimo 20 pending, scadenza, rate limit per mittente.
4. **`plaza-blob`** — allegati cifrati con una chiave per-file inclusa nel
   messaggio DM.
5. **Indice locale nel delegate** — elenco conversazioni, ultimo messaggio,
   non letti, nomi locali. Mai on-chain.

## Stato del contratto

```
DmStateV1 {
  conversation: ConversationMeta,   // id casuale, versione, generazione
  members: Vec<DmMember>,           // identità DM + dispositivi + ruoli
  keys: Vec<SealedConversationKey>, // chiave sigillata per dispositivo
  messages: Vec<DmMessage>,         // finestra recente, max 500
  read_state: Vec<DmReadState>,     // per membro
  next_generation: Option<ContractKey>,
}
```

- `DmMessage`: id = hash della firma, autore, dispositivo, timestamp, tipo,
  ciphertext, nonce, `reply_to`, dimensione dichiarata, firma.
- `DmMember`: identità DM, set di dispositivi autorizzati, ruolo
  (`owner`/`member`), versione.
- `DmDevice`: chiave di firma del dispositivo, prekey di cifratura, scadenza,
  revoca.
- Merge: unione per id, last-writer-wins per `read_state` e membership,
  ordinamento per `(timestamp, id)`. Nessun ordine totale richiesto.
- Limiti: 500 messaggi o 1 MB per contratto; a cap raggiunto si crea una nuova
  generazione e si pubblica il puntatore. La cronologia completa resta locale
  e nel backup.

## Identità e chiavi

- **Identità DM**: derivata dalla radice del profilo con contesto
  `plaza-dm-identity-v1`. Non riusa la chiave di firma della board.
- **Dispositivi**: ogni dispositivo ha una chiave di firma e una prekey.
  L'identità DM elenca i dispositivi autorizzati; un dispositivo esistente
  approva un nuovo dispositivo con un record firmato.
- **Conversazione**: chiave simmetrica casuale di 32 byte, sigillata a ogni
  dispositivo con X25519 + ML-KEM (ibrido). Rotazione quando cambia la
  membership o un dispositivo viene revocato.
- **Messaggi**: AES-256-GCM; firma Ed25519 del dispositivo su ciphertext,
  mittente, timestamp, id e `reply_to`.
- **Forward secrecy**: la v1 ruota la chiave per membership, non per messaggio.
  Il limite va dichiarato nel threat model. Un ratchet per messaggio è una
  fase successiva, perché richiede stato locale sincronizzato tra dispositivi.

## Scoperta e inviti

### v1 — invito

- Chi crea la conversazione genera il contratto e un link con la chiave
  completa; il link può essere copiato o mostrato come QR.
- Chi riceve apre il link, vede la richiesta, accetta e diventa membro.
- Nessuna directory globale e nessun elenco pubblico di utenti.

### v2 — pulsante “Message”

- Il profilo del membro pubblica il bundle `plaza-dm-profile`.
- “Message” crea la conversazione e deposita un invito cifrato nella mailbox
  del destinatario.
- La mailbox ha un tetto di richieste, scadenza e rate limit; il destinatario
  accetta, blocca o ignora.

## Modello di scala

- 10.000 utenti, 10 conversazioni a testa, 200 messaggi per conversazione,
  2 KB per messaggio: circa 40 GB distribuiti, circa 400 KB per conversazione.
- Nessun nodo conserva tutto: ogni client tiene le conversazioni attive e la
  propria cronologia; il contratto conserva la finestra recente.
- Il limite reale è il numero di sottoscrizioni attive per client e la latenza
  di update del contratto, non il numero di utenti.
- Freenet è asincrono: una conversazione DM non è una chat istantanea.
  Un messaggio per Invio, niente typing/presence nel contratto.

## Multi-dispositivo

- Il formato dei record prevede già i dispositivi nella v1, anche se la UI
  gestisce un solo dispositivo.
- Un nuovo dispositivo viene approvato da un dispositivo esistente; riceve le
  chiavi di conversazione sigillate e la cronologia dal backup o da un
  trasferimento diretto.
- La revoca di un dispositivo ruota la chiave di conversazione e invalida le
  sue firme future.

## UI

- Voce **Messages** nella barra superiore con contatore non letti.
- Elenco conversazioni: nome locale, ultimo messaggio, non letti.
- Vista conversazione: messaggi, composer, invio, blocco, segnalazione locale.
- Pulsante **Message** sul profilo membro nella v2.
- La scheda **Mail** del Device drawer resta separata: Freenet Mail è un'altra
  app e un'altra identità.

## Sicurezza e privacy

- Chiave di contratto casuale come capability; stato cifrato.
- Metadati minimi: chiavi pubbliche pseudonime dei membri, timestamp,
  dimensione dei messaggi. Nessun collegamento automatico al profilo Plaza.
- Nessuna chiave privata nel browser storage: il delegate custodisce le chiavi.
- Blocco e segnalazione locali nella v1; segnalazioni condivise solo con un
  contratto separato, in una fase successiva.
- Threat model in `docs/plaza-dm-threat-model.md`.

## Roadmap

1. **Specifica e threat model** (`plaza-dm-contract-spec.md`,
   `plaza-dm-threat-model.md`).
2. **v1**: contratto `plaza-dm`, 1:1 con invito, testo, indice locale,
   notifiche, backup.
3. **v2**: `plaza-dm-profile`, mailbox, pulsante “Message”, blocco,
   allegati cifrati.
4. **v3**: multi-dispositivo completo, ricerca locale, retention
   configurabile.
5. **Test di scala**: 10.000 identità simulate, 100.000 conversazioni,
   misura di sottoscrizioni, update, dimensione stato e recupero cronologia.

## Aperto

- Dimensione massima degli allegati (v2).
- Durata della finestra locale e politica di backup della cronologia.
- Se la mailbox debba richiedere una proof-of-work, una board comune o
  entrambe.
- Se il primo invito debba mostrare un fingerprint da confrontare fuori banda.
