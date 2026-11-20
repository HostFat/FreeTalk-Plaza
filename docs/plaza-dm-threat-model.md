# plaza-dm — threat model

Stato: bozza di design. Riferimento: `docs/plaza-dm-contract-spec.md`.

## 1. Asset

1. **Plaintext dei messaggi.** Contenuto delle conversazioni.
2. **Chiavi di conversazione.** 32 byte per versione; aprono i messaggi.
3. **Chiavi di identità DM.** Derivano dal profilo; identificano il membro.
4. **Chiavi dei dispositivi.** Firmano e decifrano; vivono nel delegate.
5. **Cronologia locale.** Messaggi, bozze, read state.
6. **Backup.** Identità, dispositivi, chiavi di conversazione, indice.
7. **Metadati.** Membri, timestamp, dimensioni, frequenza, contract key.
8. **Link di invito.** Contiene contratto, token e chiave di conversazione.

## 2. Attori e confini di fiducia

- **Partecipanti.** Due identità DM in v1.
- **Mittente non invitato.** Possiede un link o tenta spam sulla mailbox.
- **Nodo Freenet.** Ospita e replica il contratto; vede ciphertext e metadati.
- **Gateway web.** Serve l'app e il web container; può vedere richieste e
  metadati di rete.
- **Dispositivo compromesso.** Ha accesso al delegate e alla cronologia.
- **Peer malevolo.** Pubblica delta invalidi, messaggi enormi, membership false.
- **Avversario quantistico.** Conserva ciphertext per decifrarlo in futuro.
- **Backup rubato.** File con chiavi e identità.

Confini:

```
browser UI  ->  delegate sandbox  ->  Freenet node  ->  contract state
     |                  |                   |
  DOM, JS          chiavi private      ciphertext, metadati
```

Il contratto è pubblico per chi possiede la contract key. I nodi possono
conservare stati precedenti. Il delegate è l'unico posto in cui vivono le
chiavi private.

## 3. Minacce e mitigazioni

### T1. Furto o fuga della contract key

**Minaccia:** chi ottiene il link legge lo stato e i ciphertext.

**Mitigazione:** la contract key contiene un segreto casuale; il link è un
segreto trattato come tale. Token monouso, scadenza, binding opzionale. Dopo
l'ingresso, il creatore può ruotare la chiave di conversazione; il link vecchio
non legge i messaggi nuovi.

**Residuo:** il link vecchio continua a leggere i messaggi cifrati con la
chiave che conteneva. Va documentato nell'interfaccia.

### T2. Fuga della chiave di conversazione

**Minaccia:** un membro o un dispositivo compromesso diffonde la chiave.

**Mitigazione:** rotazione su revoca o uscita; ogni versione è sigillata ai soli
dispositivi attivi; i messaggi indicano la versione. La rotazione non protegge
i messaggi già cifrati con la vecchia chiave.

**Residuo:** chi ha la vecchia chiave legge la vecchia storia. La cronologia
locale non è cancellabile a distanza.

### T3. Dispositivo compromesso

**Minaccia:** accesso a delegate, chiavi, cronologia e backup.

**Mitigazione:** chiavi per dispositivo, revoca firmata, rotazione della chiave
di conversazione, nessuna chiave in localStorage, backup cifrato con password
(da decidere), blocco locale. Il dispositivo revocato non può firmare nuovi
record dopo la revoca; i client rifiutano le sue firme.

**Residuo:** il dispositivo compromesso ha già letto la storia e può conservare
le chiavi vecchie. La revoca è forward-looking.

### T4. Replay e riordino

**Minaccia:** un peer ripubblica messaggi o delta vecchi.

**Mitigazione:** id del messaggio derivato dalla firma; deduplica; versioni
monotone per membri, inviti e read state; `state_version`; timestamp con
finestra; `reply_to` deve riferirsi a un messaggio noto.

**Residuo:** un peer può trattenere un messaggio e pubblicarlo dopo; il
timestamp originale resta, il client lo ordina di conseguenza.

### T5. Spam e inviti indesiderati

**Minaccia:** inbox piena di richieste, link condivisi con estranei.

**Mitigazione:** v1 solo inviti diretti. v2 mailbox con proof-of-work, cap 20,
scadenza, rate limit per mittente, blocco locale. Token monouso e binding
opzionale all'identità del destinatario.

**Residuo:** un link generico condiviso in pubblico può essere usato da chi lo
trova finché il token è valido. Il binding riduce il rischio.

### T6. Peer malevolo nel contratto

**Minaccia:** delta enormi, membership false, messaggi non firmati, fork della
generazione.

**Mitigazione:** validazione per record; firma del dispositivo; membership
attiva; cap di dimensione; versione monotona; firma del puntatore di
generazione; il client ignora fork non validi. Fuzz e test di convergenza.

**Residuo:** un membro legittimo può pubblicare messaggi offensivi; la
moderazione è locale nella v1.

### T7. Metadati

**Minaccia:** il nodo o un osservatore deduce chi parla con chi, quando e
quanto.

**Mitigazione:** identità DM pseudonime, contract key casuale, nessun nome o
board nel contratto, contenuto cifrato. La mailbox è separata dal profilo
pubblico.

**Residuo:** membri e timestamp sono visibili a chi ha la contract key; la
dimensione dei messaggi è visibile. Il padding uniforme è una fase successiva.

### T8. Perdita del delegate o del dispositivo

**Minaccia:** perdita di identità e chiavi, conversazioni irrecuperabili.

**Mitigazione:** backup esplicito; identità DM derivata dal profilo (se il
profilo è nel backup); chiavi di conversazione incluse; restore su un nuovo
dispositivo. Nessun recupero server-side.

**Residuo:** senza backup non c'è recupero. Va detto chiaramente.

### T9. Backup rubato

**Minaccia:** il file contiene identità e chiavi.

**Mitigazione:** il backup è un file locale; va protetto dall'utente. Se si
aggiunge una password, usare Argon2id + XChaCha20-Poly1305. Non caricare il
backup su servizi esterni.

**Residuo:** un backup non cifrato è una copia completa delle chiavi.

### T10. Avversario quantistico

**Minaccia:** decifrare in futuro i ciphertext conservati.

**Mitigazione:** sigillo ibrido X25519 + ML-KEM-768; AEAD simmetrica. Le firme
restano Ed25519 nella v1; un avversario quantistico potrebbe falsificare firme
future, non leggere il contenuto passato.

**Residuo:** firme non post-quantum. Una versione futura può usare ML-DSA con
un bump di protocollo.

### T11. Fork e partizionamento

**Minaccia:** due membri creano generazioni diverse o stati divergenti.

**Mitigazione:** la generazione successiva ha `previous_contract` e
`conversation_id`; il client preferisce il puntatore firmato da un membro
attivo; i fork non firmati sono ignorati. In v1 con due membri, il primo
puntatore valido vince.

**Residuo:** partizioni di rete prolungate possono produrre due finestre
temporanee; il client mostra lo stato più recente e conserva la cronologia
locale.

### T12. Link di invito in un contesto pubblico

**Minaccia:** il link finisce in una chat pubblica, in un log o in un QR
fotografato.

**Mitigazione:** il link è monouso e scade; il creatore può revocarlo; dopo
l'uso ruota la chiave. Il token è nel frammento, quindi non viene inviato al
server nel percorso HTTP.

**Residuo:** chi ha già aperto il link può aver letto la storia coperta dalla
chiave contenuta.

## 4. Proprietà di sicurezza attese

- **Riservatezza:** solo i dispositivi dei membri leggono il plaintext.
- **Autenticità:** ogni messaggio è firmato da un dispositivo attivo.
- **Integrità:** id, firma e cifratura coprono i campi del messaggio.
- **Freshness:** versioni monotone e timestamp; niente replay di membership.
- **Disponibilità:** il contratto è replicato da Freenet; il client può
  lavorare offline sulla cronologia locale.
- **Non ripudio:** la firma del dispositivo identifica il membro; non c'è
  anonimato tra i membri.
- **Minimizzazione:** il contratto contiene solo ciò che serve a verificare e
  decifrare.

## 5. Cosa non promettiamo

- Anonimato dei membri verso gli altri membri.
- Resistenza a un dispositivo compromesso che ha già letto la storia.
- Cancellazione remota della cronologia copiata da un membro.
- Forward secrecy per messaggio nella v1.
- Firme post-quantum nella v1.
- Disponibilità della mailbox se il nodo non la ospita.
- Notifiche con l'app chiusa.

## 6. Test di sicurezza

- Firma mancante, firma di un dispositivo revocato, firma di un non membro.
- Token riusato, scaduto, con binding errato.
- Delta con versione vecchia, versione uguale e contenuto diverso.
- Messaggio oltre il cap, ciphertext oltre il cap, nonce duplicato.
- Reply a un messaggio inesistente o di un'altra conversazione.
- Fork di generazione e puntatore non firmato.
- Fuzz di stato e delta.
- Prova che un client senza contract key non riesce a richiedere lo stato.
- Prova che un terzo membro non può leggere senza chiave sigillata.
