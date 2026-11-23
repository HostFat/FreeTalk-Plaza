# Shard dell'indice per sezione

Data: 2026-11-23. Stato: fase 3 implementata nella build locale v624. La
creazione di una sezione su una board `SectionedTopicIndex` crea la board
figlia e ne registra la chiave; topic, risposte, attività, flag e report
vengono scritti sulla figlia. La UI unisce gli indici delle figlie. Restano
l'aggregazione di ricerca/notifiche/moderazione e la propagazione
dell'autorità (fase 4-5).

## Problema

La board `TopicIndex` tiene in un unico contratto sezioni, membri, autorità e
l'indice completo dei topic (entry, attività, flag, report). Anche dopo la
verifica incrementale e l'accorpamento dell'attività, ogni modifica all'indice
viene trasmessa a tutti i membri e il contratto resta un punto di scrittura
globale. Con molte sezioni e molti topic il costo di rete e di verifica cresce
con l'intera board.

## Scelta: board figlie per sezione

Ogni sezione di una board indicizzata diventa una **board figlia** con lo
stesso codice di `ChatBoardStateV1`, parametri `{ owner, section_id }` e stato
limitato alla sezione:

- membri, ruoli, ban, admin e ownership sono una copia della board madre;
- `sections` contiene solo la sezione della figlia;
- `topics` contiene solo le entry, l'attività, i flag e i report di quella
  sezione;
- il topic contract resta invariato: un topic appartiene a una figlia.

La board madre conserva l'elenco delle sezioni e l'autorità; non conserva
l'indice dei topic. La UI tratta ogni sezione come una board.

### Perché questa scelta

- Riusa validazione, moderazione, flag, report, continuation e UI esistenti.
- Non introduce un nuovo modello di fiducia: la figlia verifica membri e
  autorità come la madre.
- Il costo di una risposta tocca una sola sezione, non l'intera board.
- La madre resta piccola e stabile.

### Svantaggi

- Membri e autorità sono replicati in ogni figlia. Un ban o un cambio di ruolo
  genera un update per figlia; con poche sezioni (indicativamente fino a
  20–30) è accettabile.
- La ricerca e la lista aggregata devono interrogare tutte le figlie.
- La migrazione delle board esistenti non è automatica; le nuove board
  partono già sectioned.

## Modello dati

### Board madre

- `sections`: elenco delle sezioni (id, nome, ACL, flag).
- `members`, `roles`, `bans`, `admins`, `ownership`: autorità globale.
- `topics`: vuoto nelle board nuove; resta per le board legacy.
- Nuovo `BoardModeV1::SectionedTopicIndex` per distinguere il modo.

### Board figlia

- Parametri: owner, `section_id`, `mode = SectionedTopicIndex`.
- `sections`: la sola sezione.
- `members`/autorità: copia della madre al momento della creazione e degli
  update di autorità.
- `topics`: indice della sezione.
- La verifica impone che ogni entry abbia `section == section_id` e che la
  sezione esista.

### Chiavi

- Madre: `board_key(owner)` come oggi.
- Figlia: `section_key(owner, section_id)` con byte di dominio diversi.
- Topic: invariata (`owner`, `topic_id`, `part`).

## Flussi

### Creazione sezione

1. L'owner crea la sezione nella madre.
2. Il client crea la figlia con lo stato iniziale (sezione + membri/autorità).
3. La madre registra la chiave della figlia nella sezione, firmata dall'owner.

### Creazione topic

1. Il client scrive il topic contract.
2. Scrive l'entry e l'attività nella figlia della sezione.
3. La madre non viene aggiornata.

### Risposta

1. Il client scrive il topic contract.
2. Aggiorna l'attività nella figlia (con l'accorpamento già presente).
3. La madre non viene aggiornata.

### Ban, ruoli, ownership

1. L'owner/modifica la madre.
2. Il client propaga membri e autorità a ogni figlia, con la stessa logica di
   `propagate_authority` già usata per i topic.
3. Una figlia non aggiornata può accettare un post da un membro appena
   bannato; la UI filtra e il client riprova. È lo stesso limite noto dei
   topic.

### Ricerca, notifiche, moderazione

- La ricerca interroga le figlie delle sezioni visibili, con cache e limite.
- Le notifiche leggono l'attività dalle figlie.
- La coda report/approvazioni aggrega le figlie; le azioni restano sulla
  figlia.

## Sicurezza

- Ogni figlia verifica firme, membri, ruoli, ban e sezione come la madre.
- La figlia non accetta entry di altre sezioni.
- La madre è l'unica fonte di autorità; le figlie sono copie firmate.
- Un client può creare una figlia con stato arbitrario? No: lo stato iniziale
  è firmato dall'owner e la figlia verifica l'autorità.
- Un attacco di sostituzione della chiave della figlia è impedito dal record
  firmato nella sezione.

## Migrazione

- Le board `TopicIndex` esistenti restano leggibili e non vengono migrate.
- Le nuove board usano `SectionedTopicIndex` e la UI non mostra il vecchio
  indice.
- Il passaggio è coperto da un nuovo `CONTRACT_REVISION` e da un nuovo WASM;
  le board vecchie vanno ricreate, come per i cambi precedenti.

## Fasi

1. **Contratto** (fatto): `SectionParametersV1 { owner, section }`, nuovo
   crate `plaza-section-contract`, modo `SectionedTopicIndex`, verifica della
   sezione, `SectionV1.contract` e test unitari. La madre rifiuta i topic nel
   proprio stato; la figlia accetta solo la propria sezione.
2. **Creazione e caricamento** (fatto): `create_section` calcola la chiave
   della figlia, la include nel record firmato della sezione, crea la figlia
   e la carica all'apertura della board. Il test real-node
   "a sectioned board creates a child index contract" verifica la chiave
   pubblicata.
3. **Topic e attività** (fatto): creazione topic, risposte, flag e report
   vanno sulla figlia della sezione; la madre resta invariata. Il client
   unisce gli indici delle figlie per la lista, la ricerca del topic e la
   continuation. La sezione General crea la sua figlia alla creazione della
   board. Test real-node sectioned esteso a topic, risposta e reload.
4. **Ricerca, notifiche e moderazione**: aggregazione delle figlie, cache,
   code report/approvazioni.
5. **Autorità**: propagazione di membri/ban/ruoli alle figlie, retry e test di
   ban/ruolo su più sezioni.
6. **Benchmark**: 10 sezioni × 200 topic; verificare che una risposta tocchi
   solo la figlia e che la madre resti piccola.

## Rischi

- Fan-out degli update di autorità su molte sezioni.
- Complessità del client (navigazione, cache, ricerca).
- Doppia copia di membri/autorità da tenere coerente.
- Migrazione e re-key delle board esistenti.

## Criterio di completamento

Una board con 10 sezioni e 2.000 topic totali deve:

- aggiornare una sola figlia per una risposta;
- mantenere la madre sotto poche decine di KiB;
- propagare un ban a tutte le figlie entro un ciclo di retry;
- mantenere ricerca, notifiche, report e approvazioni consistenti;
- passare la suite real-node con almeno uno scenario multi-sezione.
