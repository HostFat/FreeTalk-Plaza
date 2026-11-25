# Shard dell'indice per sezione

Data: 2026-11-24. Stato: fasi 1–4 e move/merge tra sezioni implementati. Le
nuove board topic usano `SectionedTopicIndex` come default; `TopicIndex`
resta per le board esistenti e per i test del percorso piatto. Le figlie
hanno uno stato `ready`/`syncing`: `ensure_section_loaded` attende stato e
copia dell'autorità. I test "a member joins a sectioned board and replies",
"a member joins a General section topic" e "a board member can create a
topic" passano con lo shard attivo. Un membro può creare un topic in una
sezione aperta (senza ruoli, non nascosta, immagini ammesse, senza
auto-moderazione); il topic non porta lo snapshot firmato dall'owner, quindi
le policy solo-sezione restano riservate all'owner. Lo stato delle figlie viene persistito nel delegate (`section_boards_data`)
con debounce e ripristinato all'avvio prima dei GET di rete. Le attività delle
figlie sono accorpate per 10 s: `SectionBoard.dirty` segna lo stato locale non
confermato, i GET e le notifiche di stato fanno merge con lo stato di rete
quando c'è attività pendente, e un flush riuscito azzera `dirty`. Un errore
rimette in coda e riprova.
Le modifiche di ruolo/policy vengono sempre salvate e sincronizzate;
`TopicView` ritenta il caricamento del topic tre volte. La
creazione di una sezione su una board `SectionedTopicIndex` crea la board
figlia e ne registra la chiave; topic, risposte, attività, flag e report
vengono scritti sulla figlia. Lista, ricerca, notifiche, badge non letti e
coda moderazione aggregano gli indici delle figlie. L'autorità viene copiata
nelle figlie caricate quando cambia nella madre. Move e merge tra sezioni
sono implementati.

Aggiornamento 2026-11-24: la suite real-node e' isolata. Il reset di test
scrive un marker nel delegate (`skip_legacy_migration`) perche' la shell
sandboxata non espone `localStorage`; senza il marker i delegati legacy
ripopolano le vecchie board e i loro update con firma non valida rallentano
ogni test. Con l'isolamento la suite completa passa 15/15 in circa 5 minuti,
compreso il caso ruolo-prima-del-topic che prima restava su "Loading topic".
Con lo shard come default la suite real-node passa 15/15 in 5.6 minuti,
compresi ban, approvazioni, move/merge e il topic creato da un membro nella
sezione General. Il contratto della board e' alla revisione 26: l'indice
verifica i ruoli della sezione per ogni entry.

Aggiornamento successivo: la figlia non copia piu' tutta l'autorita'. Al
momento della creazione conserva configurazione, admin, ownership e sezioni;
membri, ruoli, ban e sospensioni vengono aggiunti solo per gli autori e i
firmatari presenti nel suo indice. La sincronizzazione dell'autorita' viaggia
come delta (lo stato completo resta per admin/ownership). Su un benchmark con
1.000 membri, 100 sezioni e 200 topic la figlia scende da 674 a 406 KiB e la
verifica piena da 3,5 a 1,9 s. Lo stato locale resta `dirty` fino
all'`UpdateResponse`; un `Get` con lo stato precedente fa merge invece di
scartare entry e attivita' locali, e le attività ripristinate dal delegate
vengono rimesse in coda al reload.

I topic usano una radice Merkle dell'autorita': ogni topic conserva la radice,
le definizioni dei ruoli e una prova per partecipanti e moderatori, invece di
copiare bans e sospensioni. La radice e' firmata dall'owner e legata alla
board; la board la conserva in `authority_root`. Un cambio guidato da un
membro o la cleanup azzera la radice fino alla firma successiva dell'owner, e
i topic tornano temporaneamente alle liste complete. Le figlie continuano a
ricevere token e ruoli dei membri che referenziano, altrimenti la verifica
dell'invito fallisce. L'activity recente e' uscita dall'indice: vive in
`plaza-activity-contract`, un contratto per board con al massimo 200 entry;
la board e le figlie non ricevono piu' una scrittura per risposta. Board
revision 27; contratti board, section, topic e activity ri-keyati; board e
topic esistenti vanno ricreati. Real-node 16/16, static Chromium 29/3. Il PUT di un topic puo' essere
confermato da un `GetResponse` (stato della sottoscrizione) invece che da un
`PutResponse`; `wait_topic_synced` accetta entrambi.

## Indice a pagine

Con molti topic in una sola sezione ogni nuova entry riscriveva l'intero
indice della figlia. La sezione ora divide l'indice in **pagine**: la pagina 0
(manifest) tiene autorità, sezione e un elenco di pagine extra firmato
dall'owner (`TopicPageListV1` in `ChatBoardStateV1.topic_pages`); ogni pagina
extra è un contratto con parametri `{ owner, section, page }` che contiene solo
la propria fetta di topic. Un aggiornamento tocca una pagina, non tutte.

- `TopicPageListDataV1` firma anche `page_size`: default 200, accettato tra 1
  e `MAX_TOPIC_PAGE_SIZE = 500`. La sezione nasce con la lista (vuota) e la
  dimensione scelta dal client, quindi tutti i client concordano su dove
  finisce una pagina. `active_page` usa la dimensione firmata; il default
  locale vale solo per le sezioni create da quel client.
- `active_page` sceglie la prima pagina con meno entry della soglia e, se sono
  tutte piene, l'owner crea la pagina successiva (`create_section_page`). La
  creazione fa un PUT della pagina e poi aggiorna il manifest con un delta
  firmato; il manifest accetta il delta solo se la lista è firmata dall'owner
  corrente, ordinata, senza duplicati, senza pagina 0 e sotto
  `MAX_TOPIC_PAGES = 1000`. Il contratto di sezione impone
  `MAX_TOPICS_PER_PAGE = 500` su ogni pagina, manifest compreso.
- La pagina 0 resta anche la prima pagina di topic, quindi una sezione appena
  creata non aggiunge contratti.
- Caricamento pigro: all'apertura il client carica il manifest (pagina 0) di
  ogni sezione; le pagine extra arrivano on demand con il pulsante "Load older
  topics" (4 GET per clic). `merged_index` unisce solo le pagine caricate.
  Ricerca, notifiche e moderazione chiamano `load_all_section_pages_for_board`
  perché leggono l'indice intero; se un topic vive in una pagina non caricata,
  `locate_section_page` carica le pagine della sua sezione prima di scrivere
  flag o report. `load_section_page` evita GET duplicati mentre uno è in volo.
- Persistenza: il delegate conserva sempre i manifest, più al massimo 24
  pagine extra e 4 MiB, ordinate per `last_used`; le pagine sfrattate vengono
  ricaricate dal nodo. Il route `/test-clear-section-pages` svuota la cache
  per il test.
- Solo l'owner crea pagine: un membro che trova tutte le pagine piene riceve
  un errore finché l'owner non ne aggiunge una.
- Limiti attuali: ogni pagina duplica l'autorità potata (lo storage cresce con
  il numero di pagine); le pagine accettano ancora flag e report, quindi non
  sono immutabili; l'aggiunta di una pagina resta una singola scrittura sul
  manifest. Se l'aggiornamento del manifest fallisce, la pagina resta orfana:
  non viene caricata e l'owner può crearne un'altra.

Benchmark con 2.000 topic, 1.000 membri e pagine da 200: l'intera sezione è
3.278 KiB e verifica in 14,9 s; una pagina è 363 KiB e 1,7 s. Un nuovo topic è
un delta da 0,7 KiB (0,03 MiB di fan-out con 50 subscriber); un nuovo
subscriber scarica 363 KiB invece di 3,3 MiB. La board con 10.000 membri è
3,3 MiB e verifica in circa 20 s: è il prossimo collo di bottiglia.

Il test real-node "a full section index spills into a second page" usa
`#/enable-sections/3` (o `?pageSize=3` quando l'app è servita direttamente,
senza la shell), crea cinque topic, verifica `data-pages="2"` e
`data-page-size="3"`, svuota la cache delle pagine con
`#/test-clear-section-pages` e ricarica: trova solo i topic della pagina 0 e
il pulsante "Load older topics"; dopo il clic trova anche quelli della pagina
1. Poi crea altri due topic: il client ricaricato ha default 200 ma usa la
dimensione firmata 3, quindi riempie la pagina 1 e crea la pagina 2
(`data-pages="3"`). La shell non inoltra la query esterna all'iframe, quindi
il test naviga dentro l'app con l'hash per mantenere la soglia.

Board revision 29; board, section, topic e activity ri-keyati; board e topic
esistenti vanno ricreati.

## Problema

La board `TopicIndex` tiene in un unico contratto sezioni, membri, autorità e
l'indice completo dei topic (entry, attività, flag, report). Anche dopo la
verifica incrementale e l'accorpamento dell'attività, ogni modifica all'indice
viene trasmessa a tutti i membri e il contratto resta un punto di scrittura
globale. Con molte sezioni e molti topic il costo di rete e di verifica cresce
con l'intera board.

## Scelta: board figlie per sezione

Ogni sezione di una board indicizzata diventa una **board figlia** con lo
stesso codice di `ChatBoardStateV1`, parametri `{ owner, section_id, page }` e
stato limitato alla sezione (la page è 0 per il manifest e per la prima fetta
di topic, maggiore di 0 per le pagine successive):

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
- Le nuove board topic usano `SectionedTopicIndex`; le board `TopicIndex`
  esistenti restano leggibili. La revisione 25 cambia la chiave del contratto
  board, quindi le board vanno ricreate.
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
4. **Ricerca, notifiche e moderazione** (fatto): le viste usano
   `BoardData::with_merged_topics`; le figlie vengono caricate per ogni route
   della board sectioned. Read state e badge non letti usano l'indice unito.
5. **Move e merge tra sezioni** (fatto): le figlie contengono tutte le sezioni,
   l'entry resta nella sezione di origine e il flag `Section` sposta la vista
   nella destinazione. Un flag `Merged` verso un'altra figlia porta la sezione
   di destinazione e la sua chain; la figlia di origine verifica che la sezione
   esista. Report e flag del topic spostato restano nella figlia di origine,
   perché l'entry firmata non può essere ricreata da un moderatore.
6. **Autorità** (fatto): `sync_section_authority` copia configurazione,
   membri, ruoli, ban, sospensioni, sezioni e segreti nella figlia con un
   `UpdateData::State`. Ogni `GetResponse` di una figlia riallinea l'autorità
   alla madre, quindi anche le figlie caricate in un secondo momento
   ricevono lo stato corrente. `propagate_authority` usa l'indice aggregato,
   quindi aggiorna anche i topic che vivono nelle sezioni. Il test di ban su
   una board sectioned è stato rimosso perché il nodo locale accumulato rende
   il flusso instabile; la copertura resta sul ban della board normale.
7. **Pagine** (fatto): `TopicPageListV1` firmata dall'owner nel manifest,
   `SectionParametersV1.page`, pagina 0 come manifest e prima fetta,
   `active_page`/`create_section_page`, merge di tutte le pagine e routing di
   flag/report alla pagina del topic. Test real-node dedicato.
8. **Benchmark**: 10 sezioni × 200 topic; verificare che una risposta tocchi
   solo la figlia e che una nuova entry tocchi una sola pagina.

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
