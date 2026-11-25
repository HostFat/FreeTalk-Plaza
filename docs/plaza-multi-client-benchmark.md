# Benchmark multi-client: costo strutturale di una board sectioned

Data: 2026-11-24. Build: release locale, Windows. Il test misura lo stato e
i payload che il nodo trasmette, poi li moltiplica per il numero di
subscriber e di sezioni. Non e' una simulazione di rete: e' il costo che la
struttura attuale impone a ogni aggiornamento.

Comando:

```text
cargo test -p plaza-core --test scale_multi_client --release -- --ignored --nocapture
```

## Scenario

- 1.000 membri firmati nella board madre.
- 20 o 100 sezioni, ognuna con il proprio contratto figlio.
- 200 topic per sezione, con activity, un flag e un report ogni quattro topic.
- 50 subscriber per sezione (client che hanno aperto quella sezione).

La board madre contiene solo configurazione, membri e sezioni. Ogni figlia
copia l'autorita' della madre e aggiunge l'indice della propria sezione.

## Risultati

| Sezioni | Madre | Figlia piena | Verify piena | Figlia pruned | Verify pruned | Legacy activity delta |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 345 KiB | 639 KiB | 3,46 s | 363 KiB | 1,71 s | 2,1 ms |
| 100 | 380 KiB | 674 KiB | 3,61 s | 363 KiB | 1,67 s | 2,0 ms |

| Sezioni | Storage figlie (pruned) | Activity contract | Summary / 1-entry delta | Fan-out activity (50 sub) | Authority sync |
|---:|---:|---:|---:|---:|---:|
| 20 | 7,1 MiB | 83,2 KiB (200 entry) | 8,6 KiB / 0,42 KiB | 0,021 MiB (delta) / 4,06 MiB (full) | 7,1 MiB |
| 100 | 35,4 MiB | 83,2 KiB (200 entry) | 8,6 KiB / 0,42 KiB | 0,021 MiB (delta) / 4,06 MiB (full) | 35,4 MiB |

Le figlie ora tengono solo la propria catena di sezioni: la dimensione pruned è
la stessa con 20 e con 100 sezioni sorelle (363 KiB), e lo storage cresce con
le figlie, non con il quadrato delle sezioni.

Indice a pagine, 1.000 membri, 2.000 topic, pagine da 200 (10 pagine):

| Unità | Dimensione | Verify | Summary / note |
|---|---:|---:|---|
| Sezione intera | 3.278,4 KiB | 15,5 s | bootstrap 3,3 MiB |
| Manifest (pagina 0, `ChatBoardStateV1`) | 363,1 KiB | 1,73 s | autorità potata + `topic_pages` + flag sezione |
| Pagina compatta aperta (`page > 0`, `SectionPageStateV1`) | 190,9 KiB | 813 ms | summary 21,4 KiB; delta 1 topic 0,97 KiB (4,33 ms) |
| Pagina compatta sigillata (`page > 0`, `SectionPageStateV1`) | 124,4 KiB | 5,19 ms | summary 9,0 KiB; 0 autori/autorità duplicati (~333× più veloce) |

Lo storage della sezione da 10 pagine scende da 3,55 MiB (10 copie di
`ChatBoardStateV1` potato) a 1,51 MiB (1 manifest + 8 pagine sigillate + 1
aperta, -57%). Il fan-out di sincronizzazione dell'autorità tocca 1 solo
contratto per sezione (il manifest) invece di tutte le pagine. Un nuovo topic
è un delta da 0,7–0,97 KiB: con 50 subscriber il fan-out è 0,03–0,05 MiB. Il
manifest cambia solo quando nasce una pagina o arriva un flag.

Moderazione, 500 report e 500 risoluzioni:

| Unità | Dimensione | Fan-out (50 sub) |
|---|---:|---:|
| Feed completo (bootstrap) | 362,8 KiB | — |
| `ReportFeedSummaryV1` (sync peer) | 100,5 KiB | — |
| Un nuovo report (delta) | 0,34 KiB | 0,017 MiB |
| Una risoluzione (delta) | 0,42 KiB | 0,021 MiB |

Le scritture di report sulla board o sulla pagina della sezione sono zero, e la
sincronizzazione peer-to-peer usa summary/delta incrementali invece di
ritrasmettere l'intero feed.

Membri della board con nickname (10 sezioni, nessun topic):

| Membri | Board | Nickname | Verify piena | Verify root | Delta nickname |
|---:|---:|---:|---:|---:|---:|
| 1.000 | 618 KiB | 277 KiB | 4,3 s | 39 ms | 4,6 ms |
| 5.000 | 3.076 KiB | 1.395 KiB | 21,3 s | 162 ms | 5,1 ms |
| 10.000 | 6.148 KiB | 2.792 KiB | 45,8 s | 540 ms | 6,2 ms |

Senza nickname la board da 10.000 membri è 3.356 KiB: i nickname sono circa il
45% dello stato. La radice firmata ora copre anche il record del nickname, e
un cambio di nickname verifica solo il record del delta: il percorso caldo
passa da 20 s a 6 ms.

I profili sono ora shardati in 32 bucket deterministici (`plaza-profile-contract`,
`bucket = blake3(member_id)[0..2] % 32`, stesso bucket di `plaza-member-contract`)
con `ProfileSummaryV1` e `get_state_delta` incrementale:

| Membri | Profili monolitico | Bucket 0 | Max bucket | Summary b0 | Verify b0 | Rename/sync delta |
|---:|---:|---:|---:|---:|---:|---:|
| 1.000 | 314,3 KiB | 10,3 KiB (33 p.) | 13,5 KiB | 2,1 KiB | 67,3 ms | 0,32 KiB (2,0 ms) |
| 5.000 | 1.580,8 KiB | 55,3 KiB (175 p.) | 55,3 KiB | 10,9 KiB | 399,3 ms | 0,32 KiB (2,6 ms) |
| 10.000 | 3.163,0 KiB | 102,8 KiB (325 p.) | 108,8 KiB | 20,3 KiB | 714,5 ms | 0,32 KiB (2,4–2,5 ms) |

A 10.000 membri ciascun bucket profili è ~30× più piccolo del feed monolitico;
al bootstrap il client scarica solo il proprio bucket (`GET`-only) e i bucket
degli autori visibili vengono caricati pigro per vista, mentre il sync tra peer
invia solo i record nuovi/aggiornati (0,32 KiB per un rename).

I membri sono ora shardati in 32 bucket deterministici (`plaza-member-contract`,
`bucket = blake3(member_id)[0..2] % 32`):

| Membri | Board (senza nick) | Bucket 0 | Max bucket | Verify bucket 0 | Join delta |
|---:|---:|---:|---:|---:|---:|
| 1.000 | 340,7 KiB | 11,3 KiB (33 m.) | 14,8 KiB | 81,1 ms | 0,35 KiB (2,5 ms) |
| 5.000 | 1.680,9 KiB | 60,0 KiB (175 m.) | 60,0 KiB | 381,8 ms | 0,36 KiB (2,6 ms) |
| 10.000 | 3.356,1 KiB | 111,4 KiB (325 m.) | 118,0 KiB | 740,0 ms | 0,35 KiB (2,9–3,4 ms) |

A 10.000 membri (con 10 o 100 sezioni) ciascun bucket è ~30× più piccolo della
lista monolitica, il bootstrap scarica solo il proprio bucket (`GET`-only) e
ogni join è un delta da `0,35 KiB` verificato in ~3 ms senza scrivere sulla
board madre né richiedere l'owner online.

Con 100 sezioni e 10.000 membri il costo dipende dai membri, non dalle
sezioni.

Prima del pruning le figlie erano 639/674 KiB, lo storage 12,5/65,9 MiB,
il fan-out dell'activity 31,2/32,9 MiB e la sincronizzazione dell'autorita'
12,5/65,9 MiB. Ora una figlia pruned è 363 KiB in entrambi gli scenari e lo
storage è 7,1/35,4 MiB. Una risposta scrive il topic e il contratto activity;
la board e le figlie non ricevono più l'activity.

## Cosa dicono i numeri

1. **L'activity e' fuori dalla figlia e sincronizza per delta.** Una risposta
   scrive il topic e il contratto activity per board (83,2 KiB con 200 entry;
   `ActivitySummaryV1` 8,6 KiB; sync delta di 1 entry 0,42 KiB, cioè 0,021 MiB
   di fan-out con 50 subscriber invece di 4,06 MiB di stato pieno). La board
   non riceve piu' l'activity. Il fast path del contratto section resta per
   gli altri delta.
2. **La verifica completa resta il costo di ingresso.** Un nuovo subscriber,
   un `UpdateData::State` o un merge versionato pagano 1,7 s per figlia con
   1.000 membri e 200 topic, dopo il pruning e la catena di sezioni.
3. **Un nuovo topic trasmette un delta piccolo.** Il client invia un
   `TopicIndexDelta` da 0,7 KiB; con 50 subscriber il fan-out e' 0,03 MiB.
   Lo stato completo (371-406 KiB) serve a un nuovo subscriber o a un
   resync, non a ogni topic. L'activity non contribuisce a questo traffico.
4. **Il pruning e la catena tagliano circa il 45% della figlia.** La figlia
   conserva solo i membri che il suo indice referenzia e la propria catena di
   sezioni: 363 KiB invece di 639-674 KiB, con una verifica piena di 1,7 s
   invece di 3,5 s. La dimensione pruned non dipende dalle sezioni sorelle.
   Le definizioni dei ruoli restano nel topic.
5. **Le pagine compatte e sigillate eliminano l'autorità duplicata.** Con
   `page_size=200` una nuova entry tocca solo la pagina attiva (`O(1)` lookup
   della coda); le pagine extra (`page > 0`) usano `SectionPageStateV1` senza
   `configuration`/`sections`/`bans`/`suspensions`/`flags` e non ricevono mai
   `sync_section_authority`. Quando la pagina si riempie e l'owner crea la
   successiva, la pagina piena viene sigillata (`AuthorizedSectionPageSealV1`):
   tutti gli autori duplicati vengono rimossi (124,4 KiB invece di 363,1 KiB)
   e la verifica di bootstrap passa da 1,73 s a 5,19 ms (~333× più veloce).
   Lo storage di 10 pagine scende da 3,55 MiB a 1,51 MiB.
6. **La propagazione dell'autorita' e' il caso peggiore.** Un cambio di
   ruolo o un ban sincronizza tutte le figlie (35,4 MiB nello scenario da 100
   sezioni dopo il pruning) e poi aggiorna ogni topic. Il limite di 100 topic
   e' stato rimosso. Ogni topic riceve una radice Merkle firmata dall'owner e
   le prove dei suoi membri, non la copia globale di ban/sospensioni; le
   definizioni dei ruoli restano nel topic. Un cambio guidato da un membro
   azzera la radice fino alla firma successiva dell'owner, e i topic usano
   temporaneamente le liste complete. La passata carica ogni topic, quindi il
   costo CPU del client cresce con il numero di topic: aggiornamenti
   incrementali della sola radice sono il passo successivo.
7. **I membri restano il limite.** La board tiene tutti i membri: a 10.000
   membri pesa 3,3 MiB senza nickname. Con una radice firmata valida la
   verifica scende da 20 s a 88 ms (tree 53 ms); senza radice, o per una
   modifica guidata da un admin, resta la verifica completa. I nickname sono
   fuori (feed separato da 3,2 MiB); paginare membri e profili toglie la
   crescita dello stato e del bootstrap.
8. **La moderazione e' fuori dall'indice.** Un report e' un delta da 0,3 KiB
   al contratto moderazione; il feed completo (500 report + 500 risoluzioni)
   e' 362,8 KiB per un nuovo subscriber.

## Prossimi passi

1. Indice a pagine con manifest (fatto): aggiornamenti limitati alla pagina,
   `page_size` firmato con cap 500, caricamento pigro e budget dello storage
   locale.
2. Moderazione fuori dall'indice (fatto): feed per board, report e
   risoluzioni verificati dal client.
3. Radice firmata come percorso veloce di verifica (fatto): 10.000 membri
   passano da 20 s a 88 ms.
4. Profili fuori dalla board (fatto): nickname nel contratto profili, delta
   da 0,3 KiB, zero scritture sulla board.
5. Membri shardati in 32 bucket deterministici (fatto): `plaza-member-contract`,
   111,4 KiB/bucket (max 118,0 KiB) a 10.000 membri (~30× meno della board
   monolitica), join delta 0,35 KiB (~3 ms), zero dipendenza dall'owner online.
6. Profili shardati in 32 bucket deterministici e delta incrementali nei feed
   per-board (fatto): `plaza-profile-contract` shardato con `bucket =
   blake3(member_id)[0..2] % 32` (102,8 KiB/bucket, max 108,8 KiB a 10.000
   profili, ~30× meno del feed monolitico; caricamento pigro per autore/vista)
   e `summarize_state`/`get_state_delta` incrementali in `profile-contract`,
   `activity-contract` (delta 0,42 KiB vs 83,2 KiB) e `moderation-contract`
   (delta 0,34–0,42 KiB vs 362,8 KiB).
7. Compattare le pagine e l'autorita' duplicata (fatto, rev 35): le pagine
   extra (`page > 0`) usano `SectionPageStateV1` senza autorità duplicata né
   flag (tutti i flag di sezione vivono nel manifest pagina 0) e non ricevono
   `sync_section_authority`; alla creazione della pagina successiva l'owner
   sigilla le pagine piene (`AuthorizedSectionPageSealV1`), azzerando gli
   autori duplicati (124,4 KiB, verifica 5,19 ms vs 363,1 KiB / 1,73 s; 10
   pagine 1,51 MiB vs 3,55 MiB) e permettendo comunque gli edit autore tramite
   `entry_edits`. Fixata anche la potatura su pagina 0 nei sync `admin`/
   `ownership`.
8. Topic a pagine append-only; una risposta scrive una pagina.
9. Compattare le sezioni nelle figlie (`O(sezioni^2)`) e le definizioni dei
   ruoli.
10. Aggiornamenti incrementali della sola radice per i topic, senza caricare
    ogni topic nella passata di propagazione.
11. Subscription lazy con budget/TTL e `Unsubscribe` quando la stdlib lo
    espone.

## Limiti del benchmark

- Nessuna latenza di rete o perdita di pacchetti.
- I subscriber sono un modello: il fan-out reale dipende dal nodo e dalla
  topologia.
- I contenuti sono brevi; titoli e anteprime pieni aumentano lo stato.
- Le firme sono Ed25519 locali; una CPU piu' lenta o firme PQ cambiano i
  tempi assoluti, non il rapporto tra fast path e verifica completa.
