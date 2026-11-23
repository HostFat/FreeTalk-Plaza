# Benchmark di scala di FreeTalk Plaza

Data: 2026-11-23. Build: release locale, Windows. Metodo: due test `#[ignore]`
che costruiscono stati firmati e misurano `verify`, `apply_delta`,
serializzazione e dimensione.

Comandi:

```text
cargo test -p plaza-topic-core --release --lib scale_topic_benchmark -- --ignored --nocapture
cargo test -p plaza-core --release --test topic_index scale_board_benchmark -- --ignored --nocapture
```

## Risultati

### Topic

| Post | Stato | Serializzazione | `verify` | `apply_delta` (1 post) |
|---|---|---|---|---|
| 100 | 37 KiB | 0.3 ms | 254 ms | 241 ms |
| 500 | 180 KiB | 1.4 ms | ~1,15 s | ~1,15 s |

### Board (1.000 membri)

| Topic | Flag | Report | Stato | Serializzazione | `verify` | `apply_delta` (1 activity) |
|---|---|---|---|---|---|---|
| 500 | 500 | 125 | 1063 KiB | 7.4 ms | 5,35 s | 1,33 s |
| 2.000 | 2.000 | 500 | 3253 KiB | 23.2 ms | 15,43 s | 5,38 s |

I tempi sono per operazione, misurati sul computer locale; il costo per firma
risulta circa 2–2,5 ms. Lo stato della board usa titoli e anteprime di pochi
byte: con contenuti reali da 512 byte per campo lo stato cresce di circa
2 MiB a 2.000 topic.

## Cosa dicono i numeri

1. **`apply_delta` non è incrementale.** `TopicStateV1::apply_delta` chiama
   `self.verify(params)` alla fine; `TopicIndexV1::apply_delta` verifica ogni
   record ma il contratto richiama poi `ChatBoardStateV1::verify`. Il costo di
   un delta è quindi quello di una verifica completa, non quello del record
   aggiunto.
2. **`update_state` verifica due volte.** Il contratto applica il delta (che
   verifica tutto) e poi chiama di nuovo `verify`. Il costo reale di una
   risposta è circa il doppio di `apply_delta`: ~2,3 s per un topic da 500
   post e ~20 s per una board da 2.000 topic.
3. **Il collo di bottiglia è la verifica delle firme.** La serializzazione
   costa 1–23 ms, la verifica 0,25–15 s. Con 1.000 membri, la sola lista
   membri costa circa 2,5 s per ogni update della board.
4. **I limiti attuali sono già alti per il modello attuale.** 2.000 topic
   significano 15 s di verifica per ogni aggiornamento della board; 500 post
   significano 1,15 s per ogni risposta al topic. Ogni risposta aggiorna anche
   la board, quindi il costo si somma.
5. **Il caso peggiore reale è peggiore del benchmark.** Titoli e anteprime
   pieni, `section_chain` fino a 64 id e flag con scope aumentano lo stato e
   il tempo di serializzazione; le azioni e le approvazioni aggiungono altre
   firme da verificare.

## Raccomandazioni

1. **Verifica incrementale, priorità massima.** In `update_state` validare
   solo i record del delta contro lo stato precedente già validato, più le
   invarianti; togliere la seconda `verify` completa. In `apply_delta` non
   richiamare `verify` sull'intero stato.
2. **Togliere l'attività dal contratto board.** Ogni risposta non deve
   riscrivere l'indice globale. Un contatore separato, aggiornamenti
   periodici o un contratto attività shardato.
3. **Non alzare i limiti attuali.** 500 post e 2.000 topic restano alti finché
   la verifica è completa. Se serve usabilità immediata, scendere a 200 post
   per parte e 500 topic per board è un tampone, non una soluzione.
4. **Shardare l'indice per sezione** e **dividere i post in pagine** dopo la
   verifica incrementale.
5. **Ripetere il benchmark con contenuti realistici, azioni, approvazioni e
   1.000 membri attivi**, e su un secondo computer, per separare il costo
   algoritmico dalla velocità della CPU.

## Test

I benchmark sono test ignorati: la CI normale non li esegue. I test
funzionali restano quelli di `plaza-core` (325) e `plaza-topic-core` (40).
