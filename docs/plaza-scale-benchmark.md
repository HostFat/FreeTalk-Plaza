# Benchmark di scala di FreeTalk Plaza

Data: 2026-11-23. Build: release locale, Windows; misure aggiornate dopo la
verifica incrementale (v609). Metodo: due test `#[ignore]` che costruiscono
stati firmati e misurano `verify`, `apply_delta`, `apply_delta_incremental`,
serializzazione e dimensione.

Comandi:

```text
cargo test -p plaza-topic-core --release --lib scale_topic_benchmark -- --ignored --nocapture
cargo test -p plaza-core --release --test topic_index scale_board_benchmark -- --ignored --nocapture
```

## Risultati

### Topic

| Post | Stato | Serializzazione | `verify` | `apply_delta` (1 post) | `apply_delta_incremental` |
|---|---|---|---|---|---|
| 100 | 37 KiB | 0.3 ms | 236 ms | 231 ms | 12.7 ms |
| 200 | 73 KiB | 0.5 ms | 455 ms | 472 ms | 13.1 ms |

### Board (1.000 membri)

| Topic | Flag | Report | Stato | Serializzazione | `verify` | `apply_delta` (1 activity) | `apply_topics_delta` |
|---|---|---|---|---|---|---|---|
| 500 | 500 | 125 | 1063 KiB | 7.4 ms | 5,35 s | 1,33 s | 2,5 ms |
| 2.000 | 2.000 | 500 | 3253 KiB | 23.2 ms | 15,43 s | 5,38 s | 3,6 ms |

I tempi sono per operazione, misurati sul computer locale; il costo per firma
risulta circa 2–2,5 ms. Lo stato della board usa titoli e anteprime di pochi
byte: con contenuti reali da 512 byte per campo lo stato cresce di circa
2 MiB a 2.000 topic.

## Cosa dicono i numeri

1. **La verifica completa resta il costo dominante.** `verify` costa 5,35 s
   con 500 topic e 15,43 s con 2.000; 236 ms con 100 post e 455 ms con 200.
   La serializzazione costa 1–23 ms: il tempo è quasi tutto firma.
2. **Il percorso incrementale risolve il caso caldo.** Un post su un topic
   già validato richiede 13 ms indipendentemente da 100 o 200 post
   precedenti. Un delta che tocca solo l'indice della board richiede 2,5–3,6
   ms, contro 1,33–5,38 s del percorso completo. La suite real-node passa
   10/10 su questa build.
3. **La board resta un punto di scrittura globale.** Ora l'update costa pochi
   millisecondi, il client invia un delta rispetto all'ultimo stato confermato
   e le modifiche di sola attività vengono accorpate con un ritardo di 10
   secondi. Ogni risposta aggiorna comunque l'indice e il nodo trasmette lo
   stato risultante a tutti i membri. Shardare l'indice resta il prossimo
   guadagno di rete.
4. **Gli update che toccano membri, autorità o stato completo pagano ancora
   la verifica piena.** Un cambio di ruolo, ban o merge di stato su una board
   da 2.000 topic resta nell'ordine dei secondi. Sono eventi rari, ma vanno
   misurati e possibilmente resi incrementali.
5. **Il caso peggiore reale è peggiore del benchmark.** Titoli e anteprime
   pieni, `section_chain` fino a 64 id e flag con scope aumentano lo stato e
   il tempo di serializzazione; le azioni e le approvazioni aggiungono altre
   firme da verificare.

## Raccomandazioni

1. **Togliere l'attività dal contratto board.** Ora la verifica è economica,
   ma ogni risposta scrive ancora l'indice globale e lo trasmette a tutti i
   membri. Un contatore separato, aggiornamenti periodici o un contratto
   attività shardato.
2. **Gestire il percorso completo.** I delta di membri/autorità ora usano
   `verify_delta`, che salta la rifirma di tutti i topic ma verifica ancora
   membri, ban e ruoli per intero. Restano da rendere incrementali anche
   queste parti e da misurare il caso reale; i merge di stato completo
   richiedono ancora la verifica piena.
3. **Non alzare i limiti attuali.** La parte è scesa a 200 post / 512 KiB;
   2.000 topic restano alti per gli update completi. Se serve usabilità
   immediata, 500 topic per board è un tampone.
4. **Shardare l'indice per sezione** e **dividere i post in pagine** per
   ridurre il broadcast dello stato completo.
5. **Ripetere il benchmark con contenuti realistici, azioni, approvazioni e
   1.000 membri attivi**, e su un secondo computer, per separare il costo
   algoritmico dalla velocità della CPU.

## Test

I benchmark sono test ignorati: la CI normale non li esegue. I test
funzionali restano quelli di `plaza-core` (325) e `plaza-topic-core` (40).
