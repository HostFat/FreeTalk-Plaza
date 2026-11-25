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

| Sezioni | Madre | Figlia piena | Verify piena | Figlia pruned | Verify pruned | Activity delta |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 345 KiB | 639 KiB | 3,50 s | 371 KiB | 1,75 s | 2,1 ms |
| 100 | 380 KiB | 674 KiB | 3,53 s | 406 KiB | 1,90 s | 2,0 ms |

| Sezioni | Storage figlie (pruned) | Activity fan-out (50 sub) | Authority sync a tutte le figlie |
|---:|---:|---:|---:|
| 20 | 7,3 MiB | 18,1 MiB per finestra di 10 s | 7,3 MiB |
| 100 | 39,7 MiB | 19,8 MiB per finestra di 10 s | 39,7 MiB |

Prima del pruning le figlie erano 639/674 KiB, lo storage 12,5/65,9 MiB,
il fan-out 31,2/32,9 MiB e la sincronizzazione dell'autorita' 12,5/65,9 MiB.

## Cosa dicono i numeri

1. **Il fast path della figlia funziona.** Dopo la correzione del contratto
   section, un aggiornamento di sola activity costa 2 ms + layout scan
   trascurabile, contro 3,5 s della verifica completa. Il contratto non
   rifirma piu' tutti i membri e tutti i topic a ogni refresh.
2. **La verifica completa resta il costo di ingresso.** Un nuovo subscriber,
   un `UpdateData::State` o un merge versionato pagano 3,5 s per figlia con
   1.000 membri e 200 topic. E' il costo da ridurre con autorita' compatta e
   indice a pagine.
3. **Il broadcast e' il vero collo di bottiglia.** Il nodo restituisce lo
   stato completo della figlia (639-674 KiB) a ogni subscriber. Con 50
   subscriber sono 18-20 MiB per finestra di activity (31-33 prima del
   pruning), anche se il calcolo del contratto costa 2 ms. Togliere
   l'activity dalla figlia o restituire solo il delta elimina questo traffico.
4. **Il pruning taglia circa il 40% della figlia.** La figlia conserva solo i
   membri che il suo indice referenzia: 371-406 KiB invece di 639-674 KiB,
   con una verifica piena di 1,75-1,90 s invece di 3,5 s. Restano le sezioni
   copiate in ogni figlia (`O(sezioni^2)`) e le copie nei topic. Un authority
   root con prove di inclusione eliminera' anche quelle.
5. **La propagazione dell'autorita' e' il caso peggiore.** Un cambio di
   ruolo o un ban sincronizza tutte le figlie (39,7 MiB nello scenario da 100
   sezioni dopo il pruning) e poi aggiorna ogni topic. Il limite di 100 topic
   e' stato rimosso. Ogni topic riceve una radice Merkle firmata dall'owner e
   le prove dei suoi membri, non la copia globale di ban/sospensioni; le
   definizioni dei ruoli restano nel topic. Un cambio guidato da un membro
   azzera la radice fino alla firma successiva dell'owner, e i topic usano
   temporaneamente le liste complete. La passata carica ogni topic, quindi il
   costo CPU del client cresce con il numero di topic: aggiornamenti
   incrementali della sola radice sono il passo successivo.

## Prossimi passi

1. Authority root + prove di inclusione al posto delle copie ancora presenti
   (tutte le sezioni in ogni figlia, roles/bans nei topic). Il pruning delle
   figlie e' gia' implementato.
2. Activity fuori dall'indice della figlia (nel topic o in un contratto
   activity separato).
3. Indice a pagine con manifest; aggiornamenti limitati alla pagina.
4. Topic a pagine append-only; una risposta scrive una pagina.
5. Subscription lazy con budget/TTL e `Unsubscribe` quando la stdlib lo
   espone.

## Limiti del benchmark

- Nessuna latenza di rete o perdita di pacchetti.
- I subscriber sono un modello: il fan-out reale dipende dal nodo e dalla
  topologia.
- I contenuti sono brevi; titoli e anteprime pieni aumentano lo stato.
- Le firme sono Ed25519 locali; una CPU piu' lenta o firme PQ cambiano i
  tempi assoluti, non il rapporto tra fast path e verifica completa.
