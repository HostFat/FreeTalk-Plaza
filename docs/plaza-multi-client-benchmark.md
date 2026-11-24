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

| Sezioni | Madre | Verify madre | Figlia | Verify figlia | Activity delta | Layout scan |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 345 KiB | 2,14 s | 639 KiB | 3,50 s | 2,1 ms | 0,0 ms |
| 100 | 380 KiB | 2,29 s | 674 KiB | 3,53 s | 2,0 ms | 0,0 ms |

| Sezioni | Storage figlie | Activity fan-out (50 sub) | Authority sync a tutte le figlie |
|---:|---:|---:|---:|
| 20 | 12,5 MiB | 31,2 MiB per finestra di 10 s | 12,5 MiB |
| 100 | 65,9 MiB | 32,9 MiB per finestra di 10 s | 65,9 MiB |

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
   subscriber sono 31-33 MiB per finestra di activity, anche se il calcolo
   del contratto costa 2 ms. Togliere l'activity dalla figlia o restituire
   solo il delta elimina questo traffico.
4. **Le figlie duplicano membri e sezioni.** Lo storage cresce con
   `O(sezioni x membri + sezioni^2)`: 100 figlie con 1.000 membri e 100
   sezioni occupano circa 66 MiB. Una autorita' condivisa o un root compatto
   riduce lo stato a pochi KiB per figlia.
5. **La propagazione dell'autorita' e' il caso peggiore.** Un cambio di
   ruolo o un ban sincronizza tutte le figlie (66 MiB nello scenario da 100
   sezioni) e poi propaga ai topic, con il limite attuale di 100 topic per
   passata. Serve un epoch/root con prove, non una copia completa per topic.

## Prossimi passi

1. Authority root + prove di inclusione al posto di members/roles/bans
   copiati in ogni figlia e topic.
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
