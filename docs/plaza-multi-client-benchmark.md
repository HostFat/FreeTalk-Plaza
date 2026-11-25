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
| 20 | 345 KiB | 639 KiB | 3,50 s | 371 KiB | 1,75 s | 2,1 ms |
| 100 | 380 KiB | 674 KiB | 3,53 s | 406 KiB | 1,90 s | 2,0 ms |

| Sezioni | Storage figlie (pruned) | Activity contract | Fan-out activity (50 sub) | Authority sync |
|---:|---:|---:|---:|---:|
| 20 | 7,3 MiB | 83,2 KiB (200 entry) | 4,06 MiB per update | 7,3 MiB |
| 100 | 39,7 MiB | 83,2 KiB (200 entry) | 4,06 MiB per update | 39,7 MiB |

Indice a pagine, 1.000 membri, 2.000 topic, pagine da 200:

| Unità | Dimensione | Verify | Bootstrap nuovo subscriber |
|---|---:|---:|---:|
| Sezione intera | 3.278 KiB | 14,9 s | 3,3 MiB |
| Una pagina | 363 KiB | 1,7 s | 363 KiB |

Un nuovo topic è un delta da 0,7 KiB: con 50 subscriber il fan-out è
0,03 MiB. Il manifest cambia solo quando nasce una pagina.

Membri della board (10 sezioni, nessun topic):

| Membri | Board | Verify |
|---:|---:|---:|
| 1.000 | 341 KiB | 2,1 s |
| 5.000 | 1.681 KiB | 10,1 s |
| 10.000 | 3.356 KiB | 20,4 s |

Con 100 sezioni e 10.000 membri la board resta 3.396 KiB e la verifica 19,8 s:
il costo dipende dai membri, non dalle sezioni.

Prima del pruning le figlie erano 639/674 KiB, lo storage 12,5/65,9 MiB,
il fan-out dell'activity 31,2/32,9 MiB e la sincronizzazione dell'autorita'
12,5/65,9 MiB. Ora una risposta scrive il topic e il contratto activity; la
board e le figlie non ricevono piu' l'activity.

## Cosa dicono i numeri

1. **L'activity e' fuori dalla figlia.** Una risposta scrive il topic e un
   piccolo contratto activity per board (83,2 KiB con 200 entry, 4,06 MiB di
   fan-out con 50 subscriber). La board non riceve piu' l'activity. Il fast
   path del contratto section resta per gli altri delta.
2. **La verifica completa resta il costo di ingresso.** Un nuovo subscriber,
   un `UpdateData::State` o un merge versionato pagano 3,5 s per figlia con
   1.000 membri e 200 topic. E' il costo da ridurre con autorita' compatta e
   indice a pagine.
3. **Un nuovo topic trasmette un delta piccolo.** Il client invia un
   `TopicIndexDelta` da 0,7 KiB; con 50 subscriber il fan-out e' 0,03 MiB.
   Lo stato completo (371-406 KiB) serve a un nuovo subscriber o a un
   resync, non a ogni topic. L'activity non contribuisce a questo traffico.
4. **Il pruning taglia circa il 40% della figlia.** La figlia conserva solo i
   membri che il suo indice referenzia: 371-406 KiB invece di 639-674 KiB,
   con una verifica piena di 1,75-1,90 s invece di 3,5 s. La radice firmata
   elimina le copie nei topic; restano le sezioni copiate in ogni figlia
   (`O(sezioni^2)`) e le definizioni dei ruoli.
5. **Le pagine limitano scrittura e bootstrap.** Con `page_size=200` una nuova
   entry tocca solo la pagina attiva; il bootstrap di un nuovo subscriber
   passa da 3,3 MiB (sezione da 2.000 topic) a 363 KiB (una pagina), con la
   verifica da 14,9 s a 1,7 s. Le pagine duplicano l'autorita' potata, quindi
   lo storage cresce con il numero di pagine.
6. **La propagazione dell'autorita' e' il caso peggiore.** Un cambio di
   ruolo o un ban sincronizza tutte le figlie (39,7 MiB nello scenario da 100
   sezioni dopo il pruning) e poi aggiorna ogni topic. Il limite di 100 topic
   e' stato rimosso. Ogni topic riceve una radice Merkle firmata dall'owner e
   le prove dei suoi membri, non la copia globale di ban/sospensioni; le
   definizioni dei ruoli restano nel topic. Un cambio guidato da un membro
   azzera la radice fino alla firma successiva dell'owner, e i topic usano
   temporaneamente le liste complete. La passata carica ogni topic, quindi il
   costo CPU del client cresce con il numero di topic: aggiornamenti
   incrementali della sola radice sono il passo successivo.
7. **I membri sono il prossimo limite.** La board tiene tutti i membri: a
   10.000 membri pesa 3,3 MiB e la verifica piena supera i 20 s, mentre le
   sezioni restano 3,3 MiB. Un contratto membri con radice firmata toglie
   questa crescita dal percorso caldo.

## Prossimi passi

1. Indice a pagine con manifest (fatto): aggiornamenti limitati alla pagina,
   `page_size` firmato con cap 500, caricamento pigro e budget dello storage
   locale.
2. Contratto membri con radice firmata; la board conserva solo radice e
   versione.
3. Compattare le pagine e l'autorita' duplicata; oggi ogni pagina copia
   l'autorita' potata.
4. Topic a pagine append-only; una risposta scrive una pagina.
5. Compattare le sezioni nelle figlie (`O(sezioni^2)`) e le definizioni dei
   ruoli.
6. Aggiornamenti incrementali della sola radice per i topic, senza caricare
   ogni topic nella passata di propagazione.
7. Subscription lazy con budget/TTL e `Unsubscribe` quando la stdlib lo
   espone.

## Limiti del benchmark

- Nessuna latenza di rete o perdita di pacchetti.
- I subscriber sono un modello: il fan-out reale dipende dal nodo e dalla
  topologia.
- I contenuti sono brevi; titoli e anteprime pieni aumentano lo stato.
- Le firme sono Ed25519 locali; una CPU piu' lenta o firme PQ cambiano i
  tempi assoluti, non il rapporto tra fast path e verifica completa.
