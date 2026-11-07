# baseline.md - Raw log dataset ölçmələri

Bu fayl `generate_logs.py` tərəfindən avtomatik yaradılıb. Dəyərlər yaradılmış JSONL fayllarından ölçülüb.

## Metodologiya

- **Event sayı** - fayldakı sətir sayı (1 sətir = 1 event).
- **Fayl ölçüsü** - diskdəki JSONL faylının baytla ölçüsü.
- **Ölçmə müddəti** - datasetdəki ən son və ən erkən `timestamp` arasındakı fərq (log pəncərəsi).
- **EPS** = event sayı / ölçmə müddəti (saniyə).
- **GB/day** = fayl ölçüsü / ölçmə müddəti x 86 400 san / 10^9 (1 GB = 10^9 bayt).
- **Generasiya vaxtı** - generatorun həmin faylı yaratma müddəti (divar saatı).

## small dataset

| Mənbə | Event sayı | Fayl ölçüsü | Ölçmə müddəti (log pəncərəsi) | EPS | GB/day (ekstrapolyasiya) | Generasiya vaxtı |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| linux_auth | 35 | 9.2 KB | 00:33:34 (2,014 san) | 0.017 | 0.0004 | 0.00 san |
| web_access | 30 | 8.7 KB | 00:37:24 (2,244 san) | 0.013 | 0.0003 | 0.00 san |
| firewall | 28 | 7.8 KB | 00:33:28 (2,008 san) | 0.014 | 0.0003 | 0.00 san |
| **Cəmi** | **93** | **25.6 KB** | 00:37:24 (2,244 san) | **0.041** | **0.0010** | 0.00 san |

> Qeyd: small dataset qısa pəncərədə (~40 dəq) çoxlu ssenari ehtiva edir, ona görə EPS və GB/day burada yalnız formal göstəricidir; real həcm planlaması üçün **large** dataset-i istifadə edin.

## large dataset

| Mənbə | Event sayı | Fayl ölçüsü | Ölçmə müddəti (log pəncərəsi) | EPS | GB/day (ekstrapolyasiya) | Generasiya vaxtı |
| --- | ---: | ---: | --- | ---: | ---: | ---: |
| linux_auth | 30,021 | 7.64 MB | 23:59:57 (86,397 san) | 0.347 | 0.0080 | 0.31 san |
| web_access | 50,014 | 15.05 MB | 23:59:53 (86,393 san) | 0.579 | 0.0158 | 0.60 san |
| firewall | 50,014 | 13.33 MB | 23:59:58 (86,398 san) | 0.579 | 0.0140 | 0.45 san |
| **Cəmi** | **130,049** | **36.02 MB** | 23:59:58 (86,398 san) | **1.505** | **0.0378** | 1.36 san |

## Həcm proqnozu (large dataset-in orta event ölçüsü əsasında)

| Mənbə | Orta event ölçüsü (bayt) | 10 EPS -> GB/day | 100 EPS -> GB/day | 1 000 EPS -> GB/day |
| --- | ---: | ---: | ---: | ---: |
| linux_auth | 266.9 | 0.231 | 2.306 | 23.058 |
| web_access | 315.5 | 0.273 | 2.726 | 27.259 |
| firewall | 279.5 | 0.241 | 2.415 | 24.149 |

Cədvəl hər mənbənin ayrıca həmin EPS-də işlədiyi fərziyyəsi ilə hesablanıb.
