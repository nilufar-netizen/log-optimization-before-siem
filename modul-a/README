# Modul A — Log Generatoru

**Məsul:** Həsənəli | **İnteqrasiya:** Modul B — Nilufər

`generate_logs.py` Linux authentication, web access və firewall mənbələri üçün **sintetik** raw loglar yaradır. Loglar Cribl Stream-də qəbul, emal, detection və maskalama testləri üçün nəzərdə tutulub.

## Quraşdırma

Yalnız **Python 3.8+** lazımdır. Əlavə paket quraşdırılmır.

```bash
python3 --version
```

## İşə salma

```bash
# 1) Hər iki dataset (small + large) + expected_results.md + baseline.md
python3 generate_logs.py --out .

# 2) Yalnız kiçik test dataset (Modul B-yə ilk təhvil: 20–50 event/mənbə + bütün ssenarilər)
python3 generate_logs.py --profile small --out .

# 3) Böyük dataset-in həcmini dəyişmək
python3 generate_logs.py --profile large --linux-events 100000 --web-events 200000 --firewall-events 200000 --out .

# 4) Mövcud (köhnə) böyük dataset-ə yalnız yeni ssenari event-lərini əlavə etmək
python3 generate_logs.py --append-to /yol/köhnə_dataset

# 5) Format və detection yoxlaması
python3 generate_logs.py --verify small
python3 generate_logs.py --verify large

# 6) İstənilən qovluq üçün baseline cədvəli (event sayı, ölçü, EPS, GB/day)
python3 generate_logs.py --measure large
```

Parametrlər: `--seed` (default 42; eyni seed = eyni dataset), `--scenario-time` (default `2026-11-07T10:00:00Z`).

## Nəticə strukturu

```
.
├── generate_logs.py
├── README.md
├── expected_results.md     # ssenari, source_ip, gözlənilən detection
├── baseline.md             # event sayı, ölçü, ölçmə müddəti, EPS, GB/day
├── small/                  # Modul B üçün ilk test dataset (~93 event)
│   ├── linux_auth.jsonl
│   ├── web_access.jsonl
│   └── firewall.jsonl
└── large/                  # böyük dataset (default ~130 000 event)
    ├── linux_auth.jsonl
    ├── web_access.jsonl
    └── firewall.jsonl
```

## Format

- JSON Lines: hər sətir = 1 müstəqil JSON obyekt (array yoxdur).
- `timestamp`: ISO 8601 UTC, məs. `2026-11-07T10:00:00Z`.
- `source_type` dəqiq olaraq `linux_auth`, `web_access` və ya `firewall`; bütün IP sahələri `source_ip` adlanır.
- Məcburi field-lər hər event-də var; dəyər yoxdursa `null` (məs. web `url_query`).
- Raw loglarda maskalanmamış sintetik dəyərlər: `password_sample = "Secret123!"`, `url_query = "token=xyz123secret"`.

## Ssenarilər

Hər ssenari ayrıca `source_ip` (192.0.2.0/24) ilə hər iki dataset-də eyni vaxtlarda yerləşir. Detalları `expected_results.md`-dədir:

| Ssenari | source_ip |
| --- | --- |
| SSH Brute-Force | 192.0.2.10 |
| Suspicious Admin Login | 192.0.2.11 |
| Password Spraying — positive | 192.0.2.12 |
| Password Spraying — negative 1 (3 username) | 192.0.2.13 |
| Password Spraying — negative 2 (eyni username x5 → Brute-Force) | 192.0.2.14 |
| Repeated Failed Login (POST /login 401 x6) | 192.0.2.20 |
| Port Scanning | 192.0.2.30 |

Əlavə negative-lər: 192.0.2.21, .22 (web), 192.0.2.31, .32 (firewall).

Fon (noise) trafiki `198.51.100.0/24` və `203.0.113.0/24` aralığından gəlir və qaydalar üzrə heç bir alert yaratmır (generator özü `--verify` ilə bunu yoxlayır).

## Mövcud dataset ilə iş (tapşırıq bölmə 5)

Əvvəlki böyük dataset-lər dəyişdirilmir. `--append-to` yalnız ssenari event-lərini fayl sonuna əlavə edir; təkrar işə salma dublikat yaratmır. Əlavə edilmiş dataset üçün `--verify` yumşaq rejimdə işləyir: gözlənilən IP-lər aşkarlanmalı, negative IP-lər aşkarlanmamalıdır; köhnə datasetdəki digər IP-lər yalnız məlumat kimi göstərilir.

## Modul B ilə inteqrasiya ardıcıllığı

1. `small/` fayllarını Nilufər-ə təqdim et (20–50 event/mənbə + bütün positive/negative ssenarilər).
2. Nilufər faylları Cribl Stream-ə daxil edib parsing və field-ləri yoxlayır.
3. Qəbul və emal qaydaları işlədikdən sonra `large/` təqdim olunur.
4. Raw və processed loglar müqayisə olunur: detection itkisi və maskalama nəticələri yoxlanılır.

## Təhlükəsizlik qeydi

Dataset yalnız sintetik/lab məlumatlarından ibarətdir (RFC 5737 sənəd IP aralıqları). Real parol, token və ya real IP istifadə olunmur.
