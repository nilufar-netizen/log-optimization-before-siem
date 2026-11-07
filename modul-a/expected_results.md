# expected_results.md - Ssenarilər və gözlənilən detection nəticələri

Ssenari event-ləri **eyni source_ip və vaxtlarla** həm `small/`, həm `large/` dataset-ində yerləşir (başlanğıc: `2026-11-07T10:00:00Z`). Hər ssenari üçün ayrıca `source_ip` istifadə olunur; positive və negative ssenarilər heç vaxt eyni IP-ni paylaşmır.

## 1. Ssenari cədvəli

| ID | Ssenari | Növ | Mənbə | source_ip | Vaxt (UTC) | Event | Təsvir | Gözlənilən nəticə |
| --- | --- | --- | --- | --- | --- | ---: | --- | --- |
| A1 | SSH Brute-Force | positive | linux_auth | `192.0.2.10` | 2026-11-07T10:00:00Z - 10:00:40Z | 6 | username=admin üçün 6 failure, 8 san aralıqla (40 san) | SSH Brute-Force aşkarlanmalıdır |
| A2 | Suspicious Admin Login | positive | linux_auth | `192.0.2.11` | 2026-11-07T10:02:00Z - 10:02:10Z | 2 | root və demo_admin ilə success login (sshd) | Suspicious Admin Login aşkarlanmalıdır (2 event) |
| A3 | Password Spraying - positive | positive | linux_auth | `192.0.2.12` | 2026-11-07T10:04:00Z - 10:04:40Z | 5 | 5 fərqli username, hər biri üçün 1 failure, 10 san aralıqla (40 san) | Password Spraying aşkarlanmalıdır; Brute-Force aşkarlanmamalıdır |
| A4 | Password Spraying - negative 1 | negative | linux_auth | `192.0.2.13` | 2026-11-07T10:06:00Z - 10:06:30Z | 3 | yalnız 3 fərqli username, hər biri üçün 1 failure (30 san) | Heç bir detection işləməməlidir (Spraying eşiyi 5-dir) |
| A5 | Password Spraying - negative 2 (Brute-Force) | negative | linux_auth | `192.0.2.14` | 2026-11-07T10:08:00Z - 10:08:40Z | 5 | eyni username (svc_backup) üçün 5 failure (40 san) | Brute-Force aşkarlanmalıdır, Password Spraying aşkarlanmamalıdır |
| W1 | Repeated Failed Login | positive | web_access | `192.0.2.20` | 2026-11-07T10:10:00Z - 10:10:40Z | 6 | 6 x POST /login, status_code=401, 8 san aralıqla (40 san) | Repeated Failed Login aşkarlanmalıdır |
| W2 | Repeated Failed Login - negative (az saylı) | negative | web_access | `192.0.2.21` | 2026-11-07T10:12:00Z - 10:12:40Z | 3 | yalnız 3 x POST /login 401 (40 san) - əlavə negative | Aşkarlanmamalıdır (eşik 5) |
| W3 | Repeated Failed Login - negative (status 200) | negative | web_access | `192.0.2.22` | 2026-11-07T10:14:00Z - 10:14:40Z | 5 | 5 x POST /login, lakin status_code=200 - əlavə negative | Aşkarlanmamalıdır (status_code != 401) |
| F1 | Port Scanning | positive | firewall | `192.0.2.30` | 2026-11-07T10:16:00Z - 10:16:20Z | 6 | 6 fərqli destination_port, action=BLOCK, 4 san aralıqla (20 san) | Port Scanning aşkarlanmalıdır |
| F2 | Port Scanning - negative (yavaş) | negative | firewall | `192.0.2.31` | 2026-11-07T10:18:00Z - 10:19:20Z | 3 | 3 fərqli port BLOCK, lakin 40 san aralıqla (heç bir 30 san pəncərəsində 3 port yoxdur) - əlavə negative | Aşkarlanmamalıdır |
| F3 | Port Scanning - negative (ALLOW) | negative | firewall | `192.0.2.32` | 2026-11-07T10:20:00Z - 10:20:20Z | 5 | 5 fərqli port, lakin action=ALLOW - əlavə negative | Aşkarlanmamalıdır (action != BLOCK) |

> A1-A5 tapşırığın məcburi ssenarilərinə, W1 və F1 məcburi web/firewall ssenarilərinə uyğundur. W2, W3, F2, F3 əlavə negative ssenarilərdir (qaydaların yalnız eşiyə deyil, status_code/action/zaman şərtlərinə də baxdığını yoxlamaq üçün).

## 2. Detection qaydaları

| Qayda | Şərt |
| --- | --- |
| `ssh_bruteforce` | Eyni source_ip + eyni username, process=sshd, outcome=failure: 60 san ərzində >= 5 |
| `suspicious_admin_login` | username in (root, demo_admin), process=sshd, outcome=success |
| `password_spraying` | Eyni source_ip, process=sshd, outcome=failure: 60 san ərzində >= 5 FƏRQLİ username |
| `web_repeated_failed_login` | Eyni source_ip, POST /login, status_code=401: 60 san ərzində >= 5 |
| `port_scan` | Eyni source_ip, action=BLOCK: 30 san ərzində >= 3 FƏRQLİ destination_port |

## 3. Qayda üzrə gözlənilən aşkarlanma

| Qayda | Aşkarlanmalı IP-lər | Aşkarlanmamalı IP-lər (negative) |
| --- | --- | --- |
| `ssh_bruteforce` | `192.0.2.10`, `192.0.2.14` | `192.0.2.11`, `192.0.2.12`, `192.0.2.13` |
| `suspicious_admin_login` | `192.0.2.11` | - |
| `password_spraying` | `192.0.2.12` | `192.0.2.10`, `192.0.2.11`, `192.0.2.13`, `192.0.2.14` |
| `web_repeated_failed_login` | `192.0.2.20` | `192.0.2.21`, `192.0.2.22` |
| `port_scan` | `192.0.2.30` | `192.0.2.31`, `192.0.2.32` |

Fon (noise) trafiki yalnız `198.51.100.0/24` və `203.0.113.0/24` aralıqlarından gəlir (eyni IP eyni mənbədə ən azı 20 san fasilə ilə görünür), ona görə yuxarıdakı qaydalar fon trafikində **heç bir** alert yaratmamalıdır. Beləliklə, hər qayda üçün alert verən IP-lər yalnız 3-cü cədvəldəki IP-lərdir (`generate_logs.py --verify` bunu yoxlayır).

## 4. Maskalama (Modul B) üçün gözlənilənlər

| Mənbə | Field | Raw logda (açıq) | Cribl-dən sonra |
| --- | --- | --- | --- |
| linux_auth | `password_sample` | `Secret123!` (bütün event-lərdə) | maskalanmış olmalıdır |
| web_access | `url_query` | `token=xyz123secret` (W1-W3 və fon event-lərinin bir hissəsində; bəzilərində `token=xyz123secret&session=test123`) | `token` dəyəri maskalanmış olmalıdır |

Maskalamadan sonra da yuxarıdakı detection nəticələri dəyişməməlidir (detection itkisi = 0).

## 5. Bu faylı yoxlama

```bash
python generate_logs.py --verify small
python generate_logs.py --verify large
```
