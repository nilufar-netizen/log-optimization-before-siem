# Modul C — raw log yoxlaması

Mənbə: `linux_auth.jsonl`, `web_access.jsonl`, `firewall.jsonl`  
Tarix: 2026-10-29  
Bu, emaldan əvvəlki nəticədir. Processed log hələ yoxdur.

## Ssenarilər

| # | Ssenari | Qayda | Raw nəticə |
|---|---|---|---|
| 1 | SSH brute-force | eyni `source_ip`, 1 dəqiqədə >= 5 `outcome: "failure"`, `process: "sshd"` | 4 IP |
| 2 | Suspicious admin login | `outcome: "success"` və `username` `root` və ya `demo_admin` | 168011 hadisə |
| 3 | Web credential stuffing | `POST /login`, 1 dəqiqədə >= 5 `status_code: 401` | 4 IP, 1440977 hadisə |
| 4 | Port scanning | eyni `source_ip`, 30 saniyədə >= 3 fərqli `destination_port`, `action: "BLOCK"` | 4 IP |
| 5 | Critical port access | `action: "BLOCK"` və `destination_port` 22 və ya 3389 | 22: 267572, 3389: 267762 |

## Maskalama üçün raw vəziyyət

- `linux_auth.jsonl`: `password_sample` açıqdır, dəyər `Secret123!`
- `web_access.jsonl`: `url_query` açıqdır, dəyər `token=xyz123secret`
- `firewall.jsonl`: həssas dəyər yoxdur

Jsonl faylları repoya əlavə olunmur. Hər biri təxminən 360 MB-dir.
