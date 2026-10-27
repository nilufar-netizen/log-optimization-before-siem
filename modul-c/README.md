# Modul C: Deteksiya Qaydaları və Məlumatların Maskalanması Təlimatı

## 1. Mənbə Məlumatları və Həsənəli (Modul A) üçün Tələblər

### 1.1. Mənbə Loglarının Strukturu (JSONL)
* **`linux_auth` (`samples/linux_auth/auth.jsonl`):** `timestamp`, `source_type`, `event_type`, `source_ip`, `username`, `outcome`, `process`, `message`, `debug_info`, `password_sample`
* **`web` (`samples/web/web.jsonl`):** `timestamp`, `source_type`, `event_type`, `source_ip`, `http_method`, `url_path`, `url_query`, `status_code`, `user_agent`, `response_bytes`, `debug_info`
* **`firewall` (`samples/firewall/firewall.jsonl`):** `timestamp`, `source_type`, `event_type`, `source_ip`, `destination_ip`, `destination_port`, `protocol`, `action`, `rule`, `raw_message`

### 1.2. Həsənəlidən (Modul A) Tələb Olunan Şərtlər
1. **Sahə Adlarının Standartlaşdırılması:** Bütün log mənbələrində IP ünvanı sahəsi **`source_ip`** kimi adlandırılmalıdır.
2. **Həssas Məlumatların Əlavə Edilməsi:**
   * Emal olunmamış ilkin loglarda (raw logs) parol və tokenlər **AÇIQ MƏTN İLƏ** görünməlidir ki, maskalama qaydasının işlədiyi sübut oluna bilsin.
   * `auth.jsonl` faylında `password_sample` sahəsi (məs: `"Secret123"`), `web.jsonl` faylında isə `url_query` sahəsi (məs: `"token=xyz123secret"`) mütləq olmalıdır.
3. **Anomaliya və Hücum Ssenarilərinin Yaradılması:** Test dataset-ə aşağıdakı hadisələr daxil edilməlidir:
   * **`linux_auth`:** 1 dəqiqə ərzində eyni `source_ip`-dən ən azı 5 ardıcıl `failure` hadisəsi (`process: "sshd"`).
   * **`web`:** 1 dəqiqə ərzində `/login` ünvanına 5-dən çox `401` status kodlu POST sorğusu.
   * **`firewall`:** 30 saniyə ərzində eyni `source_ip`-dən müxtəlif portlara `BLOCK` olunmuş bağlantılar.

---

## 2. Deteksiya Ssenariləri (1–5)

| № | Ssenari Adı | Mənbə | Məntiq və Qayda (SIEM Logic) | Detections üçün Vacib Sahələr (Must Keep) |
|---|---|---|---|---|
| **1** | **SSH Brute-Force Attack** | `linux_auth` | `source_type: "linux_auth" AND process: "sshd" AND outcome: "failure"` <br> *(Group: `source_ip` >= 5 / 1 min)* | `timestamp`, `source_type`, `event_type`, `source_ip`, `username`, `outcome`, `process` |
| **2** | **Suspicious Admin Login** | `linux_auth` | `source_type: "linux_auth" AND outcome: "success" AND username IN ("root", "demo_admin")` | `timestamp`, `source_type`, `event_type`, `source_ip`, `username`, `outcome` |
| **3** | **Web Credential Stuffing** | `web` | `source_type: "web" AND url_path: "/login" AND http_method: "POST" AND status_code: 401` <br> *(Group: `source_ip` >= 5 / 1 min)* | `timestamp`, `source_type`, `event_type`, `source_ip`, `http_method`, `url_path`, `url_query`, `status_code` |
| **4** | **Port Scanning Activity** | `firewall` | `source_type: "firewall" AND action: "BLOCK"` <br> *(Group: `source_ip` üzrə distinct `destination_port` >= 3 / 30 sec)* | `timestamp`, `source_type`, `event_type`, `source_ip`, `destination_port`, `action` |
| **5** | **Critical Port Access Attempt** | `firewall` | `source_type: "firewall" AND action: "BLOCK" AND destination_port IN (22, 3389)` | `timestamp`, `source_type`, `event_type`, `source_ip`, `destination_ip`, `destination_port`, `action` |

---

## 3. Log Emalı Sistemi üçün Texniki Qaydalar (Nilufər — Modul B)

Nilufər emal pipeline-ını konfiqurasiya edərkən aşağıdakı qaydaları tətbiq etməlidir:

### 3.1. Qorunmalı Sahələr (Must Keep)
Deteksiya qaydalarının pozulmaması üçün bu sahələr **heç bir halda silinməməlidir**:
* `timestamp`, `source_type`, `event_type`, `source_ip`, `username`, `outcome`, `process`, `http_method`, `url_path`, `url_query`, `status_code`, `destination_ip`, `destination_port`, `action`.

> **Xüsusi Qeyd (Hadisə Filtrasiyası):** Deteksiya ssenarilərinin pozulmaması üçün `outcome: "failure"`, `status_code: 401` və `action: "BLOCK"` olan hadisələri pipeline-da filtrləyib silmək **qadağandır**.

### 3.2. Maskalanmalı Həssas Məlumatlar (Masking Rules)
Həssas verilənlərin yalnız dəyəri `[REDACTED]` ilə əvəzlənməlidir:
1. **Parollar (`password_sample`):** `(?i)"password_sample"\s*:\s*"[^"]*"` $\rightarrow$ `"password_sample": "[REDACTED]"`
2. **URL Query Tokenləri (`url_query`):** `(?i)(token\|session\|key)=([^&]+)` $\rightarrow$ `${1}=[REDACTED]`

### 3.3. Silinməli Artıq Sahələr (Safe to Drop)
Deteksiya ssenarilərində istifadə olunmayan və təhlükəsiz şəkildə silinə bilən sahələr:
* `linux_auth`: `debug_info`, `message`
* `web`: `debug_info`, `user_agent`, `response_bytes`
* `firewall`: `raw_message`, `rule`, `protocol`

---

## 4. Test və Doğrulama Metodologiyası (Validation Workflow)

Modul C tərəfindən emalın düzgünlüyü aşağıdakı kimi yoxlanılır:

1. **İlkin Data (Test A):** `raw_logs.jsonl` faylı üzərində deteksiya skripti çalışdırılır (parol və tokenlərin açıq yazıldığı təsdiqlənir).
2. **Emal Olunmuş Data (Test B):** `processed_logs.jsonl` faylı üzərində eyni skript təkrar edilir.
3. **Nəticənin Qiymətləndirilməsi:**
   * **0% Deteksiya İtkisi:** Test A və Test B-də yaranan alert-lərin sayı və məzmunu 100% üst-üstə düşməlidir.
   * **100% Maskalama:** `processed_logs.jsonl` faylında bütün `password_sample` və `url_query` tokenləri `[REDACTED]` olmalıdır.
