# SOC Modul C: Loq Optimizasiyası və Deteksiya Təlimatı
> **Əməliyyat Təlimatı və Komandalararası Texniki Tapşırıq**  
> **Məsul:** Modul C (Modul A — Həsənəli və Modul B — Nilufər üçün)

---

## 1. Mənbə Məlumatları və Həsənəli (Modul A) üçün Tələblər

Deteksiya qaydalarının pozulmaması və maskalama testlərinin düzgün aparılması üçün Həsənəli (Modul A) xammal loqlar generatorunda aşağıdakı sahələrin mövcudluğunu və açıq mətn formatında ötürülməsini təmin etməlidir:

| Mənbə (`Source`) | Həsənəlidən Tələb Olunan Sahələr | Açıq Həssas Data Örnəyi (`Raw`) | Təyinatı və Rolu |
| :--- | :--- | :--- | :--- |
| **`linux_auth`** | `timestamp`, `source_ip`, `username`, `outcome`, `process`, `password_sample` | `password_sample: "Secret123!"` | SSH Brute-Force, Suspicious Admin Login, Password Spraying və Parol Maskalanması testi |
| **`web_access`** | `timestamp`, `source_ip`, `http_method`, `url_path`, `url_query`, `status_code` | `url_query: "token=xyz123secret"` | Repeated Failed Login və URL Token Maskalanması testi |
| **`firewall`** | `timestamp`, `source_ip`, `destination_ip`, `destination_port`, `action` | *N/A (Həssas data yoxdur)* | Port Scanning fəaliyyətinin təhlili |

### Modul A üçün Xüsusi Tələblər:
* **İP Standartlaşdırılması:** Bütün log mənbələrində İP sahəsi istisnasız olaraq `source_ip` adlandırılmalıdır.
* **Açıq Mətn Sirrləri:** Maskalama testinin işlədiyini yoxlamaq üçün xammal loqlarda (`raw`) parollar və tokenlər açıq şəkildə görünməlidir (maskalama Modul B tərəfindən emal mərhələsində tətbiq olunacaq).
* **Anomaliya Ssenariləri və Dataset Tələbi:** Köhnə loglar saxlanılır. Generatora aşağıdakı nümunələr daxil edilməlidir (Positive və negative ssenarilər eyni `source_ip` üzərində olmamalıdır):
  * **SSH Brute-Force:** Eyni `source_ip` və eyni `username` üçün 60 saniyədə $\ge 5$ ədəd `outcome: "failure"`, `process: "sshd"`.
  * **Repeated Failed Login:** Eyni `source_ip`-dən 60 saniyədə $\ge 5$ hadisə: `http_method: "POST"`, `url_path: "/login"`, `status_code: 401`.
  * **Port Scanning:** Eyni `source_ip`-dən 30 saniyədə $\ge 3$ fərqli `destination_port` üzrə `action: "BLOCK"`.
  * **Positive (Password Spraying):** Yeni `source_ip`, 60 saniyədə 5 fərqli `username`, hər birinə 1 `failure` (`process: "sshd"`). Bu, Password Spraying üçündür.
  * **Negative 1:** Başqa `source_ip`, 60 saniyədə yalnız 3 fərqli `username`, hər birinə 1 `failure`. Spraying sayılmasın.
  * **Negative 2:** Üçüncü `source_ip`, eyni `username`-ə 60 saniyədə 5 `failure`. Bu, yalnız SSH brute-force üçündür, spraying deyil.

---

## 2. Bütün 5 Deteksiya Ssenarisi və Kritik Sahələr

Modul C tərəfindən tətbiq olunacaq 5 əsas deteksiya qaydası və onların işləməsi üçün vacib olan kritik sahələr:

| # | Ssenari Adı | Mənbə | Məntiq və Qayda (SIEM Logic) | Deteksiya üçün Vacib Sahələr |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **SSH Brute-Force** | `linux_auth` | Eyni `source_ip` və eyni `username` üzrə 60 saniyədə $\ge 5$ `outcome: "failure"`, `process: "sshd"` | `timestamp`, `source_ip`, `username`, `outcome`, `process` |
| **2** | **Suspicious Admin Login** | `linux_auth` | `process: "sshd"`, `outcome: "success"`, `username` IN (`"root"`, `"demo_admin"`) | `timestamp`, `source_ip`, `username`, `outcome`, `process` |
| **3** | **Repeated Failed Login** | `web_access` | Eyni `source_ip`-dən 60 saniyədə $\ge 5$ hadisə: `http_method: "POST"`, `url_path: "/login"`, `status_code: 401` | `timestamp`, `source_ip`, `http_method`, `url_path`, `status_code` |
| **4** | **Port Scanning** | `firewall` | Eyni `source_ip`-dən 30 saniyədə $\ge 3$ fərqli `destination_port`, `action: "BLOCK"` | `timestamp`, `source_ip`, `destination_port`, `action` |
| **5** | **Password Spraying** | `linux_auth` | Eyni `source_ip`-dən 60 saniyədə $\ge 5$ fərqli `username`; hər `username` üçün ən çox 2 `outcome: "failure"`; ümumi `failure` sayı $\ge 5$; `process: "sshd"` *(Bir `username`-ə 5 `failure` halı spraying sayılmır)* | `timestamp`, `source_ip`, `username`, `outcome`, `process` |

---

## 3. Log Emalı Pipeline-ı üçün Texniki Tapşırıq (Nilufər - Modul B)

Nilufər emal qaydalarını konfiqurasiya edərkən deteksiya keyfiyyətinin qorunması məqsədilə aşağıdakı matrisə riayət etməlidir:

| Sahə Adı (`Field Name`) | Aksiya (`Action`) | Maskalama Qaydası / Təsvir | Kritiklik Məntiqi |
| :--- | :---: | :--- | :--- |
| `source_ip`, `timestamp`, `username`, `outcome`, `process`, `http_method`, `url_path`, `status_code`, `destination_ip`, `destination_port`, `action` | **MUST KEEP** | Dəyişdirilmədən saxlamaq | 1–5 saylı deteksiya qaydalarının işləməsi üçün mütləqdir. Sahə silinərsə deteksiya sıfırlanar. |
| `password_sample` | **MASKING** | Bütün dəyəri `[REDACTED]` ilə əvəzləmək | Sahə silinmir, saxlanılır. Açıq parolların SIEM-ə sızmasının qarşısı alınır. |
| `url_query` | **MASKING** | Yalnız token dəyəri bağlanır: `token=[REDACTED]`, `url_path` və URL strukturu qalır | URL strukturu qorunur, daxilindəki həssas token dəyəri maskalanır. |
| `debug_info`, `message`, `user_agent`, `response_bytes`, `raw_message`, `rule`, `protocol` | **SAFE TO DROP** | Kəsilir / Silinir (`Drop`) | Heç bir deteksiya ssenarisində istifadə olunmur. Təhlükəsiz şəkildə kəsilə bilər. |

### Modul B üçün Xüsusi Qeyd:
1. **Sahə Mühafizəsi:** Deteksiya üçün tələb olunan kritik sahələri silməyin. `password_sample` sahəsi ləğv edilməməli, yalnız dəyəri tam `[REDACTED]` edilməlidir.
2. **Hadisə Filtrasiyası Qadağası:** Həcmi azaltmaq məqsədilə `outcome: "failure"`, `status_code: 401` və `action: "BLOCK"` hadisələri heç bir halda filtrlənib silinməməlidir (`Drop` olunmamalıdır).

---

## 4. Test və Doğrulama Metodologiyası (Validation Workflow)

Modul C tərəfindən xammal loqlar (Həsənəli) və emal olunmuş loqlar (Nilufər) müqayisə edilərək aşağıdakı 2 əsas meyar avtomatik yoxlanılır:

* **0% Deteksiya İtkisi (Zero Loss):** Xammal (`raw`) və emal olunmuş (`processed`) loqlar üzrə tətiklənən ssenari sayları tam bərabər olmalıdır.
* **100% Məxfilik / Maskalama Keyfiyyəti:** Raw loglarda sirlər açıq şəkildə mövcud olmalı, emal olunmuş loglarda isə tam `[REDACTED]` formasına salınmalıdır.

```python
# Validation Logic (test_detection.py)

# 1. Raw data üzərində alert-lər
raw_alerts = run_detection_rules(raw_logs_jsonl)

# 2. Emal olunmuş data üzərində alert-lər
proc_alerts = run_detection_rules(processed_logs_jsonl)

# 3. 0% Deteksiya İtkisi doğrulandı (alert sayları bərabərdir)
assert raw_alerts == proc_alerts

# 4. Raw-da açıq sirlər (parol və token) var
assert has_unmasked_secrets(raw_logs_jsonl) == True

# 5. Emal olunmuşda bütün sirlər maskalanıb
assert has_unmasked_secrets(processed_logs_jsonl) == False
