# SOC Module D: Metrics Definition
## Log Optimization Before SIEM

> **Texniki Sənədləşdirmə**  
> **Modul:** Module D — Log Delivery, Reliability & Benchmarking  
> **Sənəd:** Metrics Definition  
> **Məqsəd:** Log optimallaşdırılması və SIEM sisteminə ötürülmə prosesinin effektivliyini ölçmək, qiymətləndirmək və müqayisə etmək.

---

# 1. Introduction (Giriş)

Bu sənəd Log Optimization Before SIEM layihəsi çərçivəsində istifadə ediləcək əsas performans, etibarlılıq, məlumat bütövlüyü və resurs istifadəsi metrikalarını müəyyən edir.

Module D-nin əsas məqsədi optimallaşdırılmış logların SIEM sisteminə ötürülməsi zamanı sistemin effektivliyini ölçmək və optimallaşdırma nəticəsində əldə edilən dəyişiklikləri obyektiv şəkildə qiymətləndirməkdir.

Log optimallaşdırılması yalnız məlumatların həcminin azaldılması ilə məhdudlaşmamalıdır. Proses zamanı logların təhlükəsizlik baxımından əhəmiyyətli məlumatları qorunmalı, ötürülmə sürəti yaxşılaşdırılmalı və sistemin etibarlılığı təmin edilməlidir.

Bu səbəbdən layihədə metrikalar aşağıdakı əsas kateqoriyalar üzrə qruplaşdırılır:

1. Log Optimization Metrics
2. Delivery Performance Metrics
3. Reliability Metrics
4. Resource Utilization Metrics
5. Data Integrity Metrics
6. Detection Preservation Metrics

Hər bir metrika üçün ölçmə məqsədi, hesablama düsturu, ölçü vahidi və nəticələrin interpretasiyası müəyyən edilir.

---

# 2. Log Optimization Metrics (Log optimallaşdırılması metrikaları)

Bu kateqoriya optimallaşdırma prosesinin log məlumatlarının həcminə və strukturuna təsirini qiymətləndirir.

Əsas məqsəd logların ilkin və optimallaşdırılmış vəziyyətlərini müqayisə etməkdir.

## 2.1. Original Log Size

**Təsviri:**

Optimallaşdırma başlamazdan əvvəl ilkin log məlumatlarının ümumi ölçüsünü göstərir.

Bu metrika optimallaşdırma nəticəsində əldə edilən məlumat həcminin azalmasını hesablamaq üçün baza göstəricisi kimi istifadə olunur.

**Formula:**

```text
Original Log Size = Total Size of Raw Log Files
```

**Ölçü vahidi:** Bytes, KB, MB, GB.

**Əhəmiyyəti:**

Optimallaşdırmadan əvvəl məlumat həcmini müəyyən edir və digər optimallaşdırma metrikaları üçün müqayisə bazası yaradır.

## 2.2. Optimized Log Size

**Təsviri:**

Optimallaşdırma prosesindən sonra əldə edilən log məlumatlarının ümumi ölçüsünü göstərir.

**Formula:**

```text
Optimized Log Size = Total Size of Optimized Log Files
```

**Ölçü vahidi:** Bytes, KB, MB, GB.

**Əhəmiyyəti:**

Optimallaşdırma nəticəsində məlumatların həcminin nə qədər dəyişdiyini müəyyən etməyə imkan verir.

## 2.3. Log Size Reduction (%)

**Təsviri:**

İlkin log məlumatlarının optimallaşdırmadan sonra neçə faiz kiçildiyini göstərir.

Bu, layihənin əsas optimallaşdırma göstəricilərindən biridir.

**Formula:**

```text
Log Size Reduction (%) =

((Original Log Size - Optimized Log Size)
 / Original Log Size) * 100
```

**Ölçü vahidi:** Percentage (%).

**Nümunə:**

```text
Original Log Size: 100 MB
Optimized Log Size: 60 MB

Reduction = ((100 - 60) / 100) * 100

Result: 40%
```

**Əhəmiyyəti:**

Log optimallaşdırılması nəticəsində əldə edilən ümumi məlumat həcmi azalmasını ölçür.

## 2.4. Storage Savings

**Təsviri:**

Optimallaşdırma nəticəsində qənaət edilən disk sahəsinin həcmini göstərir.

**Formula:**

```text
Storage Savings = Original Log Size - Optimized Log Size
```

**Ölçü vahidi:** Bytes, KB, MB, GB.

**Əhəmiyyəti:**

SIEM sistemində logların saxlanılması üçün tələb olunan disk sahəsinin azaldılmasını qiymətləndirməyə imkan verir.

**Qeyd:** Bu göstərici yalnız müqayisə olunan məlumatların eyni saxlanma formatında və eyni şərtlərdə ölçüldüyü halda düzgün interpretasiya edilməlidir.

## 2.5. Duplicate Log Reduction (%)

**Təsviri:**

Optimallaşdırma prosesində təkrar logların aradan qaldırılması nəticəsində əldə edilən azalma faizini göstərir.

**Formula:**

```text
Duplicate Reduction (%) =

((Original Duplicate Count - Remaining Duplicate Count)
 / Original Duplicate Count) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Təkrar məlumatların azaldılmasını qiymətləndirir.

**Qeyd:** Təkrar hadisələrin aradan qaldırılması zamanı eyni görünən, lakin fərqli təhlükəsizlik hadisələrini təmsil edən logların səhvən silinməməsi təmin edilməlidir.

---

# 3. Delivery Performance Metrics (Ötürülmə performansı metrikaları)

Bu kateqoriya logların mənbədən SIEM sisteminə ötürülmə sürətini, gecikməsini və uğurluluğunu qiymətləndirir.

## 3.1. Events Per Second (EPS)

**Təsviri:**

EPS müəyyən zaman intervalında emal edilən və ya ötürülən log hadisələrinin sayını göstərir.

Bu metrika sistemin log emalı və ötürülməsi qabiliyyətini qiymətləndirmək üçün istifadə olunur.

**Formula:**

```text
EPS = Total Events Processed / Time in Seconds
```

**Ölçü vahidi:** Events/Second.

**Nümunə:**

```text
Total Events: 120,000
Processing Time: 60 seconds

EPS = 120,000 / 60

Result: 2,000 EPS
```

**Əhəmiyyəti:**

Sistemin müəyyən zaman ərzində nə qədər log hadisəsini emal edə bildiyini göstərir.

**Qeyd:** Incoming EPS, Processing EPS və Delivered EPS ayrı-ayrılıqda ölçülməlidir. Bu göstəricilər arasındakı fərq sistemdə yaranan gecikmə və ya emal darboğazlarını müəyyən etməyə kömək edir.

## 3.2. Throughput

**Təsviri:**

Throughput müəyyən zaman ərzində uğurla ötürülən məlumatların ümumi həcmini göstərir.

EPS-dən fərqli olaraq, bu metrika hadisələrin sayını deyil, ötürülən məlumatların ölçüsünü qiymətləndirir.

**Formula:**

```text
Throughput (MB/s) =

Total Successfully Delivered Data (MB)
 / Time in Seconds
```

**Ölçü vahidi:** MB/s, KB/s, GB/s.

**Nümunə:**

```text
Delivered Data: 600 MB
Time: 60 seconds

Throughput = 600 / 60

Result: 10 MB/s
```

**Əhəmiyyəti:**

Log ötürülməsi zamanı şəbəkə və sistem performansını qiymətləndirməyə imkan verir.

## 3.3. Average Delivery Latency

**Təsviri:**

Log hadisəsinin mənbədə yaradıldığı vaxtdan SIEM sistemində qəbul edildiyi vaxta qədər keçən orta müddəti göstərir.

**Formula:**

```text
Delivery Latency =

SIEM Reception Timestamp - Source Event Timestamp
```

Orta gecikmə:

```text
Average Latency =

Sum of All Delivery Latencies
 / Total Number of Events
```

**Ölçü vahidi:** Milliseconds (ms), Seconds (s).

**Əhəmiyyəti:**

Logların SIEM sisteminə nə qədər tez çatdırıldığını müəyyən edir.

**Qeyd:** Mənbə və təyinat sistemlərinin saatları sinxronlaşdırılmalıdır. Əks halda gecikmə ölçmələri düzgün nəticə verməyə bilər.

## 3.4. P95 Latency (95th Percentile)

**Təsviri:**

P95 Latency bütün log ötürülmələrinin 95%-nin hansı gecikmə müddətində tamamlandığını göstərir.

Bu metrika orta gecikmədən fərqli olaraq yüksək gecikmə yaşayan hadisələri daha yaxşı qiymətləndirməyə imkan verir.

**Nümunə:**

```text
P95 Latency = 250 ms
```

Bu nəticə o deməkdir ki, log ötürülmələrinin 95%-i 250 ms və ya daha az müddətdə tamamlanıb.

**Ölçü vahidi:** Milliseconds (ms).

**Əhəmiyyəti:**

Sistemin yalnız orta performansını deyil, gecikmə baxımından daha zəif nəticələrini də qiymətləndirir.

## 3.5. P99 Latency (99th Percentile)

**Təsviri:**

P99 Latency log ötürülmələrinin 99%-nin tamamlandığı gecikmə həddini göstərir.

Bu metrika xüsusilə yüksək yük və qeyri-sabit şəbəkə şəraitində vacibdir.

**Ölçü vahidi:** Milliseconds (ms).

**Əhəmiyyəti:**

Ən yüksək gecikmə ilə müşahidə olunan ötürülmə hallarını qiymətləndirməyə kömək edir.

## 3.6. Delivery Success Rate

**Təsviri:**

SIEM sisteminə uğurla çatdırılmış logların ümumi göndərilmiş loglara nisbətini göstərir.

**Formula:**

```text
Delivery Success Rate (%) =

(Successfully Delivered Events / Total Events Sent) * 100
```

**Ölçü vahidi:** Percentage (%).

**Nümunə:**

```text
Total Events Sent: 100,000
Successfully Delivered: 99,500

Success Rate = (99,500 / 100,000) * 100

Result: 99.5%
```

**Əhəmiyyəti:**

Log delivery prosesinin uğurluluğunu ölçən əsas göstəricilərdən biridir.

## 3.7. Delivery Failure Rate

**Təsviri:**

Ötürülməsi uğursuz olan log hadisələrinin ümumi göndərilmiş hadisələrə nisbətini göstərir.

**Formula:**

```text
Delivery Failure Rate (%) =

(Failed Delivery Events / Total Events Sent) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Logların SIEM sisteminə çatdırılması zamanı baş verən problemlərin səviyyəsini müəyyən edir.

**Qeyd:** Müvəqqəti uğursuz ötürülmə ilə son nəticədə itirilmiş log hadisələri fərqləndirilməlidir.

---

# 4. Reliability Metrics (Etibarlılıq metrikaları)

Bu kateqoriya sistemin nasazlıqlara davamlılığını, məlumat itkisini və bərpa imkanlarını qiymətləndirir.

## 4.1. Data Loss Rate

**Təsviri:**

Mənbədə yaradılmış, lakin SIEM sisteminə çatdırılmamış log hadisələrinin faizini göstərir.

**Formula:**

```text
Data Loss Rate (%) =

((Total Source Events - Unique Delivered Events)
 / Total Source Events) * 100
```

**Ölçü vahidi:** Percentage (%).

**Nümunə:**

```text
Source Events: 100,000
Unique Delivered Events: 99,900

Data Loss Rate = 0.1%
```

**Əhəmiyyəti:**

Log ötürülməsi zamanı məlumat itkisi riskini qiymətləndirir.

**Vacib:** Hesablama zamanı təkrar ötürülmüş hadisələr ayrıca nəzərə alınmalıdır. Əks halda dublikatlar itkinin hesablanmasını təhrif edə bilər.

## 4.2. Retry Success Rate

**Təsviri:**

İlkin ötürülmə cəhdi uğursuz olduqdan sonra yenidən göndərilən logların neçə faizinin uğurla çatdırıldığını göstərir.

**Formula:**

```text
Retry Success Rate (%) =

(Successful Retry Deliveries / Total Retry Attempts) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Retry mexanizminin effektivliyini qiymətləndirir.

## 4.3. Recovery Time

**Təsviri:**

Sistemdə nasazlıq yarandıqdan sonra normal fəaliyyətin bərpa olunmasına qədər keçən müddəti göstərir.

**Formula:**

```text
Recovery Time =

Time of Service Restoration - Time of Failure
```

**Ölçü vahidi:** Seconds, Minutes.

**Əhəmiyyəti:**

Sistemin nasazlıqlardan sonra nə qədər tez bərpa olunduğunu müəyyən edir.

## 4.4. Mean Time Between Failures (MTBF)

**Təsviri:**

İki ardıcıl sistem nasazlığı arasında keçən orta işləmə müddətini göstərir.

**Formula:**

```text
MTBF = Total Operational Time / Number of Failures
```

**Ölçü vahidi:** Hours.

**Əhəmiyyəti:**

Sistemin uzunmüddətli etibarlılığını qiymətləndirmək üçün istifadə olunur.

## 4.5. Mean Time To Recovery (MTTR)

**Təsviri:**

Sistemin nasazlıqdan sonra bərpa olunmasına sərf edilən orta müddəti göstərir.

**Formula:**

```text
MTTR = Total Recovery Time / Number of Recovery Events
```

**Ölçü vahidi:** Seconds, Minutes.

**Əhəmiyyəti:**

Sistemin nasazlıqlardan sonra nə qədər sürətlə normal fəaliyyətə qayıtdığını qiymətləndirir.

## 4.6. System Availability

**Təsviri:**

Sistemin müəyyən müddət ərzində əlçatan və işlək olduğu zamanın ümumi müşahidə müddətinə nisbətini göstərir.

**Formula:**

```text
Availability (%) =

(Uptime / Total Observation Time) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Log delivery sisteminin fasiləsiz işləmə qabiliyyətini qiymətləndirir.

---

# 5. Resource Utilization Metrics (Resurs istifadəsi metrikaları)

Bu kateqoriya log emalı və ötürülməsi zamanı sistem resurslarının nə dərəcədə istifadə edildiyini ölçür.

## 5.1. CPU Usage

**Təsviri:**

Logların emalı və ötürülməsi zamanı prosessor resurslarından istifadə səviyyəsini göstərir.

**Formula:**

```text
CPU Usage (%) =

(CPU Time Used / Total Available CPU Time) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Yüksək CPU istifadəsi sistemdə performans darboğazlarının mövcudluğunu göstərə bilər.

## 5.2. Memory Usage (RAM)

**Təsviri:**

Log emalı zamanı istifadə olunan operativ yaddaşın həcmini göstərir.

**Formula:**

```text
Memory Usage (%) =

(Used RAM / Total Available RAM) * 100
```

**Ölçü vahidi:** MB, GB, Percentage (%).

**Əhəmiyyəti:**

Sistemin yaddaş istifadəsini və yüksək log həcmlərinin RAM-a təsirini qiymətləndirir.

## 5.3. Disk I/O

**Təsviri:**

Logların saxlanılması, oxunması və yazılması zamanı disk əməliyyatlarının intensivliyini ölçür.

Əsas göstəricilər:

- Disk Read Throughput.
- Disk Write Throughput.
- Read IOPS.
- Write IOPS.
- Disk Utilization.

**Ölçü vahidi:** MB/s, IOPS, Percentage (%).

**Əhəmiyyəti:**

Logların disk üzərində emalı zamanı yaranan performans məhdudiyyətlərini müəyyən etməyə kömək edir.

## 5.4. Network Bandwidth Utilization

**Təsviri:**

Logların ötürülməsi zamanı şəbəkənin ötürmə qabiliyyətindən istifadə səviyyəsini göstərir.

**Formula:**

```text
Bandwidth Utilization (%) =

(Actual Network Throughput / Available Bandwidth) * 100
```

**Ölçü vahidi:** Mbps, Gbps, Percentage (%).

**Əhəmiyyəti:**

Log delivery prosesinin şəbəkə resurslarına təsirini qiymətləndirir.

## 5.5. Buffer Utilization

**Təsviri:**

Logların müvəqqəti saxlanılması üçün ayrılmış buffer yaddaşının nə qədərinin istifadə edildiyini göstərir.

**Formula:**

```text
Buffer Utilization (%) =

(Used Buffer Capacity / Total Buffer Capacity) * 100
```

**Ölçü vahidi:** Percentage (%), MB, GB.

**Əhəmiyyəti:**

SIEM sistemi əlçatmaz olduqda logların müvəqqəti saxlanılması üçün ayrılmış yaddaşın vəziyyətini izləməyə imkan verir.

---

# 6. Data Integrity Metrics (Məlumat bütövlüyü metrikaları)

Log optimallaşdırılması zamanı məlumatların həcmi azaldılsa belə, təhlükəsizlik baxımından vacib məlumatların qorunması təmin edilməlidir.

Bu kateqoriya ilkin və optimallaşdırılmış logların uyğunluğunu qiymətləndirir.

## 6.1. Data Integrity Rate

**Təsviri:**

Müəyyən edilmiş bütövlük yoxlamasından uğurla keçən logların ümumi yoxlanılmış loglara nisbətini göstərir.

**Formula:**

```text
Data Integrity Rate (%) =

(Integrity Validated Events / Total Validated Events) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Log məlumatlarının emal və ötürülmə zamanı pozulub-pozulmadığını qiymətləndirir.

## 6.2. Field Preservation Rate

**Təsviri:**

Optimallaşdırmadan sonra qorunub saxlanılmış vacib log sahələrinin ümumi tələb olunan sahələrə nisbətini göstərir.

**Formula:**

```text
Field Preservation Rate (%) =

(Preserved Required Fields / Total Required Fields) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Optimallaşdırma zamanı təhlükəsizlik təhlili üçün vacib olan sahələrin silinmədiyini və ya dəyişdirilmədiyini yoxlayır.

## 6.3. Duplicate Event Rate

**Təsviri:**

SIEM sisteminə çatdırılmış təkrar hadisələrin ümumi çatdırılmış hadisələrə nisbətini göstərir.

**Formula:**

```text
Duplicate Event Rate (%) =

(Duplicate Delivered Events / Total Delivered Events) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Təkrar logların sistemə təsirini qiymətləndirməyə kömək edir.

**Qeyd:** Eyni məzmunlu iki log mütləq eyni hadisə demək deyil. Dublikatların müəyyən edilməsi üçün uyğun event ID və ya hadisənin unikal identifikasiyasını təmin edən sahələrdən istifadə olunmalıdır.

## 6.4. Hash Verification

**Təsviri:**

Log fayllarının və ya məlumat bloklarının bütövlüyünü yoxlamaq üçün kriptoqrafik hash funksiyalarından istifadə olunur.

Məsələn, SHA-256 vasitəsilə ilkin və sonrakı məlumatların hash dəyərləri müqayisə edilə bilər.

**Nümunə:**

```text
Original Log Hash: SHA256(...)
Optimized Log Hash: SHA256(...)
```

**Əhəmiyyəti:**

Məlumatların dəyişdirilib-dəyişdirilmədiyini müəyyən etməyə kömək edir.

**Vacib qeyd:** Optimallaşdırma logların məzmununu dəyişdirdiyi üçün ilkin və optimallaşdırılmış faylların hash dəyərlərinin eyni olması gözlənilmir. Hash müqayisəsi eyni məlumatın ötürülmədən əvvəl və sonra dəyişmədiyini yoxlamaq üçün istifadə edilməlidir.

---

# 7. Detection Preservation Metrics (Deteksiya imkanlarının qorunması)

Bu kateqoriya layihənin təhlükəsizlik baxımından ən vacib hissələrindən biridir.

Log optimallaşdırılması zamanı məlumatların həcminin azaldılması deteksiya imkanlarının itirilməsinə səbəb olmamalıdır.

Məqsəd optimallaşdırmadan əvvəl və sonra təhlükəsizlik hadisələrinin aşkarlanma keyfiyyətini müqayisə etməkdir.

## 7.1. Detection Coverage

**Təsviri:**

Optimallaşdırılmış loglar vasitəsilə yoxlanıla bilən təhlükəsizlik deteksiya ssenarilərinin ümumi tələb olunan ssenarilərə nisbətini göstərir.

**Formula:**

```text
Detection Coverage (%) =

(Detections Supported After Optimization
 / Total Required Detection Scenarios) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Optimallaşdırmadan sonra sistemin hansı təhlükəsizlik ssenarilərini dəstəklədiyini qiymətləndirir.

## 7.2. Detection Retention Rate

**Təsviri:**

Optimallaşdırmadan sonra qorunub saxlanılmış deteksiya imkanlarının optimallaşdırmadan əvvəl mövcud olan deteksiya imkanlarına nisbətini göstərir.

**Formula:**

```text
Detection Retention Rate (%) =

(Detections Preserved After Optimization
 / Detections Available Before Optimization) * 100
```

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Log optimallaşdırılmasının təhlükəsizlik deteksiyalarına təsirini müəyyən edir.

## 7.3. False Negative Rate (FNR)

**Təsviri:**

Əslində təhlükəli olan, lakin deteksiya sistemi tərəfindən aşkarlanmayan hadisələrin faizini göstərir.

**Formula:**

```text
FNR (%) =

(FN / (TP + FN)) * 100
```

Burada:

- TP — True Positives.
- FN — False Negatives.

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Optimallaşdırılmış logların vacib təhlükəsizlik hadisələrinin aşkarlanmasına mane olub-olmadığını qiymətləndirməyə kömək edir.

## 7.4. False Positive Rate (FPR)

**Təsviri:**

Əslində təhlükəli olmayan hadisələrin səhvən təhlükəli kimi müəyyən edilmə faizini göstərir.

**Formula:**

```text
FPR (%) =

(FP / (FP + TN)) * 100
```

Burada:

- FP — False Positives.
- TN — True Negatives.

**Ölçü vahidi:** Percentage (%).

**Əhəmiyyəti:**

Optimallaşdırmanın deteksiya sistemində yanlış xəbərdarlıqlara təsirini qiymətləndirir.

## 7.5. Detection Accuracy Comparison

**Təsviri:**

Optimallaşdırmadan əvvəl və sonra eyni deteksiya qaydalarının nəticələrini müqayisə edir.

Müqayisə zamanı aşağıdakılar nəzərə alınmalıdır:

- Aşkarlanan təhlükəsizlik hadisələrinin sayı.
- İtirilmiş deteksiya hadisələri.
- False Positive nəticələri.
- False Negative nəticələri.
- Deteksiya qaydalarının işləmə qabiliyyəti.

**Əhəmiyyəti:**

Log optimallaşdırılmasının təhlükəsizlik monitorinqinə mənfi təsir göstərmədiyini yoxlamağa imkan verir.

---

# 8. Benchmark Comparison (Benchmark müqayisəsi)

Bütün metrikalar optimallaşdırmadan əvvəl və sonra eyni test şəraitində ölçülməli və müqayisə edilməlidir.

### 8.1. Raw vs Optimized Comparison

| Metric | Raw Logs | Optimized Logs | Improvement |
|---|---|---|---|
| Total Log Size | To be measured | To be measured | To be calculated |
| EPS | To be measured | To be measured | To be calculated |
| Throughput | To be measured | To be measured | To be calculated |
| Average Latency | To be measured | To be measured | To be calculated |
| P95 Latency | To be measured | To be measured | To be calculated |
| CPU Usage | To be measured | To be measured | To be calculated |
| RAM Usage | To be measured | To be measured | To be calculated |
| Disk I/O | To be measured | To be measured | To be calculated |
| Data Loss Rate | To be measured | To be measured | To be calculated |
| Detection Coverage | To be measured | To be measured | To be calculated |

### 8.2. Performance Improvement (%)

Performans göstəricilərinin dəyişməsini hesablamaq üçün:

```text
Improvement (%) =

((New Value - Old Value) / Old Value) * 100
```

Bu formula daha yüksək nəticənin daha yaxşı olduğu metrikalar üçün istifadə edilir.

Latency, CPU Usage və Data Loss Rate kimi aşağı nəticənin daha yaxşı olduğu metrikalar üçün:

```text
Reduction (%) =

((Old Value - New Value) / Old Value) * 100
```

**Qeyd:** Bütün metrikalar üçün eyni yaxşılaşma formulundan istifadə etmək düzgün deyil. Hər göstəricinin xarakteri nəzərə alınmalıdır.

---

# 9. Measurement Methodology (Ölçmə metodologiyası)

Metrikaların düzgün qiymətləndirilməsi üçün bütün testlər standartlaşdırılmış şəraitdə aparılmalıdır.

### 9.1. Test şərtləri

- Eyni log dataset istifadə edilməlidir.
- Raw və optimized loglar eyni şərtlərdə müqayisə edilməlidir.
- Test müddəti əvvəlcədən müəyyən edilməlidir.
- Sistem resursları test zamanı monitorinq edilməlidir.
- Şəbəkə şəraiti qeydə alınmalıdır.
- Ölçmə nəticələri saxlanılmalıdır.
- Testlər bir neçə dəfə təkrarlanmalıdır.

### 9.2. Timestamp Synchronization

Latency göstəricilərinin düzgün hesablanması üçün log mənbəyi və SIEM sisteminin saatları sinxronlaşdırılmalıdır.

Bunun üçün NTP (Network Time Protocol) istifadə edilə bilər.

### 9.3. Repeated Benchmark Runs

Tək test nəticəsi sistemin real performansını tam əks etdirməyə bilər.

Buna görə benchmark testləri bir neçə dəfə təkrarlanmalı və nəticələrin orta göstəricisi hesablanmalıdır.

### 9.4. Measurement Accuracy

Ölçmələr zamanı aşağıdakılara diqqət yetirilməlidir:

- Test mühitinin sabitliyi.
- Paralel proseslərin təsiri.
- Sistem resurslarının ilkin vəziyyəti.
- Ölçmə intervalı.
- Dataset-in eyniliyi.
- Saat sinxronizasiyası.

---

# 10. Metric Evaluation and Acceptance Criteria (Qiymətləndirmə meyarları)

Hər bir metrika üçün layihənin tələblərinə uyğun qəbul meyarları müəyyən edilməlidir.

Aşağıdakı cədvəl ilkin qiymətləndirmə strukturunu təqdim edir.

| Category | Metric | Desired Direction |
|---|---|---|
| Optimization | Log Size Reduction | Higher is better |
| Optimization | Storage Savings | Higher is better |
| Delivery | EPS | Higher is better |
| Delivery | Throughput | Higher is better |
| Delivery | Average Latency | Lower is better |
| Delivery | P95 Latency | Lower is better |
| Delivery | Delivery Success Rate | Higher is better |
| Reliability | Data Loss Rate | Lower is better |
| Reliability | Recovery Time | Lower is better |
| Reliability | Availability | Higher is better |
| Resources | CPU Usage | Lower, within capacity |
| Resources | RAM Usage | Lower, within capacity |
| Resources | Buffer Utilization | Within safe capacity |
| Integrity | Data Integrity Rate | Higher is better |
| Integrity | Field Preservation Rate | Higher is better |
| Detection | Detection Coverage | Higher is better |
| Detection | False Negative Rate | Lower is better |

**Vacib:** Konkret faizlər və performans limitləri real benchmark nəticələri, layihənin texniki tələbləri və test mühitinin imkanları əsasında müəyyən edilməlidir. Ölçülməmiş nəticələr əvvəlcədən uğur göstəricisi kimi təqdim edilməməlidir.

---

# 11. Metrics Summary (Metrikaların ümumi xülasəsi)

Module D çərçivəsində istifadə ediləcək əsas metrikaların ümumi təsnifatı:

| Category | Key Metrics | Purpose |
|---|---|---|
| Optimization | Original Size, Optimized Size, Size Reduction | Log həcminin azaldılmasını ölçmək |
| Delivery | EPS, Throughput, Latency, P95, Success Rate | Ötürülmə performansını qiymətləndirmək |
| Reliability | Data Loss, Retry Success, MTTR, MTBF, Availability | Sistemin etibarlılığını yoxlamaq |
| Resources | CPU, RAM, Disk I/O, Network, Buffer | Resurs istifadəsini ölçmək |
| Integrity | Integrity Rate, Field Preservation, Duplicate Rate | Məlumat bütövlüyünü qorumaq |
| Detection | Detection Coverage, Detection Retention, FNR, FPR | Təhlükəsizlik deteksiyalarını qorumaq |

---

# 12. Conclusion (Nəticə)

Bu sənəddə müəyyən edilmiş metrikalar Module D-nin performansını, etibarlılığını və log optimallaşdırılmasının təhlükəsizlik monitorinqinə təsirini qiymətləndirmək üçün əsas təşkil edir.

Metrikaların sistemli şəkildə ölçülməsi aşağıdakı imkanları yaradır:

- Log optimallaşdırılmasının effektivliyini müəyyən etmək.
- SIEM sisteminə məlumat ötürülməsinin sürətini qiymətləndirmək.
- Məlumat itkisi və ötürülmə xətalarını aşkar etmək.
- Sistem resurslarından istifadənin optimallaşdırılmasını yoxlamaq.
- Şəbəkə və sistem nasazlıqlarına davamlılığı ölçmək.
- Təhlükəsizlik deteksiyalarının qorunmasını təsdiqləmək.
- Raw və Optimized log nəticələrini obyektiv müqayisə etmək.

**Yekun məqsəd:** Log məlumatlarının həcmini və ötürülmə xərclərini optimallaşdırmaqla yanaşı, SIEM sisteminin effektiv təhlükəsizlik monitorinqi aparmaq üçün tələb etdiyi məlumatların bütövlüyünü, əlçatanlığını və deteksiya imkanlarını qorumaqdır.

---
