# Suvari — Mevcut Özellik İyileştirme Planı

**Goal:** Suvari'nin var olan özelliklerini daha sağlam, hızlı ve kullanışlı hale getirmek — yeni özellik eklemeden.

**Architecture:** 7 adımda, her biri bir agent/kritik dosyayı hedef alan artımlı iyileştirmeler. Her adım test edilip doğrulanacak.

---

### Task 1: Tool Runner — Output Trimming + Akıllı Parse

**Objective:** Büyük tool çıktılarının AI token limitini patlatmasını önlemek.

**Files:**
- Modify: `suvari/tools/runner.py`

**Yapılacaklar:**
- `run()` metoduna `max_output_len` parametresi ekle (default 50_000 chars)
- Eğer output threshold'u aşarsa: ilk 20K + "... [truncated N chars] ..." + son 10K'yi döndür
- Kritik satırları (vulnerability, CVE, HIGH, CRITICAL içeren) truncation'dan muaf tut (hepsini ekle)
- Output'ta `--severity` gibi flag'lerle parçalı çalıştırma desteği için `run_priority()` ekle — önce high/critical bulgular, sonra düşük seviye

**Doğrulama:**
```bash
cd ~/Desktop/suvari && source .venv/bin/activate
python3 -c "
from suvari.tools.runner import ToolRunner
r = ToolRunner()
out = r.run(['echo', 'A'*100000], 5)
print(f'len={len(out)}')
assert len(out) < 60000, 'truncation failed'
print('OK')
"
```

---

### Task 2: Recon-Scanner Tool Çakışmasını Kaldır

**Objective:** Recon ve Scanner aynı araçları iki kere çalıştırmasın.

**Files:**
- Modify: `suvari/agents/recon.py`
- Modify: `suvari/agents/scanner.py`
- Modify: `suvari/orchestrator.py` (context'te hangi araçların çalıştığını taşı)

**Yapılacaklar:**
- ReconAgent: whatweb + nmap + headers + robots + path check. Bunlar recon'un işi.
- ScannerAgent: NOT whatweb, NOT nmap. Sadece nuclei + nikto + gobuster + ffuf + wafw00f + dalfox gibi vulnerability tarama araçları.
- Orchestrator: `context["recon_done"]` listesine yapılan araçları ekle, ScannerAgent okusun.
- ScannerAgent `run()` içinde `context["recon_done"]` kontrol et, tekrar çalıştırma.

**Doğrulama:**
```bash
cd ~/Desktop/suvari && source .venv/bin/activate
# whatweb recon'da çalışıyor, scanner'da çalışmıyor kontrol
grep -n "whatweb" suvari/agents/scanner.py
# Output: nothing or commented
```

---

### Task 3: ScannerAgent'i Zenginleştir — mevcut araçları artır (yeni özellik yok)

**Objective:** ScannerAgent daha fazla Kali aracı kullansın, çıktıyı parse etsin.

**Files:**
- Modify: `suvari/agents/scanner.py`

**Yapılacaklar:**
- Tool listesine ekle (mevcut araçlar, yeni özellik değil):
  - `wafw00f` — WAF tespiti
  - `httpx` — teknoloji tespiti
  - `dalfox` — XSS taraması
  - `ffuf` — web fuzzing
  - `wpscan` — WordPress taraması
  - `dnsrecon` — DNS sorgulama
- `parse_nuclei_output()`, `parse_nikto_output()` fonksiyonları ekle
  - Bulgu sayısı, severity dağılımı, ilk 10 bulgu özeti
- `_summary` alanına parse edilmiş sonuçları ekle
- `recon_done` kontrolü: recon'da çalışan aracı scanner tekrar çalıştırmasın
- Fast mode: nuclei, nikto, wafw00f
- Normal mode: hepsi

**Doğrulama:**
```bash
cd ~/Desktop/suvari && source .venv/bin/activate
# Test parse fonksiyonları
python3 -c "
from suvari.agents.scanner import parse_nuclei_output
sample = '[critical] [cve-2024-1234] http://test.com [http-vuln]'
summary = parse_nuclei_output(sample)
print(summary)
assert 'critical' in summary.lower()
print('OK')
"
```

**Kalan plan iptal edildi — kullanıcı MCP tarafına odaklanmak istedi.**