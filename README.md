# CTF Writeup: Management Wants a Word (Hacker Holidays 2026 - Day 14)

**Kategori:** Digital Forensics
**Zorluk:** Orta
**Platform:** TryHackMe — Hacker Holidays 2026

## Görev Özeti

Bir otel odasında (Room 214) misafirin ("Vera") unuttuğu bir laptop bulunuyor. IT ekibi laptop'ı wipe etmeden önce **KAPE** ile tam bir forensic triage almış. Görevimiz, bu triage verisi içinde dağılmış artifact'leri takip ederek Vera'nın hiç kimseye söylemediği bir şifreyi bulmak ve bu şifrenin açtığı "kapının" arkasındaki flag'i ele geçirmek.

**İpuçları:**
- Bir tarayıcı, senin ona hiç söylemediğin şeyleri hatırlar (Chrome saved passwords)
- Her gizli dosya şifre kırıcı gerektirmez, bazen sadece "iyi bir hafıza" yeterlidir
- Gizemli bir versiyon numarası: `1.26.29`

## Kullanılan Araçlar

- **DB Browser for SQLite** — Chrome'un `Login Data` veritabanını incelemek için
- **Impacket** (`secretsdump.py`, `dpapi.py`) — Windows SAM/DPAPI zincirini çözmek için
- **Python 3** + `pycryptodome` — Chrome'un AES-GCM şifreli parolasını çözmek için
- **cryptsetup** — VeraCrypt konteynerini mount etmek için
- **poppler-utils** (`pdftotext`, `pdfimages`) ve **exiftool** — PDF analiz için

## Adım 1 — Dosya Yapısını Keşfetme

Görev dosyaları bir KAPE triage klasörü olarak geliyor:

```
KAPE/C/Users/vera/
├── AppData/Local/Google/Chrome For Testing/User Data/   (Chrome profili)
├── AppData/Roaming/Microsoft/Protect/<SID>/             (DPAPI masterkey)
├── Documents/backup                                     (100MB, uzantısız — şüpheli)
KAPE/C/Windows/System32/config/
├── SAM, SYSTEM, SECURITY                                (Windows parola hash'leri)
```

`Documents/backup` dosyası tam **100MB** ve hiç uzantısı yok. Kullanıcı adının "Vera" olması ve dosyanın rastgele byte gibi görünmesi, bunun bir **VeraCrypt konteyneri** olabileceğini düşündürüyor.

## Adım 2 — Chrome'da Kayıtlı Şifreyi Bulma

Chrome'un `Default/Login Data` dosyası bir SQLite veritabanı. DB Browser for SQLite ile açılıp `logins` tablosuna bakıldığında:

![DB Browser for SQLite ile Login Data içindeki tablolar](images/01-chrome-login-data-tablosu.png)

| origin_url | username_value | password_value |
|---|---|---|
| `http://bytelotus.thm:8080/login` | `VeraSecretVault` | *(şifreli blob)* |

`password_value` alanının hex'i `76 31 30` (`v10`) ile başlıyor — bu, Chrome'un klasik **Windows DPAPI tabanlı** şifreleme formatı olduğunu gösteriyor (yeni ve çok daha zor olan v20 App-Bound Encryption değil).

> **Not:** Site adresi (`bytelotus.thm:8080`) aslında bir yem (red herring) — canlı bir sunucuya bağlanmaya gerek yoktu. Asıl hedef, bu şifrenin `backup` dosyasını açan parola olmasıydı.

## Adım 3 — Windows Parolasını SAM'den Çıkarma

```bash
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

Çıktıda LSA Secrets kısmında altın değerinde bir satır çıktı:

```
[*] DefaultPassword
(Unknown User):minivera
```

Bu, Windows'un otomatik oturum açma (autologon) için sakladığı **düz metin şifre**. Yani hash kırmaya (hashcat/john) hiç gerek kalmadı — @0xMia'nın "sadece iyi bir hafıza yeterli" ipucu tam da buymuş.

## Adım 4 — DPAPI Master Key'i Çözme

Vera'nın SID'i klasör adından biliniyor: `S-1-5-21-2529683458-431225740-1723070931-1000`

```bash
impacket-dpapi masterkey \
  -file c90719ef-5b98-474e-b934-136d606a702a \
  -sid S-1-5-21-2529683458-431225740-1723070931-1000 \
  -password minivera
```

Çıktı:
```
Decrypted key: 5e5715ec9b6df5a86e97902692a66d28e691f05d5bc1e04d0159cfe960e94c9...
```

## Adım 5 — Chrome AES Anahtarını Çözme

Chrome'un şifreleme anahtarı `Local State` dosyasında (`os_crypt.encrypted_key`), base64 + "DPAPI" prefix'i ile saklanıyor:

```python
import base64
b64 = "RFBBUEkB..."  # Local State içindeki encrypted_key değeri
raw = base64.b64decode(b64)
blob = raw[5:]  # "DPAPI" prefix'ini at
open('encrypted_key.bin', 'wb').write(blob)
```

Sonra masterkey ile çöz:

```bash
impacket-dpapi unprotect -file encrypted_key.bin -key 0x5e5715ec9b6df5a86e97902692a66d28e691f05d5bc1e04d0159cfe960e94c9...
```

Bu bize 32 byte'lık Chrome AES anahtarını verdi.

## Adım 6 — Chrome Parolasını Çözme

`Login Data` içindeki `password_value` blob'u AES-GCM ile şifreli (`v10` formatı: `nonce (12 byte) + ciphertext + tag (16 byte)`):

```python
import sqlite3
from Crypto.Cipher import AES

AES_KEY = bytes.fromhex("206a39a0971327ea9487e4aea9844f5d...")

conn = sqlite3.connect("Login Data")
cursor = conn.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
for origin, username, blob in cursor.fetchall():
    if blob[:3] in (b"v10", b"v11"):
        nonce, ciphertext, tag = blob[3:15], blob[15:-16], blob[-16:]
        cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print(f"{origin} | {username} | {plaintext.decode()}")
```

**Sonuç:**
```
URL: http://bytelotus.thm:8080/
User: VeraSecretVault
Password: Wh4t1sV3raD0inG0nTh1sH0st
```

## Adım 7 — VeraCrypt Konteynerini Açma

`@0xMia`'nın tweet'indeki gizemli **"1.26.29"** versiyon numarası, gerçek bir VeraCrypt sürüm numarasıyla birebir eşleşiyor — kullanıcı adı "Vera" ile birleşince artık şüphe kalmıyordu: `Documents/backup` bir **VeraCrypt konteyneri**.

VeraCrypt kurmaya gerek kalmadan, Kali'de hazır gelen `cryptsetup` ile TrueCrypt/VeraCrypt uyumlu modda açtık:

```bash
sudo cryptsetup open --type tcrypt --veracrypt "backup" mybackup
# Şifre: Wh4t1sV3raD0inG0nTh1sH0st

sudo mkdir -p /mnt/backup_data
sudo mount /dev/mapper/mybackup /mnt/backup_data
```

![cryptsetup ile VeraCrypt konteynerini açma](images/02-veracrypt-mount.png)

Mount başarılı oldu:

```
$RECYCLE.BIN/
secret_financial_documents/
System Volume Information/
```

## Adım 8 — Flag'i Bulma

`secret_financial_documents/` klasöründe iki dosya vardı:
- `transactions_q3.csv`
- `important_invoice_byte_lotus.pdf`

CSV'de dikkat çeken bir satır vardı:
```
2026-07-12,TXN-10531,Internal Adjustment,Image asset correction,0.00,Archived
```

Ama gerçek flag, PDF faturanın içinde, "Description" (açıklama) sütununda **düz metin** olarak duruyordu:

```
NO. | DESCRIPTION                          | QTY | PRICE | TOTAL
1.  | Flag: THM{1t_w4s_V3r4_A11_A1Ong?!}   | 1   | $100  | $100
```

![Faturada flag ortaya çıktı](images/03-flag-pdf.png)

## 🚩 Flag

```
THM{1t_w4s_V3r4_A11_A1Ong?!}
```

## Özet — Saldırı Zinciri

```
KAPE triage dosyaları
   → Chrome Login Data (şifreli parola, v10 formatı)
   → SAM hive → DefaultPassword: minivera (düz metin!)
   → DPAPI masterkey çözümü (minivera parolasıyla)
   → Local State encrypted_key çözümü (masterkey ile)
   → Chrome parolası çözümü: Wh4t1sV3raD0inG0nTh1sH0st
   → VeraCrypt "backup" konteynerini mount et (versiyon ipucu: 1.26.29)
   → secret_financial_documents/important_invoice_byte_lotus.pdf
   → 🚩 THM{1t_w4s_V3r4_A11_A1Ong?!}
```

## Öğrenilen Dersler

1. **Windows autologon şifreleri** (`DefaultPassword` LSA secret) genelde düz metin olarak saklanır ve hash kırmaya gerek bırakmadan doğrudan kullanılabilir.
2. **Chrome şifreleri** Windows'ta DPAPI + kullanıcı parolası zinciriyle korunur; kullanıcı parolası ele geçirilirse tüm kayıtlı şifreler çözülebilir.
3. **Dosya isimlendirme ve boyut kalıpları** (uzantısız, yuvarlak boyut) şifreli konteynerlerin habercisi olabilir.
4. Bazen en zor görünen adım (parola kırma) hiç gerekmez — sistemde zaten düz metin olarak duran bir bilgi işi çözer.
