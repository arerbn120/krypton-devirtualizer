# Krypton Devirtualizer — Notlar

## 2026-07-05 — NecroBit dump hatası bulundu ve düzeltildi

**Semptom:** `NET Reactor Unpack Me.exe` (`C:\Users\root\Desktop\.NET Reactor v7.5.9.1`)
üzerinde Krypton çalıştırıldığında üretilen `Devirtualized.exe`, `Form1..ctor()`
metodunu `nop;nop;nop;ret` (4 instr, boş) olarak bırakıyordu. Aynı hedefin
28 Haziran'da üretilmiş bir kopyası (`Devirtualized1.exe`) ise ctor'u tam ve
doğru (109 instr: TextBox/Button oluşturma, Click binding, Controls.Add)
içeriyordu.

**Kök neden:** `Krypton.Runner/NecrobitDumpRunner.cs` → `DumpHashtableBodies`,
NecroBit'in runtime hashtable'ını static field'ların **deklare edilen tipine**
bakarak arıyordu (`IDictionary.IsAssignableFrom(field.FieldType)`). Gerçek
hashtable `object` tipinde deklare edilmiş bir field'ın runtime değeriydi —
filtre onu atlıyor, alakasız 178-entry bir sabit tablosunu buluyordu (gerçek
tablo 696 entry). Sonuç: 0 method body restore ediliyordu.

İkinci bir eksiklik: `NecrobitDumpRunner.Run` sadece static/module
constructor'ları çalıştırıyordu (`RunClassConstructor`), Form1 gibi instance
constructor'lar hiç invoke edilmiyordu → NecroBit'in JIT-restore hook'u
tetiklenmiyordu.

**Düzeltme (2 değişiklik, aynı dosya):**
1. `DumpHashtableBodies`: `field.FieldType` ön-kontrolü kaldırıldı, doğrudan
   `field.GetValue(null) as IDictionary` ile runtime tipi kontrol ediliyor.
2. `Run`: `LoadAndInitialize` sonrası, hashtable dump'ından önce
   `FormSnapshot.CaptureFromEntryPoint(assembly)` çağrısı eklendi (gerçek
   entry point'i/Main'i çalıştırıp Form1'i normal akışta instantiate ediyor).

**Doğrulama:** Krypton.Runner + Krypton yeniden build edildi, tam pipeline
tekrar çalıştırıldı. Üretilen `Devirtualized.exe`'nin 1342 metodunun tamamı
`Devirtualized1.exe` ile birebir aynı (0 fark). Exe çalıştırıldı: 6+ saniye
kesintisiz, pencere açık ("Form1"/"NET Reactor Unpack Me" başlığı), çökme yok.
Şifre kontrolü (N3T_Reac benzeri) doğrulanmadı — istenmedi, önemli olan
çalışabilirlikti.

**Genel önem:** Bu, sadece bu hedefe özel değil — NecroBit korumalı HERHANGİ
bir hedefte aynı şekilde 0 method restore edilmesine yol açan genel bir araç
hatasıydı. Bkz memory `krypton-necrobit-dump-fix`.
