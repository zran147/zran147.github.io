+++
title = "Cyber Jawara 2022 Quals"
date = 2022-12-04
draft = false
categories = ["CTF Writeups", "Not Translated"]
tags = ["cyber-jawara", "pwn", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Pwn (Minato Aqua) di CTF Cyber Jawara 2022 babak kualifikasi."
+++

Writeup dari tim **CP Enjoyer** untuk CTF Cyber Jawara 2022 babak kualifikasi — hanya bagian **Pwn**. Ini adalah soal Cyber Jawara yang pertama kali aku solve, jadi sedikit spesial untukku.

---

# Pwn

## Minato Aqua (657 pts)

{{< admonition quote "Deskripsi" >}}
**Attachments:** `minato_aqua.zip`
{{< /admonition >}}

### Analisis awal

Diberikan file `minato_aqua.zip` yang berisi file `minato_aqua`, `libc.so.6`, dan `ld-linux-x86-64.so.2`. File `minato_aqua` adalah ELF 64-bit, dynamically linked, dan stripped. Canary tidak aktif, dan PIE tidak aktif.

{{< image src="minato-p10-1.png" caption="File chall dan mitigasi" >}}

Setelah di-decompile, ditemukan fungsi `main` yang memanggil `sub_401196` dan `sub_4011DE`. Fungsi `sub_401196` itu seperti fungsi setup, dan fungsi `sub_4011DE` itu seperti fungsi vuln.

{{< image-row height=115 >}}
{{< image src="minato-p10-2.png" caption="Decompiled fungsi `main`" >}}
{{< image src="minato-p10-3.png" caption="Fungsi `sub_4011DE` (vuln)" >}}
{{< /image-row >}}

Ditemukan juga fungsi yang akan memanggil `system` dengan suatu argumen. Maka, ini adalah ret2win biasa dengan harus memanggil fungsi `sub_4011BF` dengan argumenb `"/bin/sh"`.

{{< image src="minato-p10-4.png" caption="Fungsi `sub_4011BF` (win)" height=80 >}}

### Noob zran mencoba coba hal

Aku dapat ide untuk menaruh `rbp` pada alamat 8 byte setelah suatu string `"/bin/sh"` agar string tersebut dijadikan argumen, namun string tersebut hanya terdapat pada libc.

{{< image src="minato-p11-2.png" caption="Rencana penempatan `rbp`" >}}

Aku gatau ASLR idup atau nggak. Kayanya selalu idup ga sih (maaf bang masi awam). Ya, aku tetap mencobanya. Tetapi karena ini string, argumen yang diberikan kepada `system` adalah pointer ke string tersebut. Berarti `rbp-8` seharusnya pointer ke alamat string tersebut, bukan alamatnya langsung. Jadi aku mencoba membuat payload agar stack menjadi seperti berikut dan sepertinya dapat shell.

{{< image src="minato-p11-3.png" caption="Payload di stack" >}}
{{< image src="minato-p11-4.png" caption="Payload di stack (lanjutan)" >}}

Tapi yaa, karena ASLR hidup, kayanya ga bisa ke libc gitu. Jadi aku coba kaya gini.

{{< image src="minato-p11-5.png" caption="Percobaan payload" >}}
{{< image src="minato-p11-6.png" caption="Percobaan payload (lanjutan)" >}}

Btw, `rbp` harus menunjuk kepada dirinya sendiri karena `system` bakalan dipanggil setelah sebuah perintah `ret`. Tapiiii, aku lupa alamat stack bakalan berubah atau nggak kalo ASLR idup (maaf bang masi awam) jadi aku sebenarnya gatau kaya gini tu bisa atau nggak (masih ga dapat shell, dan gatau salahnya di sini atau di tempat lain).

{{< image src="minato-p12-1.png" caption="Ilustrasi `rbp`" >}}
{{< image src="minato-p12-2.png" caption="Ilustrasi stack" >}}

### Menemukan jalan menuju flag

{{< image src="minato-p11-1.png" caption="Decompiled fungsi vuln" >}}

Anyways, terima kasih sudah membaca ceritaku sampai di sini walaupun cukup tidak berguna. Setelah melihat kembali stack, `rax` berisi awal dari buffer yang diberikan. Dalam kata lain, kita hanya perlu mengisi awal buffer dengan string `"/bin/sh"` dan return ke alamat `0x4011d3` agar string pindah ke `rdi` dan menjadi argumen fungsi `system`. Dan ini aku cukup yakin karena tidak berhubungan dengan libc atau stack hehe.

Omaigat dapat shell, tapi gabisa interactive?? Justru, dia bakalan ngejalanin string pada `rbp` sekarang.

{{< image src="minato-p12-3.png" caption="Berhasil mendapatkan shell" >}}

Omaigat itu flagnya, tapi gabisa di cat karena `cat flag.txt` lebih dari 8 karakter awokawokawkoko. Jadi aku ngestuck. Ntah kenapa, gabisa interactive. Akhirnya, aku coba menambahkan dua gadget `ret` sebelum ke `0x4011d3`, dan bisa interactive yeyy (sebenarnya makek script, tapi biar keren, langsung dari terminal aja la ya).

{{< image src="minato-p13-1.png" caption="Flag" >}}

> Flag: `CJ2022{good_luck_with_the_other_challs!!!!!!}`
