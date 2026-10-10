+++
title = "FindIT 2023 Final"
date = 2023-06-30
draft = false
categories = ["CTF Writeups"]
tags = ["findit", "forensik", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Forensik (Tersirrat) di FindIT 2023 Final."
+++

Writeup dari tim **CP Enjoyer** untuk FindIT 2023 Final — hanya bagian **Forensik** (Tersirrat).

---

# Forensik

## Tersirrat (194 pts)

{{< admonition quote "Deskripsi" >}}
Findy has an annoying girlfriend. His girlfriend didn't like be to the point and often gave Findy "codes" to him. One day, Findy received messages and pictures from his girlfriend which made him confused because he couldn't figure out the meaning of the messages, moreover the pictures couldn't be opened!. Help Findy find out what his girlfriend means!

**Author:** AODreamer#6160

**Attachments:** `Participant.zip`
{{< /admonition >}}

### Analisis awal

Diberikan file `Participant.zip` yang berisi `chall.png` dan `msg.txt`. File `chall.png` tidak dapat dibuka.

**msg.txt**

```
Halo Findy sayang <3! maaf ya kalau aku ganggu kamu terus, maaf aku suka
KOMEN hidupmu terus. Aku sadar kok aku belum bisa jadi pasangan yang baik
buat kamu. Sebagai permintaan maafku, nih aku belikan CHUNKy bar buat kamu,
semoga kamu suka ya! di dalamnya ada sesuatu yang harus kamu lihat dengan
TELITI :D. Btw, kamu gak lupa kan 2 hari lagi aku ulang tahun? ajak aku
WALKING-WALKING ya! hehehe
```

Karena file PNG tidak dapat dibuka, kami langsung melihat isi heksadesimalnya. Terdapat juga hint `CHUNK` dari `msg.txt`. Kami menggunakan `bless` hex editor.

{{< image src="tersirrat-hex-1.png" caption="Tampilan hex chall.png" >}}
{{< image src="tersirrat-hex-2.png" caption="Tampilan hex chall.png setelah diperbaiki" >}}
{{< image src="tersirrat-hex-iend.png" caption="Terdapat trailing data setelah chunk IEND" >}}

Setelah chunk bermasalah diperbaiki, file PNG dapat dibuka. Terlihat juga terdapat trailing data setelah chunk `IEND`. Hint berikutnya dari `msg.txt` adalah melihat gambar dengan teliti. Karena laptop saya sedikit cacat, saya langsung melihat hal yang dimaksud. Biasanya, langkah ini dapat dilakukan dengan tools LSB atau `stegsolve`.

{{< image-row >}}
{{< image src="tersirrat-chall.png" caption="chall.png berhasil dibuka" height=300 >}}
{{< image src="tersirrat-zoom-740.jpeg" caption="Angka 740 terlihat pada gambar" height=300 >}}
{{< /image-row >}}

### Mengubah tinggi gambar

Kami kemudian berpikir angka `740` ini digunakan untuk apa. Kami mengubah height dari gambar menjadi 740, yang awalnya 720. Jangan lupa mengubah CRC pada akhir chunk.

{{< image-row height=120 >}}
{{< image src="tersirrat-height-before.png" caption="Nilai height awal (720) pada chunk IHDR" >}}
{{< image src="tersirrat-height-after.png" caption="Height diubah menjadi 740 beserta CRC baru" >}}
{{< /image-row >}}

### Mendapatkan bagian flag

Terdapat string base64 yang merupakan bagian ke-2 flag. Bagian pertama flag didapatkan dari comment file, sesuai hint `KOMEN` pada `msg.txt`.

{{< image-row height=300 >}}
{{< image src="tersirrat-flag2.png" caption="Gambar setelah height diubah, muncul string base64" >}}
{{< image src="tersirrat-base64-flag2.png" caption="Decode base64 untuk mendapatkan bagian ke-2 flag" height=30 >}}
{{< /image-row >}}

{{< image src="tersirrat-exiftool-flag1.png" caption="Bagian pertama flag ditemukan pada comment file PNG" height=480 >}}

### Mengekstrak file tersembunyi

Hint berikutnya dari `msg.txt` adalah `WALKING-WALKING`. Ini menandakan penggunaan `binwalk`. Tadi juga sudah ketahuan terdapat trailing data setelah chunk `IEND` PNG.

{{< image src="tersirrat-binwalk.png" caption="binwalk dan foremost menemukan file zip tersembunyi" >}}

Didapatkan file zip yang memerlukan password untuk dibuka. Kita dapat menggunakan `didufindit` yang didapatkan dari gambar sebelumnya.

{{< image src="tersirrat-zip-flag3.png" caption="Bagian ke-3 flag dari dalam file zip" >}}

Sedikit aneh, kita mendapatkan bagian ke-3 flag dengan melakukan ROT13 dari isi `flag3`.

{{< image src="tersirrat-rot13-flag3.png" caption="ROT13 pada isi flag3" height=250 >}}

> Flag: `FindITCTF{1_L0v3_y0u_3K_F1nDy}`
