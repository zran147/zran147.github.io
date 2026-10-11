+++
title = "Slashroot 7.0"
date = 2023-10-01
draft = false
categories = ["CTF Writeups"]
tags = ["slashroot", "forensik", "misc", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Forensik (Bad Radio, Zebra Cross) dan Misc (SangChall) di Slashroot 7.0."
+++

Writeup dari tim **CP Enjoyer** untuk Slashroot 7.0 — hanya bagian **Forensik** (Bad Radio, Zebra Cross) dan **Misc** (SangChall).

---

# Forensik

## Bad Radio (499 pts)

{{< admonition quote "Deskripsi" >}}
I was recording a radio station the other day and suddenly the frequency gets hijacked with some kind of weird signal?? This is the audio file, hopefully you can extract something out of it.

**Author:** sqirradotdev

**Attachments:** `09-06-2023_...`
{{< /admonition >}}

### Analisis awal

Diberikan suatu file wav yang berisi rekaman seseorang berbicara selayaknya pada radio. Namun, setelah orang tersebut selesai berbicara, terdapat suara seperti kode morse yang dilanjutkan dengan suara seperti sinyal yang tidak berarti. Pertama, kami menuliskan ulang kode morse dalam bentuk titik dan garis agar bisa di-decode. Kemudian kami menggunakan tools online untuk men-decode-nya. Didapatkan teks `ROBOT36ANDROID`.

{{< image src="bad-radio-morse.png" caption="Hasil decode kode morse: ROBOT36ANDROID" >}}

`Robot36` adalah aplikasi pada Play Store yang berfungsi untuk mengubah sinyal suara menjadi gambar atau disebut SSTV image decoder. Setelah men-download aplikasi Robot36 pada Play Store dan menjalankan file wav berkali-kali, kami mendapatkan gambar yang jauh dari kata jelas. Maka, kami mencari tools SSTV image decoder yang lain dan menemukan https://www.qsl.net/on6mu/rxsstv.htm. Setelah meng-input-kan file wav beberapa kali, didapatkan beberapa gambar di bawah.

{{< image-row height=250 >}}
{{< image src="bad-radio-sstv-1.png" caption="Hasil SSTV image decoder (1)" >}}
{{< image src="bad-radio-sstv-2.png" caption="Hasil SSTV image decoder (2)" >}}
{{< /image-row >}}

Walaupun gambar di atas kurang jelas, `https` terbaca jelas sehingga kami mengetahui ini merupakan suatu link. Bagian terakhir terbaca `.org/bad-radio`. Namun, bagian tengah sedikit kurang jelas. Setelah mencoba beberapa kemungkinan, kami menemukan sesuatu yang menarik pada https://rentry.org/bad-radio.

{{< image src="bad-radio-sstv-3.png" caption="Gambar pada https://rentry.org/bad-radio" height=500 >}}
{{< image src="bad-radio-rentry.png" caption="Menekan export raw pada https://rentry.org/bad-radio" >}}

### Menganalisis file gambar

Terdapat suatu gambar. Kami mencoba untuk men-download-nya sebagai raw dan menemukan link drive ke gambar asli. Setelah men-download gambar tersebut yang merupakan suatu png, kami melakukan langkah pengecekan biasa pada png dan mendapatkan link rickroll pada metadata file. Selain itu, tidak terdapat apapun yang menarik, dan kami pun mencoba upload gambar tersebut ke https://aperisolve.com dan didapatkan suatu qr code pada bagian Blue.

{{< image src="bad-radio-aperisolve.png" caption="QR code ditemukan pada bagian Blue di aperisolve" >}}

{{< image src="bad-radio-qr.png" caption="Link drive dari QR code" height=220 >}}

Didapatkan file yang berisi file flag tanpa ekstensi. File tersebut rupanya merupakan file zst. Dan untuk mendekompresinya, kami menambahkan ekstensi `.zst` pada file flag dan menggunakan command `zstd`.

{{< image src="bad-radio-zstd.png" caption="Ekstraksi file flag dengan zstd" height=60 >}}

### Mengekstrak pesan tersembunyi pada video

Didapatkan suatu file flag yang merupakan file video `.webm`. Video tersebut berisi suatu lagu anime tetapi terdapat 8 kotak hitam putih pada pojok kiri atas video yang terus berubah-ubah. Kami pun mencoba membaca kotak hitam sebagai 0 dan putih sebagai 1 dan menggabungkan seluruhnya menjadi suatu string panjang. Maka, kami perlu melakukan ekstraksi setiap frame, dan kami menggunakan tools https://mconverter.eu/convert/webm/png/. Didapatkan zip berisi 6574 file png yang merupakan setiap frame dari video `.webm` tadi. Kemudian, kami membuat script berikut untuk membaca dan menggabungkan seluruh kotak hitam putih yang berada pada pojok kiri atas setiap frame.

**solver.py**

```python
from PIL import Image
from base64 import b64decode
string = ''
for i in range(2, 6575, 2):
    image = Image.open(f'{i}.png'.rjust(9, '0'))
    for j in range(8):
        string += str(image.getpixel((j*32, 0))[0]//255)
open('binary2.txt', 'w').write(string)
b64 = []
for i in range(0, len(string), 8):
    b64.append(int(string[i:i+8], 2))
b64 = bytes(b64)
print(b64)
```

{{< image src="bad-radio-layered.png" caption="String panjang hasil penggabungan kotak tiap frame" >}}

### Mendapatkan flag

Terlihat format flag adalah `slashroot7{1_2_3_4_5_6_7_8}`. Terlihat juga, terdapat seperti string base64 panjang dengan beberapa string base64 pendek yang berada di dalam kurung. Kami pun mencoba men-decode string-string base64 yang di dalam kurung seperti berikut dan mendapatkan flag.

**solver.py**

```python
from PIL import Image
from base64 import b64decode
string = ''
for i in range(2, 6575, 2):
    image = Image.open(f'{i}.png'.rjust(9, '0'))
    for j in range(8):
        string += str(image.getpixel((j*32, 0))[0]//255)
open('binary2.txt', 'w').write(string)
b64 = []
for i in range(0, len(string), 8):
    b64.append(int(string[i:i+8], 2))
b64 = bytes(b64)
# print(b64)
strings = [b'MTpSNGRpMA==', b'MjpoNHM=', b'MzpiMzNu',
b'NDpUMHVob1U=', b'NTpoMUpBY2szRA==', b'Njp3', b'Nzo0cFBQbDM=',
b'ODpaME1H']
for s in strings:
    print(b64decode(s))
```

{{< image src="bad-radio-base64.png" caption="Hasil decode string base64" height=160 >}}

> Flag: `slashroot7{R4di0_h4s_b33n_T0uhoU_h1JAck3D_w_4pPPl3_Z0MG}`

## Zebra Cross (409 pts)

{{< admonition quote "Deskripsi" >}}
Ini mirip QR code tapi panjang kaya zebra cross, jadi cara caranya gimana yaah?

**Author:** bukan_littlekrisna

**Attachments:** `chall.zip`
{{< /admonition >}}

### Analisis awal

Diberikan file `chall.zip` yang berisi file `......` yang merupakan file audio dan file `qr?.png`. Jujur aja, kami tidak menyadari ada file `......` karena file tersebut berawal dengan titik sehingga merupakan file yang tersembunyi. Jadi, kami hanya menganalisis file png. Setelah menganalisis file png, dan dengan judul soal yang mengindikasikan zebra cross yang berbentuk persegi-persegi panjang, kami menyimpulkan gambar tersebut telah dibagi-bagi menjadi persegi panjang yang memanjang secara horizontal dan digabungkan tanpa urutan tertentu secara horizontal juga. Gambar tersebut terlihat seperti suatu gambar QR code sehingga kami mencoba cari ukuran satu kotak pada QR code tersebut. Kami dapatkan ukuran satu kotaknya adalah 45x45 pixel. Setelah itu, terlihat ada pola yang sering muncul pada bagian kanan bawah QR code, setelah 25 kotak dari kiri gambar. Panjang gambar adalah 11745 pixel dan kami mencari angka dekat 25 yang akan habis membagi 11745. Kami mendapatkan angka 29 sebagai panjang 1 bagian sehingga terdapat 9 bagian. Kemudian, kami membuat script untuk memisahkan setiap bagian menjadi file sendiri agar dapat disusun ulang. Setelah itu, kami membuka semua file nya sekaligus untuk coba disusun. Setelah mendapatkan susunan yang pas, kami melanjutkan script tadi untuk menyatukan semua bagiannya.

### Eksekusi mendapatkan flag

**solver.py**

```python
from PIL import Image

image = Image.open('qr?.png')
print(image.size)

new = []
for i in range(9):
    new.append(Image.new('1', (45*29, 145)))

for i in range(image.size[0]):
    for j in range(image.size[1]):
        new[i//(45*29)].putpixel((i%(45*29), j), image.getpixel((i, j))[0]//255)

for i in range(9):
    new[i].save(f'{i+1}.png')

urutan = '492576183'
gabung = Image.new('1', (45*29, 145*9))
for i in range(9):
    for j in range(45*29):
        for k in range(145):
            gabung.putpixel((j, k+i*145), new[int(urutan[i])-1].getpixel((j,k)))
gabung.save('flag.png')
```

{{< image-row >}}
{{< image src="zebra-cross-flag.png" caption="QR code berhasil disusun ulang (flag.png)" height=250 >}}
{{< image src="zebra-cross-scan.png" caption="Hasil scan QR code menampilkan flag" height=300 >}}
{{< /image-row >}}

> Flag: `slashroot7{jUst_pL4y1N6_WiTh_QqRr_c0D33}`

---

# Misc

## SangChall (409 pts)

{{< admonition quote "Deskripsi" >}}
Abijail comeback from Ssangmun-dong

**Author:** Anehinnn

`nc 103.152.242.228 30201`
{{< /admonition >}}

### Analisis awal

Diberikan suatu servis `nc` di mana kita diminta untuk meng-input-kan command.

{{< image src="sangchall-nc.png" caption="Banner servis chall SangChall" >}}

Awalnya, kami mengira ini merupakan soal semacam bash jail. Tetapi setelah mencoba beberapa command bash dan juga `*` dan `?`, tidak didapatkan apa-apa. Kami pun mencoba memberikan input `print()` dan didapatkan output 1 baris kosong. Berarti ini adalah soal python jail. Karena sedang trending di kalangan ctf nasional, kami menyimpan beberapa payload yang di-share teman-teman lain pada ctf-ctf sebelumnya, dan kami pun mencoba input payload-payload tersebut. Tidak berhasil.

### Mendapatkan shell

Maka, kami berusaha mendapatkan shell dari payload awal

```
print.__self__.__loader__.load_module('o''s').spawnl(0, "/bin/sh", "a")
```

Kami mencoba input kata per kata dari awal dan payload berhasil sampai kata `spawnl`. Kami mengira angka di-ban sehingga kami mengubah `0` menjadi `len('')`. Kami juga mengira `bin` di-ban dan juga `sh`. Sehingga, payload kami menjadi:

```
print.__self__.__loader__.load_module('o''s').spawnl(len(''), '/bi''n/s''h', 'a')
```

Namun, tetap tidak berhasil. Kami mencoba kembali kata per kata untuk argumen di dalam `spawnl` dan sepertinya spasi juga di-ban sehingga kami menghilangkan spasi dan mendapatkan shell.

```
print.__self__.__loader__.load_module('o''s').spawnl(len(''),'/bi''n/s''h','a')
```

{{< image src="sangchall-flag.png" caption="Berhasil mendapatkan shell dan flag" height=140 >}}

> Flag: `slasroot7{n0t_B4D_f0r_4b1J41l_Ch4ll3nG3_wakakakakaka}`
