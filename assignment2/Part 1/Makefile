obj-m += readRegister.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insert:
	sudo /sbin/insmod readRegister.ko

remove:
	sudo /sbin/rmmod readRegister.ko