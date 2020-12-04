all:
	gcc -fno-stack-protector -o victim victim.c
	execstack -s victim
	setarch `arch` -R ./victim