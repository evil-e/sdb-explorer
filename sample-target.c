/*
Copyright (c) 2014, Jon Erickson
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the FreeBSD Project.

*/

#include <Windows.h>
#include <stdio.h>
#include "udis86.h"

int main(int argc, char** argv)
{
	LPVOID addr;
	DWORD rva;
	DWORD i;
	unsigned char* tmp;
	ud_t disasm;

	HMODULE h = LoadLibraryA("C:\\Windows\\System32\\mshtml.dll");
	if (h == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Failed to load mshtml.dll\n");
		exit(-1);
	}

	ud_init(&disasm);
	ud_set_mode(&disasm, 32);
	ud_set_syntax(&disasm, UD_SYN_INTEL);
	
	addr = GetProcAddress(h, "PrintHTML");
	rva = (DWORD)addr - (DWORD)h;
	printf("%p %p = 0x%x\n", h, addr, rva);
	tmp = (unsigned char*)addr;
	tmp -= 5;
	for (i = 0; i < 15; i++)
	{
		printf("%02x ", tmp[i]);
	}
	printf("\n\n");

	ud_set_input_buffer(&disasm, tmp, 15);
	while (ud_disassemble(&disasm))
	{
		printf("\t%08llx  %-16s %s\n", ud_insn_off(&disasm), ud_insn_hex(&disasm), ud_insn_asm(&disasm));
	}

	printf("\n");

	printf("Press a key to exit\n");
	fflush(stdout);
	i = getc(stdin);
}