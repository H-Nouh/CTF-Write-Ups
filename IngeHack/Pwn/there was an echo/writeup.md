Look I'll give you the full context:

I'm solving a pwn chall, here's the title and description:

there was an echo (title)
flag is at ./flag (description)


I got a 64 bits ELF "out"

this is the result of checksec:

Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled

Using ghidra, I got these 2 interesting functions:

this one seems to be main (btw please comment on how I interpreted it, I renamed a var to canary cause it seemed like one but in the protections it said there are no canaries so I'm a bit confused):



void FUN_00101309(void)

{
  long in_FS_OFFSET;
  char input [264];
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  FUN_00101229();
  do {
    fgets(input,0x100,stdin);
    printf(input);
  } while( true );
}




here is the other function:



void filters(void)

{
  int iVar1;
  long lVar2;
  
  lVar2 = seccomp_init(0);
  if (lVar2 == 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  seccomp_rule_add(lVar2,0x7fff0000,2,0);
  seccomp_rule_add(lVar2,0x7fff0000,0,0);
  seccomp_rule_add(lVar2,0x7fff0000,1,0);
  seccomp_rule_add(lVar2,0x7fff0000,0xe7,0);
  iVar1 = seccomp_load(lVar2);
  if (iVar1 < 0) {
    seccomp_release(lVar2);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  seccomp_release(lVar2);
  return;
}





What I'm assuming so far, since we have a fmstr vuln, we can exploit it to leak some sort of address, then we gotta take advantage of us being able to use open and read calls, and since we know that the flag is at ./flag then we can somehow open it and read it. However, I have no clue how I can get to that syscall
