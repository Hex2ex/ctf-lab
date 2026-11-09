#include <stdio.h>
#include <string.h>
int main(void){ char flag[64]="CTFLAB{printf_never_trusts_user_input}"; char buf[128]; setvbuf(stdout,0,2,0); puts("Tell me something:"); fgets(buf,sizeof buf,stdin); printf(buf); puts(""); (void)flag; return 0; }
