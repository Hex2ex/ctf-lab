#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void win(void){ char b[64]; FILE*f=fopen("flag.txt","r"); if(!f){puts("flag.txt missing");exit(1);} fgets(b,64,f); puts(b); exit(0); }
void vuln(void){ char buf[64]; puts("What is your name?"); ssize_t n=read(0,buf,512); if(n>0&&buf[n-1]==10) buf[n-1]=0; else buf[63]=0; printf("Hello %s\n",buf); }
int main(void){ setvbuf(stdout,0,2,0); vuln(); puts("Bye"); return 0; }
