#include <stdio.h>
#include <string.h>
static const unsigned char g[]={25,14,28,22,27,24,33,34,53,40,5,49,63,35,5,106,34,111,59,5,60,53,47,52,62,5,45,51,46,50,5,61,62,56,39};
int main(int c,char**v){ char b[64]; (void)v; if(c>5){ for(unsigned i=0;i<sizeof g;i++) b[i]=g[i]^0x5a; b[sizeof g]=0; puts(b);} puts("Wrong."); return 1; }
