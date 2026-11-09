#include <stdio.h>
#include <string.h>
int main(int c,char**v){ if(c<2){puts("usage: ./rev-crackme-1 <password>");return 1;} if(strcmp(v[1],"secretpass42")==0) puts("Correct! CTFLAB{ltrace_and_strings_are_enough}"); else puts("Wrong."); return 0; }
