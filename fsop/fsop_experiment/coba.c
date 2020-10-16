#include<stdio.h>


char buf[0x100] = {0};
FILE *fp;
int main(){
  fp = fopen("key.txt","rw");
  gets(buf);
  fclose(fp);
  system("echo ':D'");
}
