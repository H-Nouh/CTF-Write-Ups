#include<stdio.h>
#include<stdlib.h>
void vuln(){
    char buf[64];
    gets(buf);
}

void win(int arg1, int arg2){
char flag[100];
FILE* file = fopen("flag.txt", "r");
if(arg1 == 0xcafebabe && arg2 == 0xcafed00d){    
    fread(flag, 100, 1, file);
    printf("here's the flag : %s\n", flag);
}

}

int main(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    vuln();

    return 0;
}
