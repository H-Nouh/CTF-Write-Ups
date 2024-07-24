#include <stdio.h>
#include <stdlib.h>


// gcc chall.c -o chall -fno-stack-protector -no-pie -m32

void setup(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
}

void flag(){
    FILE* fd = fopen("flag.txt","r");

    if (fd==NULL){
        printf("Error while openning flag.txt\n") ;
        exit(-1) ;
    }

    char flag[0x80];

    fgets(flag,0x80,fd) ;

    printf("%s",flag);

    exit(0) ;
}

void vuln(){
    char buf[64];
    int a = 0;
    int b = 0;
    gets(buf);

    if (a == 0x13371337) {
        if (b == 0xdeadbeef) {
            printf("\n");
            flag();
            exit(0);
            }
        printf("Sooo close!\n");
    }
    else{
        puts("Sorry, maybe next time\n");
        exit(0) ;
    }
}

int main(){
    setup();
    printf("Welcome to PWN!\n");
    vuln();
    return 0 ;
}