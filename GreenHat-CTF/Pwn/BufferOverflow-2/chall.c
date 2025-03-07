#include <stdio.h>
#include <stdlib.h>


// gcc chall.c -o chall -fno-stack-protector -no-pie -m32

void setup(){
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
    setbuf(stderr,NULL);
}

void win(){
    printf("You win!\n");
    fflush(stdout);
    system("/bin/sh");
    exit(0);
}

void vuln(){
    char buf[24];
    printf("Whats your favorite fruit: ");
    gets(buf);
    printf("Oh! i like %s too\n",buf);
}

int main(){
    setup();
    vuln();
    return 0 ;
}
