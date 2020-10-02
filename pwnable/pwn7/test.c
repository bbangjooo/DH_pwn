#include<stdio.h>

int main(){
    int a=-2147483648; // MSB만 1 -> 2의 보수 취해서 같은 수
    printf ("%d\n",a);
    a=-a;
    printf ("%d\n",a);

}