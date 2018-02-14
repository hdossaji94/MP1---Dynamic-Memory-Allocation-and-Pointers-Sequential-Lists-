#include <stdlib.h>

 void f(void) 
 {
 int *x = (int *) malloc(10 * sizeof(int));
 x[10] = 0;
 if (x[0] == 0) x[0] = 1;
 }
 
 int main(void)
 {
 f();
 return 0;
 }
