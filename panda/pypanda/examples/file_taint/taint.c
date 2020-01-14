#include <stdio.h>
#include <string.h>


int main(int argc, char* argv[]) {
  char buff[100];
  FILE *fp;
  fp = fopen("/tmp/panda.panda","r");
  fgetc(buff, 10, (FILE*) fp);
  //buffer should be tainted at this point
  query_taint(&buff);
  if (result == 0){
    printf("You lose\n");
  }else{
    printf("You win\n")
  }
  return 0;
}
