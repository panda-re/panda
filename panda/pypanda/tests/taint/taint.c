#include <stdio.h>
#include <string.h>
void apply_taint(char* c) {
  printf("Apply taint labels to '%s'\n", c);
}

void query_taint(int* result) {
  printf("Result = %d\n", *result);
}

int main(int argc, char* argv[]) {
  //printf("Enter input char: ");
  char *inp = "Hello world";

  apply_taint(inp);

  // Add every other char in inp to result (result should be tainted by those chars)
  int result = 0;
  for (int i = 0; i < strlen(inp); i+=2) {
    result+= (int)inp[i];
  }

  query_taint(&result);

  if (result == 0)
    printf("You lose\n");
  else
    printf("You win\n");

}
