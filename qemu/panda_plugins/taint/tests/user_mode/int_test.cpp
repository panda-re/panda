/*
 * Simple test that reads in floating point number to be tainted,
 * does a floating point  operation (based on command line argument)
 * with a constant float number, and writes the new buffer to a file.
 */

#include <cstdlib>
#include <iostream>
#include <fstream>
#include <sstream>

void usage();
int read_int(int *f2);
int write_int(int *f3);

int main(int argc, char const *argv[]) {
  // Usage statements
  if (argc < 2) {
    usage();
    return -1;
  }

  // Option handler
  int option = atoi(argv[1]);
  if (option < 1 || option > 5) {
    usage();
    return -1;
  }

  int res = 0;
  int f1 = -187, f2 = 0, f3 = 0;

  res = read_int(&f2);
  if (res) return -1;

  switch (option) {
    case 1:
      //fadd
      f3 = f1 + f2;
      res = write_int(&f3);
      break;
    case 2:
      //fsub
      f3 = f1 - f2;
      res = write_int(&f3);
      break;
    case 3:
      //fmul
      f3 = f1 * f2;
      res = write_int(&f3);
      break;
    case 4:
      //fdiv
      f3 = f1 / f2;
      res = write_int(&f3);
      break;
    case 5:
      //fcmp
      f3 = (f1 < f2);
      res = write_int(&f3);
      break;
    default:
      //ERROR should not happen
      return -1;
      break;
  }
  
  if (res) return -1;

  return 0;
}

void usage() {
  std::cout << "Usage: myprog test_#" << std::endl;
  std::cout << "Test numbers:" << std::endl;
  std::cout << "\t1 - add" << std::endl;
  std::cout << "\t2 - sub" << std::endl;
  std::cout << "\t3 - mul" << std::endl;
  std::cout << "\t4 - div" << std::endl;
  std::cout << "\t5 - cmp" << std::endl;
}

int read_int(int *f2) {
  std::ifstream in("panda_plugins/taint/tests/user_mode/int_test_input.txt");
  if(in.good()) {
    in >> *f2;
    std::cout << "Reading integer: " << std::fixed << *f2 << std::endl;
    in.close();
    return 0;
  } else {
    std:: cout << "ERROR reading from file" << std::endl;
    return 1;
  }
}

int write_int(int *f3) {
  std::ofstream out("panda_plugins/taint/tests/user_mode/int_test_output.txt");
  if(out.good()) {
    std::cout << "Writing integer: " << std::fixed << *f3 << std::endl;
    out << *f3 << std::endl;
    out.close();
    return 0;
  } else {
    std:: cout << "ERROR writing to file" << std::endl;
    return -1;
  }
}