/*
 * Simple test that reads in floating point number to be tainted,
 * does a floating point add operation with a constant float number,
 * and writes the new buffer to a file.
 */

#include <iostream>
#include <fstream>
#include <sstream>

int main() {
  float f1 = -187.33667, f2 = 0.0, f3 = 0.0;

  std::ifstream in("input.txt");
  if(in.good()) {
    in >> f2;
    std::cout << "Reading floating point number: " << std::fixed << f2 << std::endl;
    in.close();
  }

  f3 = f1 + f2;

  std::ofstream out("output.txt");
  if(out.good()) {
    std::cout << "Writing floating point number: " << std::fixed << f3 << std::endl;
    out << f3;
    out.close();
  }

  return 0;
}

