
#include <vector>
#include <map>
#include <string>

using namespace std;

typedef struct foo_struct {
  int x;
  std::vector < std::map < std::string, std::map < int, int > > > y;
} Foo;



Foo getfoo() {
  Foo f = Foo();
  f.y.resize(2);
  return f;
}

void bar (Foo &f) {
  f.x = 17;
  f.y.resize(2);
  f.y[1]["abc"][3636] = 17;
  f.y[0]["efg"][4] = 8;
  f.y[0]["efg"][34] = 8;
}
  

int main () {
  Foo f = getfoo();
  bar(f);
  for ( auto &el : f.y ) {
    for ( auto &kvp1 : el ) {
      std::string k1 = kvp1.first;
      printf ("%s \n", k1.c_str());
      for ( auto &kvp2 : kvp1.second ) {
	int i = kvp2.first;
	int j = kvp2.second;
	printf (" i=%d j=%d\n", i,j);
      }
    }
  }
}
