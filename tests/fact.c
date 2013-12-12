int main(int n, char** argv) {
  return n > 1 ? n * main(n - 1, argv) : 1;
}
