#include <string.h>

int base64_encode(char *in, int in_len, char *out);
int base64_decode(char *in, char *out, unsigned int *out_len);
