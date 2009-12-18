#include <string.h>

const char *alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int base64_encode(char *in, int in_len, char *out)
{
	int i, m, n, t;

	t = in_len/3;
	for (i = 0; i < t; i++) {
		m = i * 3;
		n = i * 4;
		out[n] = alpha[in[m] >> 2];
		out[n+1] = alpha[((in[m] << 4) + (in[m+1]>>4)) & 0x3f];
		out[n+2] = alpha[((in[m+1] << 2) + (in[m+2]>>6)) & 0x3f];
		out[n+3] = alpha[in[m+2] & 0x3f];
	}
	m = i * 3;
	n = i * 4;
	if ((t * 3 + 1) == in_len) {
		out[n] = alpha[in[m] >> 2];
		out[n+1] = alpha[(in[m] << 4) & 0x3f];
		out[n+2] = '=';
		out[n+3] = '=';
	} else if ((t * 3 + 2) == in_len) {
		out[n] = alpha[in[m] >> 2];
		out[n+1] = alpha[((in[m] << 4) + (in[m+1]>>4)) & 0x3f];
		out[n+2] = alpha[(in[m+1] << 2) & 0x3f];
		out[n+3] = '=';
	}
	out[n+4] = '\0';

	return 0;
}

char beta[128];

static void init_beta()
{
beta['A'] = 0; beta['B'] = 1; beta['C'] = 2; beta['D'] = 3; beta['E'] = 4;
beta['F'] = 5; beta['G'] = 6; beta['H'] = 7; beta['I'] = 8; beta['J'] = 9;
beta['K'] = 10; beta['L'] = 11; beta['M'] = 12; beta['N'] = 13; beta['O'] = 14;
beta['P'] = 15; beta['Q'] = 16; beta['R'] = 17; beta['S'] = 18; beta['T'] = 19;
beta['U'] = 20; beta['V'] = 21; beta['W'] = 22; beta['X'] = 23; beta['Y'] = 24;
beta['Z'] = 25; beta['a'] = 26; beta['b'] = 27; beta['c'] = 28; beta['d'] = 29;
beta['e'] = 30; beta['f'] = 31; beta['g'] = 32; beta['h'] = 33; beta['i'] = 34;
beta['j'] = 35; beta['k'] = 36; beta['l'] = 37; beta['m'] = 38; beta['n'] = 39;
beta['o'] = 40; beta['p'] = 41; beta['q'] = 42; beta['r'] = 43; beta['s'] = 44;
beta['t'] = 45; beta['u'] = 46; beta['v'] = 47; beta['w'] = 48; beta['x'] = 49;
beta['y'] = 50; beta['z'] = 51; beta['0'] = 52; beta['1'] = 53; beta['2'] = 54;
beta['3'] = 55; beta['4'] = 56; beta['5'] = 57; beta['6'] = 58; beta['7'] = 59;
beta['8'] = 60; beta['9'] = 61; beta['+'] = 62; beta['/'] = 63;
}

int base64_decode(char *in, char *out, unsigned int *out_len)
{
	int i, m, n, t;

	init_beta();

	t = strlen(in)/4;
	for (i = 0; i < t-1; i++) {
		m = i * 4;
		n = i * 3;
		out[n] = (beta[in[m]] << 2) + (beta[in[m+1]] >> 4);
		out[n+1] = (beta[in[m+1]] << 4) + (beta[in[m+2]] >> 2);
		out[n+2] = (beta[in[m+2]] << 6) + beta[in[m+3]];
	}

	m = i * 4;
	n = i * 3;
	out[n] = (beta[in[m]] << 2) + (beta[in[m+1]] >> 4);
	if (in[m+2] == '=') {
		out[n+1] = beta[in[m+1]] << 4;
		*out_len = n + 1;
	} else {
		out[n+1] = (beta[in[m+1]] << 4) + (beta[in[m+2]] >> 2);
		if (in[m+3] == '=') {
			out[n+2] = beta[in[m+2]] << 6;
		} else {
			out[n+2] = (beta[in[m+2]] << 6) + beta[in[m+3]];
		}
		*out_len = n + 2;
	}

	return 0;
}
