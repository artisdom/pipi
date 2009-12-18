#define ADDR_MAX_LEN	192
#define REQ_MAX_SIZE	336	// 336 = 126+8+4+9+4+128+55+2
#define ADDR_BASE64	"thunder://"
//#define SERVIP		"58.254.39.6"
#define SERVIP		"123.129.242.170"
//#define SERVIP		"58.254.134.233"
#define PORT		80

typedef struct {
	char ip[16];
	int port;
} serv_info;

static void die(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
	exit(1);
}
//unsigned char thunder_cmd_a_seq[8] = {0x34, 00, 00, 00, 0x96, 00, 00, 00};
unsigned char thunder_cmd_a_seq[8] = {0x34, 00, 00, 00, 0x82, 00, 00, 00};
unsigned char thunder_md5_pad[56] = { 0x80, 00, 00, 00, 00, 00, 00, 00,
	00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
	00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
	00, 00, 00, 00, 00, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 00, 00};
