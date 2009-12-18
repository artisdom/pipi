#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "pipi.h"
#include "base64.h"
#include "aes.h"

int print_hex(unsigned char *buf, int len)
{
	int i;
	printf("\n");
	for (i = 0; i < len; i++) {
		if (i != 0 && !(i % 16))
			printf("\n");
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

int write_hex(char *name, unsigned char *buf, int len)
{
	int fd;

	fd = open(name, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR);
	if (fd == -1) {
		perror("open to write error");
		exit(1);
	}
	write(fd, buf, len);

    return 0;
}

int parse_address(char *addr, char *url)
{
	unsigned int len;
	char *p, q[ADDR_MAX_LEN];

	p = addr;
	len = strlen(p);
	if (len > ADDR_MAX_LEN)
		die("url length exceedes %d", ADDR_MAX_LEN);
	strncpy(url, addr, len);
	*(url+len) = '\0';

	/* check url head whether "thunder://", 
	 * Yes, then it need be decoded with BASE64 */
	if (!strncmp(p, ADDR_BASE64, strlen(ADDR_BASE64))) {
		p += strlen(ADDR_BASE64);
		base64_decode(p, q, &len);
		if (strncmp(q, "AA", 2)) {
			printf("q: %s\n", q);
			die("thunder address error");
		}
		if (strncmp(q + len - 2, "ZZ", 2)) {
			printf("q+len-2: %s\n", q+len-1);
			die("thunder address error");
		}
		*(q+len-2) = '\0';
		memset(url, '\0', sizeof(url));
		strncpy(url, q+2, strlen(q));
	}
	/* should process other kind of address here */

	return 0;
}

int aes_decrypt_cont(unsigned char *in, int in_len, unsigned char *out,
		unsigned char *aes_key, int aes_len)
{
	int i;
	aes_ctx_t *ctx;

	init_aes();
	ctx = aes_alloc_ctx(aes_key, aes_len);
	if(!ctx) {
		perror("aes_alloc_ctx");
		return -1;
	}

	for(i = 0; i < in_len; i += 16)
		aes_decrypt(ctx, in + i, out + i);

	print_hex(out, in_len);

	return 0;
}

int aes_encrypt_cont(unsigned char *in, int in_len, unsigned char *out,
		unsigned char *aes_key, int aes_len)
{
	int i;
	aes_ctx_t *ctx;

	init_aes();
	ctx = aes_alloc_ctx(aes_key, aes_len);
	if(!ctx) {
		perror("aes_alloc_ctx");
		return -1;
	}
	for(i = 0; i < in_len; i += 16)
		aes_encrypt(ctx, in + i, out + i);

	return 0;
}

/*
 * msg: the place where ready to send packet will be
 * msg_len: value-result parameter, it contain the 
 *          actual length of msg when return
 * url: the link of the file which we'll download
 * aes_key: the key to enc and dec
 * aes_len: the length of aes_key
 */
int compose_req_packet(unsigned char *msg, int *msg_len, 
		unsigned char *url, unsigned char *aes_key, int aes_len)
{
	int len, i, fd;
	int pad_num, url_len, raw_len, con_len, raw_a_head_len;
	unsigned char *p;
	unsigned char post[] = "POST / HTTP/1.1\r\nHost: ";
	unsigned char cont[] = "\r\nContent-type: application/octet-stream\r\nContent-Length: ";
	unsigned char conn[] = "\r\nConnection: Keep-Alive\r\n\r\n";

	unsigned char raw_head[9] = {0x94, 0x01, 0x05, 0x00, 0x00, 0x00, 0xD1, 0x07, 0x00};
	unsigned char raw_tail[55] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x0A, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x30, 0x30, 0x31, 0x32, 0x33, 0x46, 0x37,
0x44, 0x43, 0x31, 0x44, 0x45, 0x30, 0x30, 0x30, 0x30, 0x2F, 0x9A, 0x38, 0x6E, 0x2A, 0x01, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char *raw_packet, *enc_packet;

	url_len = strlen(url);
	
	/* calculate unencrypted packet length */
	raw_len = sizeof(raw_head) + 4 + url_len + sizeof(raw_tail); // 4 is the space for url length
	pad_num = 16 - (raw_len % 16); //need to eliminate pad_num = 16
	raw_len += pad_num;

	/*                              http_content
	 *                            /             \
	 *                           /               \
	 *    header for unencrypted packet	 + unencrypted packet 
	 * /                                 \
	 * |                                  |
	 * |<--cmd-->| |<--seq-->| |<-length->|
	 * 34 00 00 00 96 00 00 00 80-01 00 00
	 */
	raw_a_head_len = raw_len + sizeof(thunder_cmd_a_seq) + 4; // 4 is the space for length

	/* calculate Content-Length in http header */
	memset(msg, '\0', *msg_len);
	snprintf(msg, *msg_len, "%d", PORT);
	con_len = strlen(post) + strlen(SERVIP) + strlen(":") + 
		strlen(msg) + strlen(cont) + strlen(conn) + raw_a_head_len;

	/* fill the human-readable part in POST packet */
	memset(msg, '\0', *msg_len);
	snprintf(msg, *msg_len, "%s%s%s%d%s", post, SERVIP,
			cont, raw_a_head_len, conn);

	printf("header: %s\n", msg);

	/* build the raw part for 128-AES
	 * raw part = raw_head + url_len + url + raw_tail + padding
	 */
	raw_packet = (unsigned char *)calloc(1, raw_len);
	if (raw_packet == NULL)
		die("calloc for encode source error");
	p = raw_packet;

	len = sizeof(raw_head);
	memcpy(raw_packet, raw_head, len);
	p += 9;

	*((int *)p) = url_len;
	p += sizeof(int);

	memcpy(p, url, url_len);
	p += url_len;

	len = sizeof(raw_tail);
	memcpy(p, raw_tail, len);
	p += len;

	/* pad for encode */
	for(i = 0; i < pad_num; i++)
		*p++ = 0x0c;

	printf("raw_len: %d\n", raw_len);
	printf("url_len: %d\n", url_len);
	printf("raw_a_head_len: %d\n", raw_a_head_len);
	printf("con_len: %d\n", con_len);
	printf("\nThe http content packet before encrypt:\n");
	print_hex(raw_packet, raw_len);

	/* encode the raw part with 128-AES */
	enc_packet = (unsigned char *)calloc(1, raw_len);
	if (enc_packet == NULL)
		die("calloc for encode output error");
	aes_encrypt_cont(raw_packet, raw_len, enc_packet, aes_key, aes_len);

	/* use the above resource to compose a complete POST packet 
	 * msg -- already contain "http POST command"
	 * con_len -- the msg length
	 * raw_len -- the length of encrypted packet equal to orignal packet
	 * raw_a_head_len -- the length of the left we need to copy to msg
	 * the left we need to copy to msg is:
	 * thunder_cmd_a_seq + raw_len + enc_packet
	 */
	p = msg + con_len - raw_a_head_len;
	len = sizeof(thunder_cmd_a_seq);

	memcpy(p, thunder_cmd_a_seq, len);
	p += len;

	*(int *)p = raw_len;
	p += sizeof(int);

	memcpy(p, enc_packet, raw_len);

	*msg_len = con_len;

	printf("\nThe whole message that will be send to server.\n");
	print_hex(msg, con_len);

	write_hex("test.bin", msg, *msg_len);

	free(raw_packet);
	free(enc_packet);
	return 0;
}

int recv_packet(int sk, unsigned char *buf, int *size)
{
	int i, flag = 0, buf_len;
	int len, recv_len = 0, pkt_size, ret;
	unsigned char *p;
	unsigned char recv_resp[1] = {0};

	len = sizeof(thunder_cmd_a_seq);
	buf_len = *size;
	memset(buf, '\0', buf_len);
	p = buf;
	while (1) {
		if ((ret = recv(sk, buf + recv_len, buf_len - recv_len, 0)) < 0)
			die("recv packet from %s:%d error. ret = %d",
					SERVIP, PORT, ret);
		printf("received %d bytes\n", ret);
		recv_len += ret;
		i = 0;
		while ((i < ret) && (!flag)) {
			if (!memcmp(p, thunder_cmd_a_seq, len)) {
				p += len;
				pkt_size = *((int *)p);
				p += sizeof(int);
				printf("packet size: %d\n", pkt_size);
				flag = 1;
			} else
				p++;
			i++;
		}
		/* one recv, one response */
		if ((ret = send(sk, recv_resp, 0, 0)) < 0)
			die("send response error.");
		if (flag)
			break;
	}
	i = pkt_size + (buf - p);
	if (i > buf_len)
		die("buffer for receiving is too small. we need %d bytes\n", i);
	while ((recv_len - (buf - p)) < pkt_size) {
		if ((ret = recv(sk, buf + recv_len, buf_len - recv_len, 0)) < 0) {
			printf("recv packet from %s:%d error. ret = %d",
					SERVIP, PORT, ret);
			break;
		}
		printf("received %d bytes\n", ret);
		recv_len += ret;
		if ((ret = send(sk, recv_resp, 0, 0)) < 0)
			die("send response error.");
	}

	memmove(buf, p, pkt_size);
	*size = pkt_size;

	close(sk);
	return 0;
}

int get_url_list(unsigned char *msg, int msg_len, 
		unsigned char *aes_key, int aes_len)
{
	int sk, pkt_size;
	struct sockaddr_in servaddr;
	unsigned char recvbuf[8192], *enc;

	if ((sk = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		die("create socket to send request error");
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	printf("now get the mirror list\n");
	printf("servip: %s\n", SERVIP);
	//servaddr.sin_addr.s_addr = inet_addr(SERVIP);
	if (inet_pton(AF_INET, SERVIP, &servaddr.sin_addr) <= 0)
		die("inet_pton error for %s", SERVIP);

	printf("connect to %s:%d\n", SERVIP, PORT);
	if (connect(sk, (struct sockaddr *)&servaddr,
				sizeof(struct sockaddr)) < 0)
		die("connect to %s:%d error", SERVIP, PORT);

	printf("send packet to %s:%d\n", SERVIP, PORT);
	if (send(sk, msg, msg_len, 0) < 0)
		die("send packet to %s:%d error", SERVIP, PORT);

	printf("recv packet from %s:%d\n", SERVIP, PORT);
	pkt_size = sizeof(recvbuf);
	recv_packet(sk, recvbuf, &pkt_size);

	/* prepare for 128-AES decode */
	enc = (unsigned char *)calloc(1, pkt_size);
	if (enc == NULL)
		die("calloc for 128-AES decode error");

	aes_decrypt_cont(recvbuf, pkt_size, enc, aes_key, aes_len);

	write_hex("out.bin", enc, pkt_size);

	return 0;
}

static void usage()
{
	printf("pipi - P2SP downloader for Linux\n");
	printf("Usage:\n"
			"\tpipi <url>\n");
}

int main(int argc, char *argv[])
{
	int i = 0, req_len;
	unsigned long long len;		/* use long long for md5 enc consistent */
	unsigned char url[ADDR_MAX_LEN];
	unsigned char md5_in[64];
	unsigned char aes_key[16];
	unsigned char req_packet[REQ_MAX_SIZE];

	if (argc != 2) {
		usage();
		exit(1);
	}
	if (parse_address(argv[1], url) != 0)
		die("parse_address error");
	printf("url: %s\n", url);

	len = sizeof(thunder_cmd_a_seq);
	memcpy(md5_in, thunder_cmd_a_seq, len);
	memcpy(md5_in + len, thunder_md5_pad, sizeof(thunder_md5_pad));
	len = sizeof(md5_in);
	md5_encode(md5_in, len, aes_key);

	printf("\naes_key:");
	print_hex(aes_key, sizeof(aes_key));

	req_len = sizeof(req_packet);
	compose_req_packet(req_packet, &req_len, url, 
			aes_key, sizeof(aes_key));

	get_url_list(req_packet, req_len, aes_key, sizeof(aes_key));

	exit(0);
}
