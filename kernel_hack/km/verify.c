#include "verify.h"
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>

char rc4_key[] = "!@##$asdcgfxxxop";

void rc4_init(unsigned char* s, unsigned char* key, unsigned long len_key)
{
	int i = 0, j = 0;
	unsigned char k[256] = { 0 };
	unsigned char tmp = 0;
	for (i = 0; i < 256; i++) {
		s[i] = i;
		k[i] = key[i % len_key];
	}
	for (i = 0; i < 256; i++) {
		j = (j + s[i] + k[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
	}
}

void rc4_crypt(unsigned char* data, 
    unsigned long len_data, unsigned char* key, 
    unsigned long len_key)
{
	unsigned char s[256];
	int i = 0, j = 0, t = 0;
	unsigned long k = 0;
	unsigned char tmp;
	rc4_init(s, key, len_key);
	for (k = 0; k < len_data; k++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		tmp = s[i];
		s[i] = s[j];
		s[j] = tmp;
		t = (s[i] + s[j]) % 256;
		data[k] = data[k] ^ s[t];
	}
}

bool encrypt_key(char* keydata, size_t len, int* magic) {
    if (!keydata || len < 0x100) {
        return false;
    }

    *magic = *(int*)keydata ^ 0x0C8D778A;

	*(int*)&keydata[len - 5] = *magic;

    rc4_crypt(keydata, len, rc4_key, strlen(rc4_key));
    return true;
}

bool decrypt_key(char* keydata, size_t len, int magic) {
    if (!keydata || len < 0x100) {
        return false;
    }

    rc4_crypt(keydata, len, rc4_key, strlen(rc4_key));

	if(magic + 0x55 == *(int*)&keydata[len - 5]) {
        return true;
    }
    return false;
}

bool init_key(char* key, size_t len_key) {
    
    struct socket *sock;
    struct sockaddr_in addr;
    struct msghdr sendmsg, recvmsg;
    struct kvec send_vec, recv_vec;
    char* buf = NULL;
    int err, magic;

    memset(&addr, 0, sizeof(addr));
    memset(&sendmsg, 0, sizeof(sendmsg));
    memset(&send_vec, 0, sizeof(send_vec));
    memset(&recvmsg, 0, sizeof(recvmsg));
    memset(&recv_vec, 0, sizeof(recv_vec));

    if (!key || len_key < 0x100) {
        return false;
    }

    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf) {
        return false;
    }

    err = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &sock);
    if (err < 0) {
        goto fail;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = in_aton("64.112.43.2");
    addr.sin_port = htons(31828);

    err = sock->ops->connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    if (err < 0) {
        goto fail;
    }

    memset(buf, 0, PAGE_SIZE);
    memcpy(buf, key ,len_key);
    encrypt_key(buf, 0x100, &magic);
    send_vec.iov_base = buf;
    send_vec.iov_len = 0x100;
    //send
    err = kernel_sendmsg(sock, &sendmsg, &send_vec, 1, 0x100);
    if (err < 0) {
        goto fail;
    }

    memset(buf, 0, PAGE_SIZE);
    recv_vec.iov_base = buf;
    recv_vec.iov_len = 0x100;
    //recv
    err = kernel_recvmsg(sock, &recvmsg, &recv_vec, 1, 0x100, 0);
    if (err < 0) {
        goto fail;
    }

    if(decrypt_key(buf, 0x100, magic)) {
        if (*(uint64_t*)&buf[0] == 0xDFFDABCD03007677) {
            sock_release(sock);
            return true;
        }
    }

fail:
 	if (sock) {
		sock_release(sock);
		sock = NULL;
	}
    if (buf) {
        kfree(buf);
    }
    return false;
}
