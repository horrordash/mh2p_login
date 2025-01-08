/*
MinGW:
 cc -o mh2p_login mh2p_login.c -lcrypto -lwsock32

Linux:
 cc -o mh2p_login mh2p_login.c -lcrypto
*/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef __MINGW32__
#include <winsock2.h>
#else
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define CHALLENGE_LINE_LEN	128

#ifndef SHUT_WR
#define SHUT_WR   0x01
#endif

const char private_key_data[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"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\n"
"-----END RSA PRIVATE KEY-----";

const char bin2hex[] = "0123456789ABCDEF";

char challenge[5][CHALLENGE_LINE_LEN];

int hex2bin(char hex)
{
  if(hex < '0')		return -1;
  else if(hex <= '9')	return hex-'0';
  else if(hex <  'A')	return -1;
  else if(hex <= 'F')	return hex-'A'+10;
  else if(hex <  'a')	return -1;
  else if(hex <= 'f')	return hex-'a'+10;

  return -1;
}

int main()
{
#ifndef __MINGW32__
  signal(SIGPIPE, SIG_IGN);
#endif

#ifdef __MINGW32__
  WSADATA wsaData;
  if(WSAStartup(MAKEWORD(2, 2), &wsaData))
  {
    printf("WSAStartup failed\n");
    return EXIT_FAILURE;
  }
#endif

  RSA *key_rsa = NULL;
  BIO *key_bio = BIO_new_mem_buf(private_key_data, -1);
  if(key_bio)	key_rsa = PEM_read_bio_RSAPrivateKey(key_bio, NULL, NULL, NULL);
  if(!key_rsa)
  {
    printf("private key load failed\n");
    return EXIT_FAILURE;
  }

  EVP_PKEY* pkey = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pkey, key_rsa);

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(sock < 0)
  {
    printf("socket failed!\n");
    return EXIT_FAILURE;
  }

  struct sockaddr_in serv_addr = {0};

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr("172.16.250.248");
  serv_addr.sin_port = htons(22111);

  if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
  {
    printf("challenge port connection failed\n");
    return EXIT_FAILURE;
  }

  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 500000;

  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

// receive challenge

  int line = 0;
  for(int lptr = 0; line < 5;)
  {
    char net_buf[2];

    if(recv(sock, net_buf, sizeof(net_buf), MSG_WAITALL) != 2)
    {
      printf("challenge receive failed\n");
      return EXIT_FAILURE;
    }

    // parse received part

    int d1 = hex2bin(net_buf[0]);
    int d2 = hex2bin(net_buf[1]);

    if(d1 < 0 || d2 < 0)
    {
      printf("invalid challenge data received\n");
      return EXIT_FAILURE;
    }

    d1 <<= 4;
    d1 |= d2;
    if(0xA == d1)	// EOL detected
    {
      challenge[line][lptr] = 0;
      if(5 == ++line)		break;
      lptr = 0;
    }
    else
    {
      challenge[line][lptr++] = d1;

      if(CHALLENGE_LINE_LEN == lptr)
      {
        printf("challenge data received too long at line %d\n", line+1);
        return EXIT_FAILURE;
      }
    }
  }

  if(line < 5)
  {
    printf("incomplete challenge received\n");
    return EXIT_FAILURE;
  }

  printf("Algo type: %s\n", challenge[0]);
  printf("random:    %s\n", challenge[1]);
  printf("version:   %s\n", challenge[2]);
  printf("chip id:   %s\n", challenge[3]);
  printf("FAZIT:     %s\n", challenge[4]);

// make response

  unsigned char sign_data[256] = {0};

  strcpy(sign_data, challenge[1]);	// random
  strcpy(sign_data+0x23, challenge[3]);	// chip id

  int len = 0x23 + strlen(challenge[3]);
  sign_data[len++] = 0x0A;
  strcpy(sign_data+len, challenge[2]);	// version
  len += strlen(challenge[2]);

  EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
  EVP_DigestSignUpdate(mdctx, sign_data, len);

  size_t siglen;
  EVP_DigestSignFinal(mdctx, NULL, &siglen);

  unsigned char *sig = malloc(siglen);
  EVP_DigestSignFinal(mdctx, sig, &siglen);
  EVP_MD_CTX_destroy(mdctx);

// make response

  unsigned char *response = malloc((siglen+0x28)*2 + 1);	//*2 hex-digits + \n

  memset(response, '0', 0x28*2);

  for(int n = 0;; n++)
  {
    int d = challenge[1][n];
    if(0 == d)	break;

    response[n*2]   = bin2hex[d >> 4];
    response[n*2+1] = bin2hex[d & 0xF];
  }

  for(int n = 0; n < siglen; n++)
  {
    int d = sig[n];

    response[0x28*2 + n*2]   = bin2hex[d >> 4];
    response[0x28*2 + n*2+1] = bin2hex[d & 0xF];
  }

  response[(siglen+0x28)*2] = 0x0A;

  send(sock, response, (siglen+0x28)*2 + 1, 0);
  shutdown(sock, SHUT_WR);
  close(sock);

  free(sig);
  free(response);

  EVP_PKEY_free(pkey);
  BIO_free(key_bio);

#ifdef __MINGW32__
  WSACleanup();
#endif

  return EXIT_SUCCESS;
}
