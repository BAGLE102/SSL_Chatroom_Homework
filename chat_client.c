/* chat_client.c
 * 功能：SSL 聊天室客戶端
 * 支援：
 * 1. 連線到 SSL Server
 * 2. 使用 fork() 同時處理「接收訊息」與「發送訊息」
 */

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h> // for exit
#include <signal.h> // for kill

#define FAIL    -1
#define BUFFER_SIZE 1024

// 建立連線
int OpenConnection(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
    if ( (host = gethostbyname(hostname)) == NULL ) {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ) {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

// 初始化 Context
SSL_CTX* InitCTX(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

// 顯示憑證
void ShowCerts(SSL* ssl) {
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl);
    if ( cert != NULL ) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("No certificates.\n");
    }
}

int main(int count, char *strings[]) {   
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[BUFFER_SIZE];
    char input[BUFFER_SIZE];
    char *hostname, *portnum;
    char username[32];
 
    if ( count != 3 ) {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    hostname = strings[1];
    portnum = strings[2];

    // 詢問使用者名稱
    printf("Enter your username: ");
    if (fgets(username, 32, stdin) == NULL) {
        exit(0);
    }
    // 移除換行符
    username[strcspn(username, "\n")] = 0;
 
    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);
    
    if ( SSL_connect(ssl) == FAIL ) {
        ERR_print_errors_fp(stderr);
    } else {   
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);

        // 1. 傳送 Username 給 Server
        SSL_write(ssl, username, strlen(username));

        // 2. 使用 fork 分離讀寫程序
        // 父進程：負責監聽鍵盤輸入並發送
        // 子進程：負責監聽伺服器訊息並顯示
        pid_t pid = fork();

        if (pid == 0) { 
            // --- Child Process (Reader) ---
            while(1) {
                int bytes = SSL_read(ssl, buf, sizeof(buf)-1);
                if (bytes > 0) {
                    buf[bytes] = 0;
                    printf("%s\n", buf); // 顯示收到的訊息
                } else {
                    // Server 斷線
                    printf("Connection closed by server.\n");
                    break;
                }
            }
            // 讀取失敗或結束時，強制結束父程序並離開
            kill(getppid(), SIGKILL);
            exit(0);
        } else {
            // --- Parent Process (Writer) ---
            while(1) {
                if(fgets(input, sizeof(input), stdin) != NULL) {
                    SSL_write(ssl, input, strlen(input));
                    if(strncmp(input, "exit", 4) == 0) break;
                }
            }
        }
        
        SSL_free(ssl);
    }
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}