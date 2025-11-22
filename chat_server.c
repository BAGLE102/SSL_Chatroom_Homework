/* chat_server.c
 * 功能：多執行緒 SSL 聊天室伺服器
 * 支援：
 * 1. 多人同時連線聊天 (廣播)
 * 2. 一對一私密訊息 (格式: @Name Message)
 */

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h> // 引入執行緒庫
#include <stdlib.h>

#define FAIL    -1
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024

// 定義客戶端結構，用來儲存連線資訊與名稱
typedef struct {
    SSL *ssl;
    int socket;
    char name[32];
    int active; // 1 表示在線，0 表示空位
} Client;

Client client_list[MAX_CLIENTS]; // 全域客戶端列表
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER; // 互斥鎖，保護列表

// 初始化 OpenSSL Server Context
SSL_CTX* InitServerCTX(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_library_init();
    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if ( ctx == NULL ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

// 載入憑證
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    if ( !SSL_CTX_check_private_key(ctx) ) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

// 建立 Socket
int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    int yes = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)); // 允許重複使用 Port
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ) {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 ) {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

// 廣播訊息給所有其他用戶 (除了發送者自己)
void send_to_all(char *msg, int sender_idx) {
    pthread_mutex_lock(&clients_mutex);
    for(int i = 0; i < MAX_CLIENTS; ++i) {
        if(client_list[i].active && i != sender_idx) {
            SSL_write(client_list[i].ssl, msg, strlen(msg));
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

/* * 核心功能：一對一秘密訊息 
 * 格式: @TargetName Message...
 */
void send_private_message(char *msg, int sender_idx) {
    char target_name[32];
    char body[BUFFER_SIZE];
    
    // 解析字串，跳過第一個 '@'
    // 假設格式為 "@name message"
    char *space_pos = strchr(msg, ' ');
    if(!space_pos) return; // 格式錯誤

    int name_len = space_pos - (msg + 1);
    if(name_len >= 32) name_len = 31;
    
    strncpy(target_name, msg + 1, name_len);
    target_name[name_len] = '\0';
    
    strcpy(body, space_pos + 1); // 複製實際訊息內容

    int found = 0;
    char formatted_msg[BUFFER_SIZE + 64]; // 確保緩衝區夠大

    pthread_mutex_lock(&clients_mutex);
    for(int i = 0; i < MAX_CLIENTS; ++i) {
        if(client_list[i].active && strcmp(client_list[i].name, target_name) == 0) {
            // 找到目標用戶，只發送給他
            snprintf(formatted_msg, sizeof(formatted_msg), "[Secret from %s]: %s", client_list[sender_idx].name, body);
            SSL_write(client_list[i].ssl, formatted_msg, strlen(formatted_msg));
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    // 回傳結果給發送者
    if(found) {
        snprintf(formatted_msg, sizeof(formatted_msg), "[System]: Secret message sent to %s.\n", target_name);
    } else {
        snprintf(formatted_msg, sizeof(formatted_msg), "[System]: User '%s' not found.\n", target_name);
    }
    SSL_write(client_list[sender_idx].ssl, formatted_msg, strlen(formatted_msg));
}

// 處理客戶端的執行緒函數
void *client_handler(void *arg) {
    int idx = *(int*)arg;
    char buffer[BUFFER_SIZE];
    int bytes;
    SSL *ssl = client_list[idx].ssl;

    // 1. 讀取第一條訊息作為使用者名稱 (簡單協定)
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if(bytes > 0) {
        buffer[bytes] = 0;
        // 去除換行符
        buffer[strcspn(buffer, "\n")] = 0;
        strcpy(client_list[idx].name, buffer);
        printf("Client %s connected.\n", client_list[idx].name);
        
        // 歡迎訊息
        char welcome[128];
        snprintf(welcome, sizeof(welcome), "[System]: Welcome %s! Use '@name msg' for secret chat.\n", client_list[idx].name);
        SSL_write(ssl, welcome, strlen(welcome));
    } else {
        goto disconnect;
    }

    // 2. 訊息循環
    while(1) {
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if(bytes <= 0) break;
        
        buffer[bytes] = 0;
        
        // 檢查是否為秘密訊息 (以 @ 開頭)
        if(buffer[0] == '@') {
            send_private_message(buffer, idx);
        } else {
            // 廣播訊息
            char broadcast_msg[BUFFER_SIZE + 64];
            snprintf(broadcast_msg, sizeof(broadcast_msg), "[%s]: %s", client_list[idx].name, buffer);
            send_to_all(broadcast_msg, idx);
        }
    }

disconnect:
    // 清理連線
    pthread_mutex_lock(&clients_mutex);
    client_list[idx].active = 0;
    pthread_mutex_unlock(&clients_mutex);
    
    printf("Client %s disconnected.\n", client_list[idx].name);
    SSL_free(ssl);
    close(client_list[idx].socket);
    free(arg);
    return NULL;
}

int main(int count, char *strings[]) {   
    SSL_CTX *ctx;
    int server;
    char *portnum;
 
    if ( count != 2 ) {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }
    portnum = strings[1];
    ctx = InitServerCTX();
    LoadCertificates(ctx, "newreq.pem", "newreq.pem");
    server = OpenListener(atoi(portnum));
    
    printf("Server listening on port %s...\n", portnum);

    while (1) {   
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        
        int client_sock = accept(server, (struct sockaddr *)&addr, &len);
        
        // 尋找空位
        int client_idx = -1;
        pthread_mutex_lock(&clients_mutex);
        for(int i=0; i<MAX_CLIENTS; ++i){
            if(!client_list[i].active){
                client_idx = i;
                client_list[i].active = 1;
                client_list[i].socket = client_sock;
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);

        if(client_idx == -1) {
            printf("Server full. Rejected connection.\n");
            close(client_sock);
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_sock);
        client_list[client_idx].ssl = ssl;

        if ( SSL_accept(ssl) == FAIL ) {
            ERR_print_errors_fp(stderr);
            close(client_sock);
            client_list[client_idx].active = 0;
        } else {
            // 建立執行緒來處理該客戶端
            pthread_t tid;
            int *arg = malloc(sizeof(int));
            *arg = client_idx;
            if(pthread_create(&tid, NULL, client_handler, arg) != 0) {
                perror("Thread create failed");
            }
        }
    }
    close(server);
    SSL_CTX_free(ctx);
}