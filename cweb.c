/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "cweb.h"

#ifdef __cplusplus
extern "C"
{
#endif

// 函数说明：检查参数c是否为空格字符，
// 也就是判断是否为空格(' ')、定位字符(' \t ')、CR(' \r ')、换行(' \n ')、垂直定位字符(' \v ')或翻页(' \f ')的情况。
// 返回值：若参数c 为空白字符，则返回非 0，否则返回 0。
#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: cweb/0.1.0\r\n" // 定义server名称


typedef struct route_handler route_handler;

//路由结构体
struct route_handler
{
    char *route;//请求url
    handler *hdl;//处理函数
    route_handler *next;
};

//创建服务端socket
static int createServer(u_short *port);
//启动web服务线程
static void *startWebThread(void *serverAddr);
//接收请求
static void *accept_request(void *client);
//查询路由
static route_handler *findRoute(char *);
//读取一行请求数据
static int get_line(int, char *, int);
//解析url参数
static int parse_url_param(char *buf, request *req);
//对url参数进行内存申请
static int url_param_calloc(request_url_param **param, char *key, char *val);
//读取请求体
static int read_body(int sock, char *buf, int size);
//解析请求头
static int parse_header(char *line, request *req);
//响应处理
static void do_response(int client, int code, char *contentType, unsigned char *data, unsigned int dataLen);
//正常响应处理，http200错误码
static void response_ok(int client, char *contentType, unsigned char *data, unsigned int dataLen);
//请求异常处理，http400错误码
static void bad_request(int); // 无效请求
//服务端异常处理，http500错误码
static void cannot_execute(int);
//请求url路由未找到处理，http404错误码
static void not_found(int);
//服务端未实现请求方法处理，http501错误码
static void unimplemented(int);
//打印请求
static void printRequest(request *req);
//打印响应
static void printResponse(response *resp);
//释放请求内存
static void releaseRequest(request *req);
//释放响应内存
static void releaseResponse(response *resp);

static pthread_t clientThread;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static struct route_handler *globalRoute;

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
// 接收客户端的连接，并读取请求数据
static void *accept_request(void *from_client)
{
    int client = *(int *) from_client;
    char buf[2048];
    int numchars;
    char method[16];
    size_t i, j = 0;
    request *req = NULL;
    int readFull = 0;
    int code = RESPONSE_STATUS_200;
    route_handler *routeHandler = NULL;
    response *resp = NULL;


    req = calloc(1, sizeof(request));
    if (req == NULL) {
        code = RESPONSE_STATUS_500;
        goto err;
    }
    memset(req, 0, sizeof(request));

    // 获取一行HTTP报文数据
    numchars = get_line(client, buf, sizeof(buf));
    if (numchars < 0) {
        //TODO 根据实际错误码判断
        code = RESPONSE_STATUS_500;
        goto err;
    }
    // 对于HTTP报文来说，第一行的内容即为报文的起始行，格式为<method> <request-URL> <version>，
    // 每个字段用空白字符相连
    while (!ISspace(buf[j]) && (i < sizeof(method) - 1)) {
        // 提取其中的请求方式是GET还是POST
        method[i] = buf[j];
        i++;
        j++;
    }
    method[i] = '\0';
    // 函数说明：strcasecmp()用来比较参数s1 和s2 字符串，比较时会自动忽略大小写的差异。
    // 返回值：若参数s1 和s2 字符串相同则返回0。s1 长度大于s2 长度则返回大于0 的值，s1 长度若小于s2 长度则返回小于0 的值。
    if (strcasecmp(method, "GET") && strcasecmp(method, "POST")) {
        // tinyhttp仅仅实现了GET和POST
        code = RESPONSE_STATUS_501;
        goto err;
    }
    memcpy(req->method, method, strlen(method));

    // 标记post请求
    if (strcasecmp(method, "POST") == 0) {
        req->postReq = 1;
    }

    i = 0;
    // 将method后面的后边的空白字符略过
    while (ISspace(buf[j]) && (j < sizeof(buf))) {
        j++;
    }
    // 继续读取request-URL
    while (!ISspace(buf[j]) && (i < sizeof(req->url) - 1) && (j < sizeof(buf))) {
        req->url[i] = buf[j];
        i++;
        j++;
    }
    req->url[i] = '\0';

    //解析url中的参数
    req->urlParamLine = strstr(req->url, "?");
    if (req->urlParamLine) {
        *req->urlParamLine = '\0';
        req->urlParamLine++;
        if (parse_url_param(req->urlParamLine, req)) {
            code = RESPONSE_STATUS_400;
            goto err;
        }
    }

    // 读取请求头信息和请求体
    while ((numchars = get_line(client, buf, sizeof(buf))) > 0) {
        if (strcmp("\n", buf) == 0) {//post请求体
            //读取请求体
            req->body = (unsigned char *) calloc(1, req->contentLength + 1);
            if (!req->body) {
                code = RESPONSE_STATUS_500;
                goto err;
            }
            memset(req->body, 0, req->contentLength + 1);
            read_body(client, (char *) req->body, req->contentLength);
            break;
        }
        else {
            //解析请求头
            *(buf + strlen(buf) - 1) = '\0';
            if (parse_header(buf, req)) {
                code = RESPONSE_STATUS_400;
                goto err;
            }
        }
    }
    if (numchars < 0) {

        goto err;
    }
    code = RESPONSE_STATUS_200;
    readFull = 1;
    printRequest(req);

    //查询对应路由
    routeHandler = findRoute(req->url);
    if (!routeHandler) {
        code = RESPONSE_STATUS_404;
        goto err;
    }
    resp = routeHandler->hdl(req);
    if (!resp) {
        printf("路由[%s]服务无响应\n", req->url);
        code = RESPONSE_STATUS_500;
        goto err;
    }
    printResponse(resp);
    do_response(client, RESPONSE_STATUS_200, resp->contentType, resp->data, resp->dataLen);
    releaseResponse(resp);

    err:
    if (!readFull) {
        //读取剩余请求并忽略处理
        while ((numchars > 0) && strcmp("\n", buf)) {
            numchars = get_line(client, buf, sizeof(buf));
        }
    }
    if (code != RESPONSE_STATUS_200) {
        do_response(client, code, NULL, NULL, 0);
    }
    releaseRequest(req);
    close(client); // 因为http是面向无连接的，所以要关闭
    return NULL;
}

static route_handler *findRoute(char *route)
{
    route_handler *next = NULL;

    //非空判断
    if (route == NULL) {
        return NULL;
    }

    next = globalRoute;
    while (next) {
        if (strcmp(route, next->route) == 0) {
            return next;
        }
        next = next->next;
    }
    return NULL;
}


/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
// 解析一行http报文
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n')) {
        n = recv(sock, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0) {
            if (c == '\r') {
                n = recv(sock, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else if (n == 0) {
            c = '\n';
        }
        else {
            // TODO 记录异常

            return -1;
        }
    }
    buf[i] = '\0';
//    printf("line: %s\n", buf);
    return (i);
}

static int parse_url_param(char *buf, request *req)
{
    int code = 0;

    char *key = NULL;
    char *val = NULL;
    char *and = NULL;
    request_url_param *urlParam = NULL;

    key = buf;
    val = strstr(key, "=");
    if (!val) {
        code = RESPONSE_STATUS_400;
        goto err;
    }
    *val = '\0';
    val++;

    and = strstr(val, "&");
    if (and) {
        *and = '\0';
    }
    code = url_param_calloc(&urlParam, key, val);
    if (code != 0) {
        goto err;
    }
    req->urlParam = urlParam;

    while (and) {
        key = and + 1;
        val = strstr(key, "=");
        if (!val) {
            code = RESPONSE_STATUS_400;
            goto err;
        }
        *val = '\0';
        val++;

        code = url_param_calloc(&urlParam, key, val);
        if (code != 0) {
            goto err;
        }
        urlParam->next = req->urlParam;
        req->urlParam = urlParam;

        and = strstr(and, "&");
    }

    return 0;
    err:
    return code;
}

static int url_param_calloc(request_url_param **param, char *key, char *val)
{
    int code = 0;
    request_url_param *urlParam = NULL;
    urlParam = calloc(1, sizeof(request_url_param));
    if (!urlParam) {
        code = RESPONSE_STATUS_500;
        goto err;
    }
    memset(urlParam, 0, sizeof(request_url_param));

    urlParam->key = calloc(1, strlen(key) + 1);
    if (!urlParam->key) {
        code = RESPONSE_STATUS_500;
        goto err;
    }
    strcpy(urlParam->key, key);
    urlParam->value = calloc(1, strlen(val) + 1);
    if (!urlParam->value) {
        code = RESPONSE_STATUS_500;
        goto err;
    }
    strcpy(urlParam->value, val);
    *param = urlParam;
    return 0;
    err:
    *param = NULL;
    if (urlParam) {
        if (urlParam->key) {
            free(urlParam->key);
        }
        if (urlParam->value) {
            free(urlParam->value);
        }
        free(urlParam);
    }
    return code;
}

static int read_body(int sock, char *buf, int size)
{
    int nread, left = size;
    while (left > 0) {
        if ((nread = read(sock, buf, left)) == 0) {
            return 0;
        }
        else if (nread < 0) {
            return nread;
        }
        else {
            left -= nread;
            buf += nread;
        }
    }
}

static int parse_header(char *line, request *req)
{
    int code = 0;
    char *key = line;
    char *val = NULL;
    size_t kLen, vLen = 0;
    request_header *header = NULL;


    val = strstr(line, ":");
    if (!val) {
        code = RESPONSE_STATUS_400;
        goto err;
    }

    *val = '\0';
    val++;
    //去除value前的空格
    while (ISspace(*val)) {
        val++;
    }

    header = (request_header *) calloc(1, sizeof(request_header));
    if (!header) {
        code = RESPONSE_STATUS_500;
        goto err;
    }
    memset(header, 0, sizeof(request_header));

    kLen = strlen(key);
    header->key = (char *) calloc(1, kLen + 1);
    if (!header->key) {
        code = RESPONSE_STATUS_500;
        goto err;
    }
    memset(header->key, 0, kLen + 1);
    strcpy(header->key, key);

    vLen = strlen(val);
    header->value = (char *) calloc(1, vLen + 1);
    if (!header->value) {
        code = RESPONSE_STATUS_500;
        goto err;
    }
    memset(header->value, 0, vLen + 1);
    strcpy(header->value, val);
    if (strcasecmp(header->key, "content-type") == 0) {
        req->contentType = header->value;
    }
    if (strcasecmp(key, "Content-Length") == 0) {
        req->contentLength = atoi(val);
        if (req->contentLength == 0 && strcmp(val, "0") != 0) {
            code = RESPONSE_STATUS_400;
            goto err;
        }
    }

    if (req->header) {
        header->next = req->header;
    }
    req->header = header;

    return 0;
    err:
    if (header) {
        if (header->key) {
            free(header->key);
        }
        if (header->value) {
            free(header->value);
        }
        free(header);
    }
    return code;
}



/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
static void do_response(int client, int code, char *contentType, unsigned char *data, unsigned int dataLen)
{
    if (code == RESPONSE_STATUS_200) {
        response_ok(client, contentType, data, dataLen);
    }
    else if (code == RESPONSE_STATUS_400) {
        bad_request(client);
    }
    else if (code == RESPONSE_STATUS_404) {
        not_found(client);
    }
    else if (code == RESPONSE_STATUS_500) {
        cannot_execute(client);
    }
    else if (code == RESPONSE_STATUS_501) {
        unimplemented(client);
    }
    else {

    }
}

static void response_ok(int client, char *contentType, unsigned char *data, unsigned int dataLen)
{
    printf("send 200 response_ok\n");

    char buf[1024];
    // 发送HTTP头
    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: %s\r\n", contentType);
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    send(client, data, dataLen, 0);
}



/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
static void bad_request(int client)
{
    printf("send 400 bad_request\n");
    char buf[1024];
    // 发送400
    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "check your head, body or url param.\r\n");
    send(client, buf, sizeof(buf), 0);
}


/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
static void cannot_execute(int client)
{
    printf("send 500 cannot_execute\n");
    char buf[1024];
    // 发送500
    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
static void not_found(int client)
{
    printf("send 404 not_found\n");
    char buf[1024];
    // 返回404
    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>404 Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>404 Not Found.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</P></BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}


/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
static void unimplemented(int client)
{
    printf("send 501 unimplemented\n");

    char buf[1024];
    // 发送501说明相应方法没有实现
    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

void printRequest(request *req)
{
    request_url_param *urlParam = NULL;
    request_header *header = NULL;
    printf("Request: \n");
    printf("\tmethod: %s\n", req->method);
    printf("\turl: %s\n", req->url);
    if (req->urlParam) {
        printf("\turl-param:\n");
        urlParam = req->urlParam;
        while (urlParam) {
            printf("\t\t%s=%s\n", urlParam->key, urlParam->value);
            urlParam = urlParam->next;
        }
    }
    if (req->header) {
        printf("\theader:\n");
        header = req->header;
        while (header) {
            printf("\t\t%s:%s\n", header->key, header->value);
            header = header->next;
        }
    }
//    printf("\turlParamLine: %s\n", req->urlParamLine);
    printf("\tContent-Type: %s\n", req->contentType);
    printf("\tContent-Length: %d\n", req->contentLength);

    if (req->postReq && req->contentLength > 0) {
        printf("\tbody:%s\n", req->body);
    }
}

static void printResponse(response *resp)
{
    printf("Response: \n");
    printf("\tContent-Type: %s\n", resp->contentType);
    printf("\tContent-Length: %d\n", resp->dataLen);
    if (strcasecmp(resp->contentType, "application/json") == 0 ||
        strcasecmp(resp->contentType, "text/plain") == 0) {
        printf("\tContent: %s\n", resp->data);
    }
}

void releaseRequest(request *req)
{
    request_url_param *urlParam = NULL;
    request_header *header = NULL;

    if (!req) {
        return;
    }
    while (req->urlParam) {
        urlParam = req->urlParam;
        req->urlParam = urlParam->next;
        if (urlParam->key) {
            free(urlParam->key);
        }
        if (urlParam->value) {
            free(urlParam->value);
        }
        free(urlParam);
    }
    while (req->header) {
        header = req->header;
        req->header = header->next;
        if (header->key) {
            free(header->key);
        }
        if (header->value) {
            free(header->value);
        }
        free(header);
    }

    if (req->body) {
        free(req->body);
    }

    free(req);
}

static void releaseResponse(response *resp)
{
    if (!resp) {
        return;
    }
    if (resp->contentType) {
        free(resp->contentType);
    }
    if (resp->data) {
        free(resp->data);
    }
    free(resp);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
// 启动服务端
static int createServer(u_short *port)
{
    int server = 0;
    struct sockaddr_in name;
    // 设置http socket
    server = socket(PF_INET, SOCK_STREAM, 0);
    if (server == -1) {
        goto err;
    }
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(*port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    // 绑定端口
    if (bind(server, (struct sockaddr *) &name, sizeof(name)) < 0) {
        goto err;
    }
    if (*port == 0) /*动态分配一个端口 */
    {
        socklen_t namelen = sizeof(name);
        if (getsockname(server, (struct sockaddr *) &name, &namelen) == -1) {
            goto err;
        }
        *port = ntohs(name.sin_port);
    }
    // 监听连接
    if (listen(server, 5) < 0) {
        goto err;
    }
    return (server);
    err:
    return -1;
}

static void *startWebThread(void *serverAddr)
{
    int server = *(int *) serverAddr;
    int client_fd = -1;
    struct sockaddr_in client;
    char ipAddress[INET_ADDRSTRLEN];
    socklen_t client_name_len = sizeof(client);

    while (1) {
        // 接受客户端连接
        client_fd = accept(server,
                           (struct sockaddr *) &client,
                           &client_name_len);
        if (client_fd == -1) {
            continue;
        }
        memset(ipAddress, 0, sizeof(ipAddress));
        inet_ntop(AF_INET, (void *) &(client.sin_addr), ipAddress, INET_ADDRSTRLEN);
        printf("accept request: %s:%d\n", ipAddress, client.sin_port);
        /*启动线程处理新的连接 */
        if (pthread_create(&clientThread, NULL, accept_request, (void *) &client_fd) != 0) {

        }
    }
    return NULL;
}

response *createResponse(char *contentType, unsigned char *data, unsigned int dataLen)
{
    response *resp = NULL;

    if (!contentType || !data || dataLen <= 0) {
        return NULL;
    }
    resp = (response *) calloc(1, sizeof(response));
    if (!resp) {
        return NULL;
    }
    memset(resp, 0, sizeof(response));

    resp->contentType = (char *) calloc(1, strlen(contentType) + 1);
    if (!resp->contentType) {
        free(resp);
        return NULL;
    }
    memset(resp->contentType, 0, strlen(contentType) + 1);
    memcpy(resp->contentType, contentType, strlen(contentType));

    resp->data = (unsigned char *) calloc(1, dataLen + 1);
    if (!resp->data) {
        free(resp->contentType);
        free(resp);
        return NULL;
    }
    memset(resp->data, 0, dataLen + 1);
    memcpy(resp->data, data, dataLen);
    resp->dataLen = dataLen;

    return resp;
}

int addRoute(const char *route, handler *hdl)
{
    struct route_handler *routeHandler = NULL;

    pthread_mutex_lock(&mutex);

    if (route == NULL || hdl == NULL) {
        goto err;
    }
    routeHandler = (struct route_handler *) calloc(1, sizeof(struct route_handler));
    if (!routeHandler) {
        goto err;
    }
    memset(routeHandler, 0, sizeof(struct route_handler));

    routeHandler->route = (char *) calloc(1, strlen(route) + 1);
    if (!routeHandler->route) {
        goto err;
    }
    memset(routeHandler->route, 0, strlen(route) + 1);
    memcpy(routeHandler->route, route, strlen(route));

    routeHandler->hdl = hdl;
    if (!globalRoute) {
        globalRoute = routeHandler;
    }
    else {
        routeHandler->next = globalRoute;
        globalRoute = routeHandler;
    }
    pthread_mutex_unlock(&mutex);
    return 0;
    err:
    if (routeHandler) {
        if (routeHandler->route) {
            free(routeHandler->route);
        }
        free(routeHandler);
    }
    pthread_mutex_unlock(&mutex);
    return -1;
}

/**
 * 释放路由
 */
void releaseRoute()
{
    struct route_handler *routeHandler = NULL;

    pthread_mutex_lock(&mutex);
    routeHandler = globalRoute;

    while (routeHandler) {
        if (routeHandler->route) {
            free(routeHandler->route);
        }
        free(routeHandler);
        globalRoute = globalRoute->next;
        routeHandler = globalRoute;
    }

    pthread_mutex_unlock(&mutex);
}

int startUp(u_short port)
{
    int server_sock = -1;

    pthread_t webThread;

    // 启动server socket
    server_sock = createServer(&port);
    if (server_sock <= 0) {
        return -1;
    }
    printf("cweb running on port %d\n", port);
    /*服务主线程*/
    if (pthread_create(&webThread, NULL, startWebThread, (void *) &server_sock) != 0) {
        printf("start web thread fail");
        return -1;
    }
    return server_sock;
}

#ifdef __cplusplus
}
#endif