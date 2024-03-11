//
// Created by 刘伟 on 2024/3/8.
//

#ifndef CWEB_H
#define CWEB_H

#define RESPONSE_STATUS_501 501
#define RESPONSE_STATUS_500 500
#define RESPONSE_STATUS_404 404
#define RESPONSE_STATUS_400 400
#define RESPONSE_STATUS_200 500

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _request_url_param request_url_param;

struct _request_url_param
{
    char *key;
    char *value;
    request_url_param *next;
};

typedef struct _request_header request_header;

struct _request_header
{
    char *key;
    char *value;
    request_header *next;
};

typedef struct
{
    char method[8];
    int postReq;
    char url[2048];
    char *urlParamLine;
    char *contentType;
    int contentLength;

    //url请求参数
    request_url_param *urlParam;
    //所有请求头
    request_header *header;
    //请求体
    unsigned char *body;
} request;

typedef struct
{
    char *contentType;
    unsigned char *data;
    unsigned int dataLen;
} response;

//请求处理函数
typedef response *(handler)(request *);

/**
 * 创建响应（释放由cweb自动释放）
 *
 * @param contentType   响应类型
 * @param data          响应数据
 * @param dataLen       响应数据长度
 * @return
 */
response *createResponse(char *contentType, unsigned char *data, unsigned int dataLen);

/**
 * 添加路由
 *
 * @param route  路由名称（请求url，不包含参数）
 * @param hdl    路由处理函数
 * @return
 */
int addRoute(const char *route, handler *hdl);

/**
 * 释放路由
 */
void releaseRoute();

/**
 * 启动服务（以线程方式启动，不会阻塞）
 *
 * @param port 服务端口
 * @return
 */
int startUp(u_short port);

#ifdef __cplusplus
}
#endif

#endif //CWEB_H
