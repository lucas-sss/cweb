#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "cweb.h"

response *test(request *req)
{
//    response *resp = createResponse("text/plain", (unsigned char *)"123", 3);
    return createResponse("text/plain", (unsigned char *) "123", 3);;
}
int main()
{
    addRoute("/test", test);
    startUp((u_short) 42112);

    sleep(36000);
    return 0;
}
