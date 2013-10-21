#include <stdio.h>
#include <event.h>
#include <evhttp.h>

void GAEProxyHandler(struct evhttp_request *req, void *arg)
{
	struct evbuffer *buf;
	buf = evbuffer_new();
	if (buf == NULL)
		printf("failed to create response buffer");
	do_METHOD(req, buf);
	evhttp_send_reply(req, HTTP_OK, "OK", buf);
}

int main(int argc, char **argv)
{
	struct evhttp *httpd;
	event_init();
	httpd = evhttp_start("127.0.0.1", 8080);
	evhttp_set_gencb(httpd, GAEProxyHandler, NULL);
	event_dispatch();
	evhttp_free(httpd);
	return 0;
}
