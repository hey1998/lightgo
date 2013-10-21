#include <stdio.h>
#include <event.h>
#include <evhttp.h>

void do_METHOD(struct evhttp_request *req, struct evbuffer *buf)
{
	struct evhttp_uri *uri = evhttp_request_get_evhttp_uri(const struct evhttp_request *req);
	char *host = evhttp_uri_get_host(uri);
	char *path = evhttp_uri_get_path(uri);
}

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
