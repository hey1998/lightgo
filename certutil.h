#ifndef __CERTUTIL_H__
#define __CERTUTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

static int add_ext(X509*, int, char*);
static int dump_ca();

#ifdef __cplusplus
}
#endif

#endif /* __CERTUTIL_H__ */
