#ifndef __COMMON_H__
#define __COMMON_H__

/* Make this header file easier to include in C++ code */
#ifdef __cplusplus
extern "C" {
#endif

static char* rstrip(char*);
static char* lskip(const char*);
static char* find_char_or_comment(const char*, char);
static int ini_parse_file(FILE*, const unsigned char*, const unsigned char*, unsigned char*);
static void config_get(FILE*, const unsigned char*, const unsigned char*, unsigned char*);
static void config_getint(FILE*, const unsigned char*, const unsigned char*, unsigned int*);
static int ini_parse(const char*);
static int info(const char*);


#ifdef __cplusplus
}
#endif

#endif /* __COMMON_H__ */
