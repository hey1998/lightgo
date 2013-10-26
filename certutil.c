#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "certutil.h"

#define CA_VENDOR "GoAgent CA"
#define CA_KEYFILE "CA.crt"
#define CA_CERTDIR "certs"

static int add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;
    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}

static int dump_ca()
{
    FILE* file = NULL;
    RSA* rsa = NULL;
    EVP_PKEY* key = EVP_PKEY_new();
    X509* ca = X509_new();
    X509_NAME* name = NULL;
    if ((rsa = RSA_generate_key(2048, 0x10001, NULL, NULL)) == NULL)
        return -1;
    if (!EVP_PKEY_assign_RSA(key, rsa))
        return -1;
    X509_set_version(ca, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca), 0);
    X509_gmtime_adj(X509_get_notBefore(ca), 0);
    X509_gmtime_adj(X509_get_notAfter(ca), (long)60*60*24*3652);
    X509_set_pubkey(ca, key);
    name = X509_get_subject_name(ca);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, CA_VENDOR, -1, -1, 0);
    X509_set_issuer_name(ca, name);
    /* Add various extensions: standard extensions */
    add_ext(ca, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(ca, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_ext(ca, NID_subject_key_identifier, "hash");
    /* Some Netscape specific extensions */
    add_ext(ca, NID_netscape_cert_type, "sslCA");
    if (!X509_sign(ca, key, EVP_sha1()))
        return -1;
    if ((file = fopen(CA_KEYFILE, "wb")) == NULL)
        return -1;
    PEM_write_X509(file, ca);
    PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL);
    fclose(file);
    X509_free(ca);
    EVP_PKEY_free(key);
    return 0;
}

static int _get_cert(unsigned char* commonname)
{
    FILE* file = NULL;
    RSA* rsa = NULL;
    EVP_PKEY* key = NULL;
    X509* ca = NULL;
    EVP_PKEY* pkey = EVP_PKEY_new();
    X509_REQ* req = X509_REQ_new();
    X509_NAME *name = NULL;
    X509* cert = X509_new();
    if ((file = fopen(CA_KEYFILE, "rb")) == NULL)
        return -1;
    if ((ca = PEM_read_X509(file, NULL, NULL, NULL)) == NULL
        || (key = PEM_read_PrivateKey(file, NULL, NULL, NULL)) == NULL)
        return -1;
    fclose(file);
    if ((rsa = RSA_generate_key(2048, 0x10001, NULL, NULL)) == NULL)
        return -1;
    if (!EVP_PKEY_assign_RSA(pkey, rsa))
        return -1;
    name = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, commonname, -1, -1, 0);
    X509_REQ_set_pubkey(req, pkey);
    if (!X509_REQ_sign(req, pkey, EVP_sha1()))
        return -1;
    X509_set_version(cert, 2);

    return 0;
}
