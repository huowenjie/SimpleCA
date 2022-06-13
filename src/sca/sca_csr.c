#include <openssl/x509.h>
#include <sca_error.h>
#include <sca_trace.h>
#include <sca_csr.h>

/*===========================================================================*/

/* 直接采用 Openssl 的实现方案 */
struct sca_cert_sig_req
{
    X509_REQ *req;
};

SCA_CERT_SIG_REQ *sca_csr_create()
{
    struct sca_cert_sig_req *ret = malloc(sizeof(*ret));
    X509_REQ *req = X509_REQ_new();
    
    ret->req = req;
    return ret;
}

int sca_csr_set_subject(SCA_CERT_SIG_REQ *csr, const char *field, const struct sca_data *dn)
{
    X509_NAME *name = NULL;

    if (!csr || !field || !dn) {
        SCA_TRACE_ERROR("参数为 NULL");
        return SCA_ERR_NULL_PARAM;
    }

    if (!csr->req) {
        SCA_TRACE_ERROR("证书请求对象为 NULL");
        return SCA_ERR_NULL_PARAM;
    }

    name = X509_REQ_get_subject_name(csr->req);
    if (!name) {
        X509_NAME *tmp = X509_NAME_new();

        /* 这个会拷贝一份 X509_NAME 对象 */
        X509_REQ_set_subject_name(csr->req, tmp);
        name = X509_REQ_get_subject_name(csr->req);

        X509_NAME_free(tmp);
    }

    if (X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8, dn->value, dn->size, -1, 0) != 1) {
        SCA_TRACE_ERROR("添加信息失败！");
        return SCA_ERR_NULL_PARAM;
    }

    return SCA_ERR_SUCCESS;
}

int sca_csr_set_pubkey(SCA_CERT_SIG_REQ *csr, SCA_KEY *key)
{
    X509_REQ *req = NULL;
    EVP_PKEY *pkey = NULL;

    if (!csr || !key) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    if (!csr->req) {
        SCA_TRACE_ERROR("证书请求对象为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    req = csr->req;
    pkey = (EVP_PKEY *)sca_get_key_obj(key);

    if (X509_REQ_set_pubkey(req, pkey) != 1) {
        SCA_TRACE_ERROR("设置公钥失败！");
        return SCA_ERR_FAILED;
    }

    return 0;
}

int sca_csr_sign(SCA_CERT_SIG_REQ *csr, const char *sign, const char *md, SCA_KEY *key)
{
    if (!csr || !key) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    return SCA_ERR_SUCCESS;
}

int sca_csr_enc(SCA_CERT_SIG_REQ *csr, const char *file)
{
    return 0;
}

void sca_csr_destroy(SCA_CERT_SIG_REQ *csr)
{
    if (csr) {
        if (csr->req) {
            X509_REQ_free(csr->req);
        }
        free(csr);
    }
}

/*===========================================================================*/
