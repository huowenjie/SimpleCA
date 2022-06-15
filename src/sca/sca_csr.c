#include "sca_inner.h"

#include <sca_error.h>
#include <sca_trace.h>

/*===========================================================================*/

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
    pkey = key->pkey;

    if (X509_REQ_set_pubkey(req, pkey) != 1) {
        SCA_TRACE_ERROR("设置公钥失败！");
        return SCA_ERR_FAILED;
    }

    return 0;
}

int sca_csr_sign(SCA_CERT_SIG_REQ *csr, enum SCA_MD_ALGO md, SCA_KEY *key)
{
    X509_REQ *req = NULL;
    EVP_PKEY *pkey = NULL;
    const EVP_MD *digest = NULL;

    int pkid = EVP_PKEY_NONE;
    int ret = SCA_ERR_SUCCESS;

    X509_ALGOR *sig_algo = NULL;
    ASN1_OBJECT *sig_obj = NULL;

    if (!csr || !key) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    if (!csr->req) {
        SCA_TRACE_ERROR("证书请求对象为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    req = csr->req;
    pkey = key->pkey;

    switch (md) {
        case SCA_MD_MD5: digest = EVP_md5(); break;
        case SCA_MD_SHA1: digest = EVP_sha1(); break;
        case SCA_MD_SHA256: digest = EVP_sha256(); break;
        default:
            SCA_TRACE_ERROR("不支持这个摘要算法 %d！", (int)md);
            return SCA_ERR_FAILED;
    }

    sig_algo = X509_ALGOR_new();

    pkid = EVP_PKEY_get_base_id(key->pkey);
    switch (pkid) {
        case EVP_PKEY_RSA:
            switch (md) {
                case SCA_MD_MD5: sig_obj = OBJ_nid2obj(NID_md5WithRSAEncryption); break;
                case SCA_MD_SHA1:   sig_obj = OBJ_nid2obj(NID_sha1WithRSAEncryption); break;
                case SCA_MD_SHA256: sig_obj = OBJ_nid2obj(NID_sha256WithRSAEncryption); break;
            }
            break;
        case EVP_PKEY_EC:
            switch (md) {
                case SCA_MD_SHA1:   sig_obj = OBJ_nid2obj(NID_ecdsa_with_SHA1); break;
                case SCA_MD_SHA256: sig_obj = OBJ_nid2obj(NID_ecdsa_with_SHA256); break;
                default:
                    SCA_TRACE_ERROR("ECDSA 签名算法不支持和 md5 摘要");
                    ret = SCA_ERR_FAILED;
                    goto end;
            }
            break;
        case EVP_PKEY_NONE:
        default:
            SCA_TRACE_ERROR("不支持该公钥算法 %d", (int)pkid);
            ret = SCA_ERR_FAILED;
            goto end;
    }

    if (X509_ALGOR_set0(sig_algo, sig_obj, V_ASN1_OBJECT, NULL) != 1) {
        SCA_TRACE_ERROR("设置签名算法失败");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (X509_REQ_set1_signature_algo(req, sig_algo) != 1) {
        SCA_TRACE_ERROR("证书请求设置签名算法失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (!X509_REQ_sign(req, pkey, digest)) {
        SCA_TRACE_ERROR("签名失败！");
        ret = SCA_ERR_FAILED;
    }

end:

    if (sig_algo) {
        X509_ALGOR_free(sig_algo);
    }
    return ret;
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
