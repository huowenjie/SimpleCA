#include "sca_inner.h"

#include <sca_error.h>
#include <sca_trace.h>

/*===========================================================================*/

SCA_CERT_SIG_REQ *sca_csr_create()
{
    struct sca_cert_sig_req *ret = malloc(sizeof(*ret));
    X509_REQ *req = X509_REQ_new();

    X509_REQ_set_version(req, 0);

    ret->req = req;
    return ret;
}

SCA_CERT_SIG_REQ *sca_csr_load(const char *file)
{
    FILE *fp = NULL;
    SCA_CERT_SIG_REQ *ret = NULL;
    X509_REQ *req = NULL;

    if (!file || !*file) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return NULL;
    }

    fp = fopen(file, "r");
    if (!fp) {
        SCA_TRACE_ERROR("打开文件失败！");
        return NULL;
    }

    req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
    if (!req) {
        SCA_TRACE_ERROR("解析证书请求失败！");
        goto end;
    }

    ret = malloc(sizeof(*ret));
    memset(ret, 0, sizeof(*ret));

    ret->req = req;

end:

    fclose(fp);
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
        return SCA_ERR_FAILED;
    }

    return SCA_ERR_SUCCESS;
}

int sca_csr_get_subject_count(SCA_CERT_SIG_REQ *csr)
{
    X509_NAME *dn = NULL;

    if (!csr || !csr->req) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return 0;
    }

    dn = X509_REQ_get_subject_name(csr->req);
    if (!dn) {
        SCA_TRACE_ERROR("主题项不存在！");
        return 0;
    }

    return X509_NAME_entry_count(dn);
}

int sca_csr_enum_subject(SCA_CERT_SIG_REQ *csr, int index, struct sca_data *dn)
{
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *elem = NULL;
    ASN1_STRING *data = NULL;

    if (!csr || !csr->req) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    if (!dn) {
        SCA_TRACE_ERROR("必须有出参！");
        return SCA_ERR_NULL_PARAM;
    }

    if (index < 0) {
        SCA_TRACE_ERROR("index 参数错误！");
        return SCA_ERR_PARAM;
    }

    name = X509_REQ_get_subject_name(csr->req);
    if (!name) {
        SCA_TRACE_ERROR("主题项不存在！");
        return SCA_ERR_NULL_POINTER;
    }

    elem = X509_NAME_get_entry(name, index);
    if (!elem) {
        SCA_TRACE_ERROR("主题项不存在！");
        return SCA_ERR_NULL_POINTER;
    }

    data = X509_NAME_ENTRY_get_data(elem);
    if (!elem) {
        SCA_TRACE_ERROR("数据不存在！");
        return SCA_ERR_NULL_POINTER;
    }

    if (!dn->value) {
        dn->size = data->length + 1;
        return SCA_ERR_SUCCESS;
    }

    if (dn->size <= data->length) {
        SCA_TRACE_ERROR("缓冲区内存不足！");
        return SCA_ERR_FAILED;
    }

    memcpy(dn->value, data->data, data->length);
    dn->value[data->length] = '\0';
    dn->size = data->length + 1;

    return SCA_ERR_SUCCESS;
}

int sca_csr_get_subject_name(SCA_CERT_SIG_REQ *csr, const char *field, struct sca_data *dn)
{
    X509_NAME *name = NULL;
    ASN1_OBJECT *obj = NULL;
    int ret = SCA_ERR_SUCCESS;
    int len = 0;

    if (!csr || !csr->req) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    if (!field || !*field) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    if (!dn) {
        SCA_TRACE_ERROR("必须有出参！");
        return SCA_ERR_NULL_PARAM;
    }

    name = X509_REQ_get_subject_name(csr->req);
    if (!name) {
        SCA_TRACE_ERROR("主题项不存在！");
        return SCA_ERR_NULL_POINTER;
    }

    obj = OBJ_txt2obj(field, 0);
    if (!obj) {
        SCA_TRACE_ERROR("%s 对象不存在！", field);
        return SCA_ERR_NULL_POINTER;
    }

    len = X509_NAME_get_text_by_OBJ(name, obj, NULL, 0);
    if (len < 0) {
        SCA_TRACE_ERROR("对象不存在！");
        ret = SCA_ERR_NULL_POINTER;
        goto end;
    }

    if (!dn->value) {
        dn->size = len;
        goto end;
    }

    if (dn->size < len) {
        SCA_TRACE_ERROR("缓冲区内存不足！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (X509_NAME_get_text_by_OBJ(name, obj, (char *)dn->value, dn->size) != len) {
        SCA_TRACE_ERROR("获取 Subject 内容失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

end:
    if (obj) {
        ASN1_OBJECT_free(obj);
    }
    return ret;
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

SCA_KEY *sca_csr_get_pubkey(SCA_CERT_SIG_REQ *csr)
{
    SCA_KEY *ret = NULL;
    EVP_PKEY *pkey = NULL;

    if (!csr || !csr->req) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return NULL;
    }

    pkey = X509_REQ_get_pubkey(csr->req);
    if (!pkey) {
        SCA_TRACE_ERROR("公钥不存在！");
        return NULL;
    }

    pkey = EVP_PKEY_dup(pkey);
    if (!pkey) {
        SCA_TRACE_ERROR("公钥拷贝失败！");
        return NULL;
    }

    ret = malloc(sizeof(*ret));
    memset(ret, 0, sizeof(*ret));
    ret->pkey = pkey;

    return ret;
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

int sca_csr_verify(SCA_CERT_SIG_REQ *csr, SCA_KEY *key)
{
    X509_REQ *req = NULL;
    EVP_PKEY *pub = NULL;
    int ret = SCA_ERR_SUCCESS;

    if (!csr || !csr->req) {
        SCA_TRACE_ERROR("参数为 NULL！");
        return SCA_ERR_NULL_PARAM;
    }

    req = csr->req;

    if (!key) {
        pub = X509_REQ_get_pubkey(req);
    } else {
        pub = key->pkey;
    }

    if (!pub) {
        SCA_TRACE_ERROR("获取公钥失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (X509_REQ_verify(req, pub) != 1) {
        SCA_TRACE_ERROR("验签失败！");
        ret = SCA_ERR_FAILED;
    }

end:
    if (!key && pub) {
        EVP_PKEY_free(pub);
    }
    return ret;
}

int sca_csr_enc(SCA_CERT_SIG_REQ *csr, const char *file)
{
    X509_REQ *req = NULL;
    FILE *fp = NULL;
    int ret = SCA_ERR_SUCCESS;

    if (!csr || !csr->req) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!file || !*file) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    req = csr->req;
    fp = fopen(file, "w");

    if (!fp) {
        SCA_TRACE_ERROR("文件创建失败\n");
        return SCA_ERR_FAILED;
    }

    if (PEM_write_X509_REQ(fp, req) != 1) {
        SCA_TRACE_ERROR("PEM 编码失败");
        ret = SCA_ERR_FAILED;
    }

    if (fp) {
        fflush(fp);
        fclose(fp);
    }
    return ret;
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
