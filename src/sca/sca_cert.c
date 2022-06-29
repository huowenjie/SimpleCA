#include <sca_cert.h>
#include <sca_trace.h>
#include <openssl/x509v3.h>

#include "sca_inner.h"

/*===========================================================================*/

SCA_CERT *sca_cert_create()
{
    X509 *cer = X509_new();
    SCA_CERT *ret = malloc(sizeof(*ret));

    X509_set_version(cer, 3);

    ret->cert = cer;
    ret->req_algo = NULL;
    return ret;
}

void sca_cert_destroy(SCA_CERT *cert)
{
    if (cert) {
        if (cert->cert) {
            X509_free(cert->cert);
        }

        if (cert->req_algo) {
            X509_ALGOR_free(cert->req_algo);
        }

        free(cert);
    }
}

SCA_CERT *sca_cert_load(const char *file)
{
    FILE *fp = NULL;
    SCA_CERT *ret = NULL;
    X509 *cer = NULL;

    if (!file || !*file) {
        SCA_TRACE_ERROR("文件名不能为空！");
        return NULL;
    }

    fp = fopen(file, "r");
    if (!fp) {
        SCA_TRACE_ERROR("读取证书失败！");
        return NULL;
    }

    cer = PEM_read_X509(fp, NULL, NULL, NULL);
    if (!cer) {
        SCA_TRACE_ERROR("解析证书失败！");
        goto end;
    }

    ret = malloc(sizeof(*ret));
    ret->cert = cer;
    ret->req_algo = NULL;

end:
    if (fp) {
        fclose(fp);
    }

    return ret;
}

/*
 * 证书请求可导入证书的信息有
 * （1）请求者的用户主题信息
 * （2）请求者的主题公钥信息，和其私钥相对应
 * （3）其他属性
 */
int sca_cert_import_csr(SCA_CERT *cert, SCA_CERT_SIG_REQ *req)
{
    X509 *cer = NULL;
    X509_REQ *cer_req = NULL;
    X509_NAME *subject = NULL;
    EVP_PKEY *pubkey = NULL;

    X509_ALGOR *sig_algo = NULL;
    ASN1_OBJECT *sig_obj = NULL;
    int sig_nid = 0;

    if (!cert || !req) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    cer = cert->cert;
    cer_req = req->req;

    if (!cer || !cer_req) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    subject = X509_REQ_get_subject_name(cer_req);
    if (!subject) {
        SCA_TRACE_ERROR("证书请求主题项不存在！");
        return SCA_ERR_FAILED;
    }

    pubkey = X509_REQ_get_pubkey(cer_req);
    if (!subject) {
        SCA_TRACE_ERROR("证书请求用户公钥不存在！");
        return SCA_ERR_FAILED;
    }

    if (X509_set_subject_name(cer, subject) != 1) {
        SCA_TRACE_ERROR("设置证书主题失败！");
        return SCA_ERR_FAILED;
    }

    if (X509_set_pubkey(cer, pubkey) != 1) {
        SCA_TRACE_ERROR("设置证书公钥失败！");
        return SCA_ERR_FAILED;
    }

    sig_nid = X509_REQ_get_signature_nid(cer_req);
    sig_obj = OBJ_nid2obj(sig_nid);
    if (!sig_obj) {
        SCA_TRACE_ERROR("当前系统并不支持该算法！");
        return SCA_ERR_NULL_POINTER;
    }

    sig_algo = X509_ALGOR_new();

    if (X509_ALGOR_set0(sig_algo, sig_obj, V_ASN1_OBJECT, NULL) != 1) {
        SCA_TRACE_ERROR("设置签名算法失败");

        X509_ALGOR_free(sig_algo);
        return SCA_ERR_FAILED;
    }

    cert->req_algo = sig_algo;
    return SCA_ERR_SUCCESS;
}

int sca_cert_gen_serial(SCA_CERT *cert)
{
    ASN1_INTEGER *serial = NULL;

    BN_CTX *ctx = NULL;
    BIGNUM *num = NULL;
    BIGNUM *min = NULL;
    BIGNUM *max = NULL;
    int ret = SCA_ERR_SUCCESS;
    
    if (!cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    num = BN_CTX_get(ctx);
    min = BN_CTX_get(ctx);
    max = BN_CTX_get(ctx);

    BN_hex2bn(&min, "1000000000");
    BN_hex2bn(&max, "FFFFFFFFFFFFFFFFFFFF");

    /* 确定序列号的大小后，随机生成序列号 */
    while (1) {
        if (BN_rand_range(num, max) != 1) {
            SCA_TRACE_ERROR("生成随机数失败！");
            ret = SCA_ERR_FAILED;
            goto end;
        }

        if ((BN_cmp(min, num) < 0) && (BN_num_bytes(num) <= 20)) {
            break;
        }
    }

    serial = BN_to_ASN1_INTEGER(num, NULL);
    if (!serial) {
        SCA_TRACE_ERROR("获取证书序列号失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (X509_set_serialNumber(cert->cert, serial) != 1) {
        SCA_TRACE_ERROR("设置证书序列号失败！");
        ret = SCA_ERR_FAILED;
    }

end:
    if (serial) {
        ASN1_INTEGER_free(serial);
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

int sca_cert_set_serial(SCA_CERT *cert, const struct sca_data *serial)
{
    ASN1_INTEGER *tmp = NULL;

    BN_CTX *ctx = NULL;
    BIGNUM *num = NULL;
    BIGNUM *min = NULL;
    BIGNUM *max = NULL;
    int ret = SCA_ERR_SUCCESS;
    
    if (!cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!serial || !serial->value) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (serial->size <= 0) {
        SCA_TRACE_CODE(SCA_ERR_PARAM);
        return SCA_ERR_PARAM;
    }

    ctx = BN_CTX_new();
    BN_CTX_start(ctx);

    num = BN_CTX_get(ctx);
    min = BN_CTX_get(ctx);
    max = BN_CTX_get(ctx);

    BN_hex2bn(&min, "1000000000");
    BN_hex2bn(&max, "FFFFFFFFFFFFFFFFFFFF");
    BN_bin2bn(serial->value, serial->size, num);

    if (BN_num_bytes(num) > 20) {
        SCA_TRACE_ERROR("序列号长度不符合规范！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (BN_cmp(num, min) < 0) {
        SCA_TRACE_ERROR("当前序列号太小！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (BN_cmp(num, max) > 0) {
        SCA_TRACE_ERROR("当前序列号太大！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    tmp = BN_to_ASN1_INTEGER(num, NULL);
    if (!tmp) {
        SCA_TRACE_ERROR("获取证书序列号失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (X509_set_serialNumber(cert->cert, tmp) != 1) {
        SCA_TRACE_ERROR("设置证书序列号失败！");
        ret = SCA_ERR_FAILED;
    }

end:
    if (tmp) {
        ASN1_INTEGER_free(tmp);
    }

    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ret;
}

int sca_cert_get_serial(SCA_CERT *cert, int format, struct sca_data *serial)
{
    X509 *cer = NULL;
    ASN1_INTEGER *num = NULL;
    int ret = SCA_ERR_SUCCESS;

    if (!cert || !cert->cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    cer = cert->cert;

    num = X509_get_serialNumber(cer);
    if (!num) {
        SCA_TRACE_ERROR("没有设置序列号或序列号不存在！");
        return SCA_ERR_NULL_POINTER;
    }

    if (format) {
        BIGNUM *val = NULL;
        char *hex = NULL;
        int len = 0;

        if (!serial->value) {
            serial->size = 21;
            return SCA_ERR_SUCCESS;
        }

        if (serial->size < 21) {
            SCA_TRACE_ERROR("缓冲区太小！");
            return SCA_ERR_FAILED;
        }

        val = BN_new();

        ASN1_INTEGER_to_BN(num, val);
        hex = BN_bn2hex(val);
        if (!hex) {
            SCA_TRACE_ERROR("获取整数序列号失败！");
            ret = SCA_ERR_FAILED;
            goto err;
        }

        len = (int)strlen(hex) + 1;

        if (len > serial->size) {
            SCA_TRACE_ERROR("证书的序列号长度过长，请检查！");
            ret = SCA_ERR_FAILED;
            goto err;
        }

        memcpy(serial->value, hex, len);
        serial->size = len;

err:
        if (hex) {
            OPENSSL_free(hex);
        }
        BN_free(val);
    } else {
        if (!serial->value) {
            serial->size = num->length;
            return SCA_ERR_SUCCESS;
        }

        if (serial->size < num->length) {
            SCA_TRACE_ERROR("缓冲区太小！");
            return SCA_ERR_FAILED;
        }

        memcpy(serial->value, num->data, num->length);
        serial->size = num->length;
    }

    return ret;
}

int sca_cert_set_validity(SCA_CERT *cert, const char *start, const char *end)
{
    X509 *cer = NULL;
    ASN1_TIME *tm_start = NULL;
    ASN1_TIME *tm_end = NULL;
    int ret = SCA_ERR_SUCCESS;

    if (!cert || !cert->cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!start || !*start || !end || !*end) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    cer = cert->cert;

    tm_start = ASN1_TIME_new();
    tm_end = ASN1_TIME_new();

    if (ASN1_TIME_set_string_X509(tm_start, start) != 1) {
        SCA_TRACE_ERROR("设置起始时间失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (ASN1_TIME_set_string_X509(tm_end, end) != 1) {
        SCA_TRACE_ERROR("设置终止时间失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (X509_set1_notBefore(cer, tm_start) != 1) {
        SCA_TRACE_ERROR("设置证书起始时间失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (X509_set1_notAfter(cer, tm_end) != 1) {
        SCA_TRACE_ERROR("设置证书终止时间失败！");
        ret = SCA_ERR_FAILED;
    }

end:
    if (tm_start) {
        ASN1_TIME_free(tm_start);
    }
    
    if (tm_end) {
        ASN1_TIME_free(tm_end);
    }
    return ret;
}

/* 设置颁发者信息 */
int sca_cert_set_issuer(SCA_CERT *cert, const char *field, const struct sca_data *dn)
{
    X509 *cer = NULL;
    X509_NAME *name = NULL;

    if (!cert || !cert->cert || !dn || !dn->value) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (dn->size <= 0) {
        SCA_TRACE_CODE(SCA_ERR_PARAM);
        return SCA_ERR_PARAM;
    }

    if (!field || !*field) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    cer = cert->cert;
    name = X509_get_issuer_name(cer);

    if (!name) {
        X509_NAME *tmp = X509_NAME_new();
        X509_set_issuer_name(cer, tmp);
        X509_NAME_free(tmp);

        name = X509_get_issuer_name(cer);
        if (!name) {
            SCA_TRACE_ERROR("获取颁发者信息失败！");
            return SCA_ERR_FAILED;
        }
    }

    if (X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8, dn->value, dn->size, -1, 0) != 1) {
        SCA_TRACE_ERROR("设置颁发者信息失败！");
        return SCA_ERR_FAILED;
    }

    return SCA_ERR_SUCCESS;
}

int sca_cert_get_issuer_count(SCA_CERT *cert)
{
    X509 *cer = NULL;
    X509_NAME *name = NULL;
    int count = 0;

    if (!cert || !cert->cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return 0;
    }

    cer = cert->cert;
    name = X509_get_issuer_name(cer);
    count = X509_NAME_entry_count(name);

    return count < 0 ? 0 : count;
}

int sca_cert_enum_issuer(SCA_CERT *cert, int index, struct sca_data *dn)
{
    X509 *cer = NULL;
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *entry = NULL;
    ASN1_STRING *data = NULL;

    if (!cert || !cert->cert || !dn) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (index < 0) {
        SCA_TRACE_ERROR("索引不能为负数！");
        return SCA_ERR_PARAM;
    }

    cer = cert->cert;
    name = X509_get_issuer_name(cer);

    if (!name) {
        SCA_TRACE_ERROR("颁发者信息不存在！");
        return SCA_ERR_FAILED;
    }

    if (X509_NAME_entry_count(name) <= 0) {
        SCA_TRACE_ERROR("颁发者信息数量为 0！");
        return SCA_ERR_FAILED;
    } 

    entry = X509_NAME_get_entry(name, index);
    if (!entry) {
        SCA_TRACE_ERROR("获取颁发者信息失败！");
        return SCA_ERR_FAILED;
    }

    data = X509_NAME_ENTRY_get_data(entry);
    if (!data) {
        SCA_TRACE_ERROR("获取颁发者信息数据失败！");
        return SCA_ERR_FAILED;
    }

    if (!dn->value) {
        dn->size = data->length + 1;
        return SCA_ERR_SUCCESS;
    }

    if (dn->size <= data->length) {
        SCA_TRACE_ERROR("缓冲区不足！");
        return SCA_ERR_FAILED;
    }

    memcpy(dn->value, data->data, data->length);
    dn->size = data->length;
    return SCA_ERR_SUCCESS;
}

int sca_cert_get_issuer_name(SCA_CERT *cert, const char *field, struct sca_data *dn)
{
    X509 *cer = NULL;
    X509_NAME *name = NULL;
    ASN1_OBJECT *obj = NULL;
    int ret = SCA_ERR_SUCCESS;
    int len = 0;

    if (!cert || !cert->cert || !dn) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!field || !*field) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    cer = cert->cert;

    name = X509_get_issuer_name(cer);
    if (!name) {
        SCA_TRACE_ERROR("签发者信息不存在！");
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
        SCA_TRACE_ERROR("获取颁发者信息内容失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

end:
    if (obj) {
        ASN1_OBJECT_free(obj);
    }
    return ret;
}

int sca_cert_set_subject(SCA_CERT *cert, const char *field, const struct sca_data *dn)
{
    X509 *cer = NULL;
    X509_NAME *name = NULL;

    if (!cert || !cert->cert || !dn || !dn->value) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (dn->size <= 0) {
        SCA_TRACE_CODE(SCA_ERR_PARAM);
        return SCA_ERR_PARAM;
    }

    if (!field || !*field) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    cer = cert->cert;
    name = X509_get_subject_name(cer);

    if (!name) {
        X509_NAME *tmp = X509_NAME_new();
        X509_set_subject_name(cer, tmp);
        X509_NAME_free(tmp);

        name = X509_get_subject_name(cer);
        if (!name) {
            SCA_TRACE_ERROR("获取主题项信息失败！");
            return SCA_ERR_FAILED;
        }
    }

    if (X509_NAME_add_entry_by_txt(name, field, MBSTRING_UTF8, dn->value, dn->size, -1, 0) != 1) {
        SCA_TRACE_ERROR("设置主题项信息失败！");
        return SCA_ERR_FAILED;
    }

    return SCA_ERR_SUCCESS;
}

int sca_cert_get_subject_count(SCA_CERT *cert)
{
    X509 *cer = NULL;
    X509_NAME *name = NULL;
    int count = 0;

    if (!cert || !cert->cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return 0;
    }

    cer = cert->cert;
    name = X509_get_subject_name(cer);
    count = X509_NAME_entry_count(name);

    return count < 0 ? 0 : count;
}

int sca_cert_enum_subject(SCA_CERT *cert, int index, struct sca_data *dn)
{
    X509 *cer = NULL;
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *entry = NULL;
    ASN1_STRING *data = NULL;

    if (!cert || !cert->cert || !dn) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (index < 0) {
        SCA_TRACE_ERROR("索引不能为负数！");
        return SCA_ERR_PARAM;
    }

    cer = cert->cert;
    name = X509_get_subject_name(cer);

    if (!name) {
        SCA_TRACE_ERROR("主题项信息不存在！");
        return SCA_ERR_FAILED;
    }

    if (X509_NAME_entry_count(name) <= 0) {
        SCA_TRACE_ERROR("主题项信息数量为 0！");
        return SCA_ERR_FAILED;
    } 

    entry = X509_NAME_get_entry(name, index);
    if (!entry) {
        SCA_TRACE_ERROR("获取主题项信息失败！");
        return SCA_ERR_FAILED;
    }

    data = X509_NAME_ENTRY_get_data(entry);
    if (!data) {
        SCA_TRACE_ERROR("获取主题项信息数据失败！");
        return SCA_ERR_FAILED;
    }

    if (!dn->value) {
        dn->size = data->length + 1;
        return SCA_ERR_SUCCESS;
    }

    if (dn->size <= data->length) {
        SCA_TRACE_ERROR("缓冲区不足！");
        return SCA_ERR_FAILED;
    }

    memcpy(dn->value, data->data, data->length);
    dn->size = data->length;
    return SCA_ERR_SUCCESS;
}

int sca_cert_get_subject_name(SCA_CERT *cert, const char *field, struct sca_data *dn)
{
    X509 *cer = NULL;
    X509_NAME *name = NULL;
    ASN1_OBJECT *obj = NULL;
    int ret = SCA_ERR_SUCCESS;
    int len = 0;

    if (!cert || !cert->cert || !dn) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!field || !*field) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    cer = cert->cert;

    name = X509_get_subject_name(cer);
    if (!name) {
        SCA_TRACE_ERROR("主题项信息不存在！");
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
        SCA_TRACE_ERROR("获取主题项信息内容失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

end:
    if (obj) {
        ASN1_OBJECT_free(obj);
    }
    return ret;
}

int sca_cert_set_subject_pubkey(SCA_CERT *cert, SCA_KEY *key)
{
    X509 *cer = NULL;
    EVP_PKEY *pkey = NULL;

    if (!cert || !cert->cert || !key || !key->pkey) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    cer = cert->cert;
    pkey = key->pkey;

    if (X509_set_pubkey(cer, pkey) != 1) {
        SCA_TRACE_ERROR("设置公钥失败！");
        return SCA_ERR_FAILED;
    }

    return SCA_ERR_SUCCESS;
}

/* 获取 subject 公钥，需要调用 sca_key_destroy 来释放 */
SCA_KEY *sca_cert_get_subject_pubkey(SCA_CERT *cert)
{
    SCA_KEY *ret = NULL;
    X509 *cer = NULL;
    EVP_PKEY *pkey = NULL;

    if (!cert || !cert->cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return NULL;
    }

    cer = cert->cert;

    pkey = X509_get_pubkey(cer);
    if (!pkey) {
        SCA_TRACE_ERROR("公钥不存在！");
        return NULL;
    }

    ret = malloc(sizeof(*ret));
    ret->pkey = EVP_PKEY_dup(pkey);

    EVP_PKEY_free(pkey);
    return ret;
}

int sca_cert_add_ext(SCA_CERT *cert, const char *oid, int crit, const struct sca_data *ext)
{
    X509 *cer = NULL;
    X509_EXTENSION *ext = NULL;
    ASN1_OBJECT *obj = NULL;
    ASN1_OCTET_STRING *data = NULL;

    int ret = SCA_ERR_SUCCESS;

    if (!cert || !cert->cert || !ext || !ext->value) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (ext->size <= 0) {
        SCA_TRACE_CODE(SCA_ERR_PARAM);
        return SCA_ERR_PARAM;
    }

    if (!oid || !*oid) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return SCA_ERR_NULL_STRING;
    }

    cer = cert->cert;
    obj = OBJ_txt2obj(oid, 0);
    if (!obj) {
        SCA_TRACE_ERROR("%s 对象不存在！", oid);
        return SCA_ERR_NULL_POINTER;
    }

    data = ASN1_OCTET_STRING_new();
    if (ASN1_OCTET_STRING_set(data, ext->value, ext->size) != 1) {
        SCA_TRACE_ERROR("设置扩展数据失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    ext = X509_EXTENSION_create_by_OBJ(NULL, obj, crit, data);
    if (!ext) {
        SCA_TRACE_ERROR("创建扩展对象失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (X509_add_ext(cer, ext, -1) != 1) {
        SCA_TRACE_ERROR("添加扩展项失败！");
        ret = SCA_ERR_FAILED;
    }

end:
    if (ext) {
        X509_EXTENSION_free(ext);
    }

    if (data) {
        ASN1_OCTET_STRING_free(data);
    }

    if (obj) {
        ASN1_OBJECT_free(obj);
    }
    return ret;
}

int sca_cert_ext_count(SCA_CERT *cert)
{
    X509 *cer = NULL;
    int count = 0;

    if (!cert || !cert->cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return 0;
    }

    cer = cert->cert;
    count = X509_get_ext_count(cer);
    return count;
}

int sca_cert_get_ext_loc(SCA_CERT *cert, const char *oid)
{
    ASN1_OBJECT *obj = NULL;
    int ret = -1;

    if (!cert || !cert->cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return ret;
    }

    obj = OBJ_txt2obj(oid, 0);
    if (!obj) {
        SCA_TRACE_ERROR("创建扩展对象失败！");
        return ret;
    }

    if ((ret = X509_get_ext_by_OBJ(cert->cert, obj, -1)) < 0) {
        SCA_TRACE_ERROR("查询扩展对象失败！");
        ret = -1;
    }

    if (obj) {
        ASN1_OBJECT_free(obj);
    }

    return ret;
}

/* 获取扩展项 OID */
int sca_cert_get_ext_oid(SCA_CERT *cert, int loc, struct sca_data *oid)
{
    
    return 0;
}

/* 获取扩展项数据 */
int sca_cert_get_ext_data(SCA_CERT *cert, int loc, struct sca_data *data)
{
    return 0;
}

/* 扩展项是否是关键项 */
int sca_cert_ext_is_critica(SCA_CERT *cert, int loc)
{
    return 0;
}

/*===========================================================================*/
