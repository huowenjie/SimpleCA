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
    return ret;
}

void sca_cert_destroy(SCA_CERT *cert)
{
    if (cert) {
        if (cert->cert) {
            X509_free(cert->cert);
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

    /* 其他属性暂不处理 */
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

int sca_cert_set_sign_algo(SCA_CERT *cert, const char *field)
{
    if (!cert || !cert->cert) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!field || !*field) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }


    return 0;
}

/*
 * 设置证书有效期
 *
 * start 和 end 的格式为 GeneralizedTime 时间格式 YYYYMMDDHHMMSSZ，秒数为 0，
 * 且不允许有小数秒
 * 参照 RFC 5280
 */
int sca_cert_set_validity(SCA_CERT *cert, const char *start, const char *end)
{
    return 0;
}

/* 设置颁发者信息 */
int sca_cert_set_issuer(SCA_CERT *cert, const char *field, const struct sca_data *dn)
{
    return 0;
}

/* 获取颁发者信息数量 */
int sca_cert_get_issuer_count(SCA_CERT *cert)
{
    return 0;
}

/* 根据索引枚举颁发者项 */
int sca_cert_enum_issuer(SCA_CERT *cert, int index, struct sca_data *dn)
{
    return 0;
}

/* 根据字段或者 oid 来获取颁发者项 */
int sca_cert_get_issuer_name(SCA_CERT *cert, const char *field, struct sca_data *dn)
{
    return 0;
}

/* 设置证书主题项 */
int sca_cert_set_subject(SCA_CERT *cert, const char *field, const struct sca_data *dn)
{
    return 0;
}

/* 获取主题项数量 */
int sca_cert_get_subject_count(SCA_CERT *cert)
{
    return 0;
}

/* 根据索引枚举主题项 */
int sca_cert_enum_subject(SCA_CERT *cert, int index, struct sca_data *dn)
{
    return 0;
}

/* 根据字段或者 oid 来获取主题项 */
int sca_cert_get_subject_name(SCA_CERT *cert, const char *field, struct sca_data *dn)
{
    return 0;
}

/* 设置 subject 公钥数据 */
int sca_cert_set_subject_pubkey(SCA_CERT *cert, SCA_KEY *key)
{
    return 0;
}

/* 获取 subject 公钥，需要调用 sca_key_destroy 来释放 */
SCA_KEY *sca_cert_get_subject_pubkey(SCA_CERT *cert)
{
    return NULL;
}

/* 添加扩展项, crit 为非零整数，则 ext 为关键项 */
int sca_cert_add_ext(SCA_CERT *cert, const char *oid, int crit, const struct sca_data *ext)
{
    return 0;
}

/* 获取扩展项数量 */
int sca_cert_ext_count(SCA_CERT *cert)
{
    return 0;
}

/* 根据 oid 搜索扩展项索引 */
int sca_cert_get_ext_loc(SCA_CERT *cert, const char *oid)
{
    return 0;
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
