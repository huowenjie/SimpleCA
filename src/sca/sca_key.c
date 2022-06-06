#include <stdlib.h>
#include <string.h>

#include <sca_key.h>
#include <sca_trace.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

/*===========================================================================*/

struct sca_key {
    enum SCA_KEY_TYPE type;
    int bitlen;

    EVP_PKEY *pkey;
};

static EVP_PKEY *gen_rsa_key(int bitlen);
static EVP_PKEY *gen_ec_key();

/*===========================================================================*/

SCA_KEY *sca_gen_key(enum SCA_KEY_TYPE type, int bitlen)
{
    SCA_KEY *key = NULL;
    EVP_PKEY *pkey = NULL;

    switch (type) {
    case SCA_RSA:
        pkey = gen_rsa_key(bitlen);
        break;

    case SCA_EC:
        pkey = gen_ec_key();
        break;

    default:
        SCA_TRACE_ERROR("错误的算法类型！");
        return NULL;
    }

    if (!pkey) {
        SCA_TRACE_ERROR("生成密钥失败！");
        return NULL;
    }

    key = malloc(sizeof(*key));
    memset(key, 0, sizeof(*key));

    key->type = type;
    key->bitlen = bitlen;
    key->pkey = pkey;

    return key;
}

/* 加载密钥 */
SCA_KEY *sca_load_key(enum SCA_KEY_TYPE type, const char *passwd, const struct sca_data *data)
{
    return NULL;
}

/* 加载公钥 */
SCA_KEY *sca_load_pub_key(enum SCA_KEY_TYPE type, const struct sca_data *data)
{
    return NULL;
}

/* 销毁密钥 */
void sca_destroy_key(SCA_KEY *key)
{
    if (key) {
        if (key->pkey) {
            EVP_PKEY_free(key->pkey);
        }
        free(key);
    }
}

/* 编码密钥数据 */
int sca_enc_key(SCA_KEY *key, const char *passwd, struct sca_data *data)
{
    EVP_PKEY *pkey = NULL;
    SCA_BYTE *buf = NULL;
    SCA_BYTE *p = NULL;

    BIO *io = NULL;

    int len = 0;
    int ret = SCA_ERR_SUCCESS;

    if (!key || !key->pkey) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    pkey = key->pkey;
    len = i2d_PrivateKey(pkey, NULL);

    if (len <= 0) {
        SCA_TRACE_ERROR("密钥长度异常!");
        return SCA_ERR_FAILED;
    }

    buf = malloc(len);
    memset(buf, 0, len);

    p = buf;

    if (i2d_PrivateKey(pkey, &p) != len) {
        SCA_TRACE_ERROR("密钥 DER 转码失败\n");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    io = BIO_new(BIO_s_mem());

    if (PEM_write_bio_PrivateKey(io, pkey, EVP_des_ede3_cbc(), NULL, 0, NULL, NULL) != 1) {
        SCA_TRACE_ERROR("PEM 编码失败\n");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    len = BIO_get_mem_data(io, &p);
    if (len <= 0) {
        SCA_TRACE_ERROR("获取 PEM 编码数据失败\n");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    if (!data->value) {
        data->size = len;
        goto end;
    }

    if (data->size < len) {
        SCA_TRACE_ERROR("缓冲区空间不足\n");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    memcpy(data->value, p, len);
    data->size = len;

end:
    if (io) {
        BIO_free(io);
    }

    free(buf);
    return ret;
}

/* 编码公钥数据 */
int sca_enc_pub_key(SCA_KEY *key, struct sca_data *data)
{
    return 0;
}

/*===========================================================================*/

EVP_PKEY *gen_rsa_key(int bitlen)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    if (bitlen < 0) {
        SCA_TRACE_ERROR("bitlen 不能为 0！");
        return NULL;
    }

    if (!bitlen) {
        bitlen = 2048;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) {
        SCA_TRACE_ERROR("生成上下文失败\n");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        SCA_TRACE_ERROR("初始化上下文失败\n");
        goto err; 
    }

    params[0] = OSSL_PARAM_construct_uint("bits",(unsigned int *)&bitlen);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) != 1) {
        SCA_TRACE_ERROR("设置参数失败\n");
        goto err;
    }

    if (EVP_PKEY_generate(ctx, &pkey) != 1) {
        SCA_TRACE_ERROR("生成 RSA 密钥失败\n");
        goto err;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;

err:
    if (pkey) {
        EVP_PKEY_free(pkey);
    }

    if (ctx) {
        EVP_PKEY_CTX_free(ctx);
    }
    return NULL;
}

EVP_PKEY *gen_ec_key()
{
    return NULL;
}

/*===========================================================================*/
