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

/* 解析加密的回调 */
static int cb_get_prv_passwd(char *buf, int size, int rwflag, void *u);

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
SCA_KEY *sca_load_key(enum SCA_KEY_TYPE type, const char *passwd, const char *file)
{
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;
    SCA_KEY *key = NULL;

    if (!file || !*file) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return NULL;
    }

    fp = fopen(file, "r");
    if (!fp) {
        SCA_TRACE_ERROR("打开文件失败！");
        return NULL;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, cb_get_prv_passwd, (void *)passwd);
    if (!pkey) {
        SCA_TRACE_ERROR("读取文件失败！");
        goto end;
    }

    key = malloc(sizeof(*key));
    memset(key, 0, sizeof(*key));

    key->type = type;
    key->pkey = pkey;

end:

    fclose(fp);
    return key;
}

/* 加载公钥 */
SCA_KEY *sca_load_pub_key(enum SCA_KEY_TYPE type, const char *file)
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
int sca_enc_key(SCA_KEY *key, const char *passwd, const char *file)
{
    EVP_PKEY *pkey = NULL;
    FILE *fp = NULL;
    int ret = SCA_ERR_SUCCESS;

    if (!key || !key->pkey) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    pkey = key->pkey;
    fp = fopen(file, "w");

    if (!fp) {
        SCA_TRACE_ERROR("文件创建失败\n");
        return SCA_ERR_FAILED;
    }

    if (passwd && passwd[0]) {
        if (PEM_write_PrivateKey(
            fp, pkey, EVP_aes_128_cbc(), 
            (const unsigned char *)passwd,
            (int)strlen(passwd), NULL, NULL) != 1
        ) {
            SCA_TRACE_ERROR("PEM 编码失败");
            ret = SCA_ERR_FAILED;
        }
    } else {
        if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
            SCA_TRACE_ERROR("PEM 编码失败");
            ret = SCA_ERR_FAILED;
        }
    }

    if (fp) {
        fflush(fp);
        fclose(fp);
    }
    return ret;
}

/* 编码公钥数据 */
int sca_enc_pub_key(SCA_KEY *key, const char *file)
{
    EVP_PKEY *pkey = NULL;
    FILE *fp = NULL;
    int ret = SCA_ERR_SUCCESS;

    if (!key || !key->pkey) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    pkey = key->pkey;
    fp = fopen(file, "w");

    if (!fp) {
        SCA_TRACE_ERROR("文件创建失败\n");
        return SCA_ERR_FAILED;
    }

    if (PEM_write_PUBKEY(fp, pkey) != 1) {
        SCA_TRACE_ERROR("PEM 编码失败");
        ret = SCA_ERR_FAILED;
    }

    if (fp) {
        fflush(fp);
        fclose(fp);
    }
    return ret;
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

int cb_get_prv_passwd(char *buf, int size, int rwflag, void *u)
{
    const char *pwd = (const char *)u;
    int len = 0;

    if (!pwd || !*pwd) {
        return 0;
    }

    len = (int)strlen(pwd);
    if (size < len) {
        len = size;
    }

    memcpy(buf, pwd, len);
    return len;
}

/*===========================================================================*/
