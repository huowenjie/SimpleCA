#include <sca_trace.h>
#include <sca_key.h>

#include "sca_cmd_genkey.h"
#include "../sca_err/sca_cmd_err.h"

/*===========================================================================*/

/* 默认公钥后缀 */
#define DEF_PUB_SUFFIX ".pub"

/* 默认密钥名称 */
#define DEF_RSA_NAME "rsa_key"
#define DEF_EC_NAME "ec_key"

/* 默认 rsa 模长 */
#define DEF_RSA_BITLEN 2048

/* 默认私钥密码 */
#define DEF_KEY_PASSWD "123456"

/*-------------------------------------------------------*/

static const char *key_name = NULL;
static const char *key_pwd = NULL;
static int key_bitlen = 0;

/*-------------------------------------------------------*/

int sca_cmd_genkey(struct sca_cmd_opt *opt)
{
    SCA_KEY *key = NULL;
    char *name = NULL;
    int ret = SCA_ERR_SUCCESS;
    
    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (!key_bitlen) {
        key_bitlen = DEF_RSA_BITLEN;
    }

    if (!key_name) {
        key_name = DEF_RSA_NAME;
    }

    if (!opt->arg_num) {
        key = sca_gen_key(SCA_RSA, key_bitlen);
    } else {
        const char *type = opt->args[0];
        if (!strcmp(type, CMD_ALGO_RSA)) {
            key = sca_gen_key(SCA_RSA, key_bitlen);
        } else if (!strcmp(type, CMD_ALGO_EC)) {
            key = sca_gen_key(SCA_EC, key_bitlen);
        } else {
            SCA_TRACE_CODE(SCA_CMD_ERR_UNKNOWN_ARGS);
            ret = SCA_CMD_ERR_UNKNOWN_ARGS;
            goto end;
        }
    }

    if (!key) {
        SCA_TRACE_ERROR("生成密钥失败！");
        ret = SCA_ERR_FAILED;
        goto end;
    }

    /* 编码密钥 */
    ret = sca_enc_key(key, key_pwd, key_name);
    if (ret != SCA_ERR_SUCCESS) {
        SCA_TRACE_CODE(ret);
        goto end;
    }

    name = malloc(strlen(key_name) + sizeof(DEF_PUB_SUFFIX));
    strcpy(name, key_name);
    strcat(name, DEF_PUB_SUFFIX);

    ret = sca_enc_pub_key(key, name);
    if (ret != SCA_ERR_SUCCESS) {
        SCA_TRACE_CODE(ret);
        goto end;
    }

end:
    if (name) {
        free(name);
    }

    if (key) {
        sca_destroy_key(key);
    }

    key_bitlen = 0;
    key_name = NULL;
    key_pwd = NULL;

    return ret;
}

int sca_cmd_rsa_bitlen(struct sca_cmd_opt *opt)
{
    int bitlen = 0;

    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    bitlen = atoi(opt->args[0]);
    if (bitlen) {
        key_bitlen = bitlen;
    } else {
        SCA_TRACE_ERROR("未知的参数 %s", opt->args[0]);
        return SCA_CMD_ERR_UNKNOWN_ARGS;
    }

    return SCA_ERR_SUCCESS;
}

int sca_cmd_key_name(struct sca_cmd_opt *opt)
{
    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (strlen(opt->args[0])) {
        key_name = opt->args[0];
    } else {
        SCA_TRACE_ERROR("名称不允许为空");
        return SCA_CMD_ERR_UNKNOWN_ARGS;
    }

    return SCA_ERR_SUCCESS;
}

int sca_cmd_key_passwd(struct sca_cmd_opt *opt)
{
    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    if (strlen(opt->args[0])) {
        key_pwd = opt->args[0];
    } else {
        SCA_TRACE_ERROR("密码不允许为空");
        return SCA_CMD_ERR_UNKNOWN_ARGS;
    }

    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/
