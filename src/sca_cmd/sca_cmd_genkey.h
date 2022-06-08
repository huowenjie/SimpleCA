#ifndef SCA_CMD_GENKEY_H
#define SCA_CMD_GENKEY_H

#include "sca_cmd_priority.h"

/*===========================================================================*/
/* 密钥生成模块 */
/*===========================================================================*/

/* 密钥生成 */
#define CMD_GENKEY "genkey"

/* RSA 模长的位长度 */
#define CMD_RSA_BITLEN "bitlen"

/* 密钥名称 */
#define CMD_KEY_NAME "name"

/* 私钥保护加密口令 */
#define CMD_KEY_PASSWD "pwd"

/* 算法 */
#define CMD_ALGO_RSA "rsa"
#define CMD_ALGO_EC "ec"

/* 内置选项定义 */
#define CMD_GENKEY_DEF_OPTS { CMD_GENKEY, NULL, 0, 1, 0, CMD_PRIORITY_GENKEY, sca_cmd_genkey }
#define CMD_RSA_BITLEN_DEF_OPTS { CMD_RSA_BITLEN, NULL, 0, 1, 1, CMD_PRIORITY_KEY_OPT, sca_cmd_rsa_bitlen }
#define CMD_KEY_NAME_DEF_OPTS { CMD_KEY_NAME, NULL, 0, 1, 1, CMD_PRIORITY_KEY_OPT, sca_cmd_key_name }
#define CMD_KEY_PASSWD_DEF_OPTS { CMD_KEY_PASSWD, NULL, 0, 1, 1, CMD_PRIORITY_KEY_OPT, sca_cmd_key_passwd }

/* 密钥 */
int sca_cmd_genkey(struct sca_cmd_opt *opt);

/* RSA 算法模长录入 */
int sca_cmd_rsa_bitlen(struct sca_cmd_opt *opt);

/* 输入密钥的名称 */
int sca_cmd_key_name(struct sca_cmd_opt *opt);

/* 输入密钥保护口令 */
int sca_cmd_key_passwd(struct sca_cmd_opt *opt);

/*===========================================================================*/

#endif /* SCA_CMD_GENKEY_H */