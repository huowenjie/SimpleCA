#ifndef SCA_KEY_H
#define SCA_KEY_H

#include "sca_type.h"

/*===========================================================================*/
/* 密钥管理 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* 定义密钥和密钥对象 */
typedef struct sca_key SCA_KEY;

enum SCA_KEY_TYPE{
    SCA_UNKNOW = 0,
    SCA_RSA,
    SCA_EC
};

/* 生成密钥, 如果是 RSA 密钥，bitlen 则为密钥模长的位长度 */
SCA_KEY *sca_gen_key(enum SCA_KEY_TYPE type, int bitlen);

/* 加载密钥 */
SCA_KEY *sca_load_key(const char *passwd, const char *file);

/* 加载公钥 */
SCA_KEY *sca_load_pub_key(const char *file);

/* 销毁密钥 */
void sca_destroy_key(SCA_KEY *key);

/* 编码密钥数据并输出到指定文件 */
int sca_enc_key(SCA_KEY *key, const char *passwd, const char *file);

/* 编码公钥数据 */
int sca_enc_pub_key(SCA_KEY *key, const char *file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_KEY_H */
