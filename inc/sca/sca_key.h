#ifndef SCA_KEY_H
#define SCA_KEY_H

#include "sca_type.h"

/*===========================================================================*/
/* 密钥管理 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* 定义密钥 */
typedef struct sca_key SCA_KEY;

enum SCA_KEY_TYPE{
    SCA_RSA = 0,
    SCA_EC
};

/* 生成密钥, 如果是 RSA 密钥，bitlen 则为密钥模长的位长度 */
SCA_KEY *sca_gen_key(enum SCA_KEY_TYPE type, int bitlen);

/* 加载密钥 */
SCA_KEY *sca_load_key(enum SCA_KEY_TYPE type, const char *passwd, const struct sca_data *data);

/* 加载公钥 */
SCA_KEY *sca_load_pub_key(enum SCA_KEY_TYPE type, const struct sca_data *data);

/* 销毁密钥 */
void sca_destroy_key(SCA_KEY *key);

/* 编码密钥数据 */
int sca_enc_key(SCA_KEY *key, const char *passwd, struct sca_data *data);

/* 编码公钥数据 */
int sca_enc_pub_key(SCA_KEY *key, struct sca_data *data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_KEY_H */
