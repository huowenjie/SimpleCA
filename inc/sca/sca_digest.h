#ifndef SCA_DIGEST_H
#define SCA_DIGEST_H

/*===========================================================================*/
/* 摘要 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* 摘要对象 */
typedef struct sca_digest SCA_DIGEST;

enum SCA_MD_ALGO {
    SCA_MD_MD5 = 0,
    SCA_MD_SHA1,
    SCA_MD_SHA256,
};

/* 创建摘要算法 */

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_DIGEST_H */
