#ifndef SCA_INNER_H
#define SCA_INNER_H

#include <openssl/x509.h>
#include <openssl/pem.h>

#include <sca_csr.h>
#include <sca_key.h>
#include <sca_cert.h>

/*===========================================================================*/
/* SCA 内部对象定义 */
/*===========================================================================*/

/* 密钥 */
struct sca_key {
    EVP_PKEY *pkey;
};

/* 证书请求 */
struct sca_cert_sig_req {
    X509_REQ *req;
};

/* 证书 */
struct sca_cert {
    X509 *cert;

    /* 证书请求的签名算法，如果为 NULL，则采用默认算法 */
    X509_ALGOR *req_algo;
};

/*===========================================================================*/

#endif /* SCA_INNER_H */
