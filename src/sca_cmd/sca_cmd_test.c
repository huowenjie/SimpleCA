#include <sca_trace.h>
#include <sca_cert.h>

#include "sca_cmd_test.h"

static char test_dn[] = "CN";

/*===========================================================================*/

int sca_cmd_test(struct sca_cmd_opt *opt)
{
    SCA_KEY *key = NULL;
    SCA_CERT_SIG_REQ *req = NULL;
    SCA_CERT *cert = NULL;

    struct sca_data dn = {
        (sizeof(test_dn) - 1),
        (SCA_BYTE *)test_dn
    };

    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    key = sca_gen_key(SCA_RSA, 1024);

    sca_enc_key(key, NULL, "test.key");
    sca_enc_pub_key(key, "test.pub");

    req = sca_csr_create();

    sca_csr_set_subject(req, "C", &dn);
    sca_csr_set_pubkey(req, key);
    sca_csr_sign(req, SCA_MD_SHA1, key);
    sca_csr_verify(req, key);
    sca_csr_verify(req, NULL);

    sca_csr_enc(req, "test.csr");

    /* 创建 v3 版本的证书 */
    cert = sca_cert_create();

    /* 导入证书请求信息 */
    sca_cert_import_csr(cert, req);

    /* 生成序列号 */
    sca_cert_gen_serial(cert);

    /* 设置有效期 */
    sca_cert_set_validity(cert, "20220705000000Z", "20320705000000Z");

    /* 设置颁发者信息 */
    sca_cert_set_issuer(cert, "C", &dn);

    /* 设置公钥信息 */
    sca_cert_set_subject_pubkey(cert, key);

    /* 签发证书 */
    sca_cert_sign(cert, SCA_MD_SHA1, key);

    /* 验证证书 */
    sca_cert_verify(cert, key);

    /* 编码证书输出 */
    sca_cert_enc(cert, "test.cer");

    sca_cert_destroy(cert);
    sca_csr_destroy(req);
    sca_destroy_key(key);

    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/
