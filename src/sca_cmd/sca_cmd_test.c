#include <sca_trace.h>
#include <sca_cert.h>

#include "sca_cmd_test.h"

static char ca_cn[] = "lzxxm-CA";
static char ca_c[] = "CN";
static char ca_o[] = "lzld";

static char user_cn[] = "lzxxm";
static char user_c[] = "CN";
static char user_o[] = "lzld";

static char def_cps[] = "http://certificates.starfieldtech.com/repository/";
static char def_cps1[] = "http://www.microsoft.com/pki/mscorp/cps";

/*===========================================================================*/

int sca_cmd_test(struct sca_cmd_opt *opt)
{
    SCA_KEY *key = NULL;
    SCA_KEY *userkey = NULL;
    SCA_CERT_SIG_REQ *req = NULL;
    SCA_CERT *cert = NULL;
    SCA_CERT *usercert = NULL;

    struct sca_data dn = { 0 };
    struct sca_data cps = { 0 };

    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    key = sca_gen_key(SCA_RSA, 1024);
    userkey = sca_gen_key(SCA_RSA, 1024);

    sca_enc_key(key, NULL, "testCA.key");
    sca_enc_pub_key(key, "testCA.pub");

    sca_enc_key(userkey, NULL, "test.key");
    sca_enc_pub_key(userkey, "test.pub");

    /*---------------------------------------------------*/

    /* 创建 v3 版本的证书 */
    cert = sca_cert_create();

    /* 生成序列号 */
    sca_cert_gen_serial(cert);

    /* 设置有效期 */
    sca_cert_set_validity(cert, "20220705000000Z", "20320705000000Z");

    /* 设置颁发者信息和主题信息 */
    SCA_DATA_SET(&dn, ca_c, sizeof(ca_c) - 1);
    sca_cert_set_issuer(cert, "C", &dn);
    sca_cert_set_subject(cert, "C", &dn);

    SCA_DATA_SET(&dn, ca_cn, sizeof(ca_cn) - 1);
    sca_cert_set_issuer(cert, "CN", &dn);
    sca_cert_set_subject(cert, "CN", &dn);

    SCA_DATA_SET(&dn, ca_o, sizeof(ca_o) - 1);
    sca_cert_set_issuer(cert, "O", &dn);
    sca_cert_set_subject(cert, "O", &dn);

    /* 设置公钥信息 */
    sca_cert_set_subject_pubkey(cert, key);

    /* 设置 AKID */
    sca_cert_ext_add_key_id(cert, cert, 1);

    /* 设置 SKID */
    sca_cert_ext_add_key_id(cert, cert, 0);

    /* 设置证书用途 */
    sca_cert_ext_set_key_usage(cert, cert, SCA_KU_KEY_CERT_SIGN | SCA_KU_DIDITAL_SIGNATURE);

    /* 签发证书(自签) */
    sca_cert_sign(cert, SCA_MD_SHA1, key);

    /* 验证证书 */
    sca_cert_verify(cert, key);

    /* 编码证书输出 */
    sca_cert_enc(cert, "CA.cer");

    /*---------------------------------------------------*/
    
    req = sca_csr_create();

    SCA_DATA_SET(&dn, user_c, sizeof(user_c) - 1);
    sca_csr_set_subject(req, "C", &dn);

    SCA_DATA_SET(&dn, user_cn, sizeof(user_cn) - 1);
    sca_csr_set_subject(req, "CN", &dn);

    SCA_DATA_SET(&dn, user_o, sizeof(user_o) - 1);
    sca_csr_set_subject(req, "O", &dn);

    sca_csr_set_pubkey(req, userkey);
    sca_csr_sign(req, SCA_MD_SHA1, userkey);
    sca_csr_verify(req, userkey);
    sca_csr_verify(req, NULL);

    sca_csr_enc(req, "user.csr");

    /*---------------------------------------------------*/

    /* 创建用户的证书 */
    usercert = sca_cert_create();

    sca_cert_import_csr(usercert, req);

    /* 设置颁发者信息 */
    SCA_DATA_SET(&dn, ca_c, sizeof(ca_c) - 1);
    sca_cert_set_issuer(usercert, "C", &dn);

    SCA_DATA_SET(&dn, ca_cn, sizeof(ca_cn) - 1);
    sca_cert_set_issuer(usercert, "CN", &dn);

    SCA_DATA_SET(&dn, ca_o, sizeof(ca_o) - 1);
    sca_cert_set_issuer(usercert, "O", &dn);

    sca_cert_gen_serial(usercert);
    sca_cert_set_validity(usercert, "20220705000000Z", "20320705000000Z");

    /* 设置 AKID */
    sca_cert_ext_add_key_id(cert, usercert, 1);

    /* 设置 SKID */
    sca_cert_ext_add_key_id(cert, usercert, 0);

    /* 设置证书用途 */
    sca_cert_ext_set_key_usage(cert, usercert, SCA_KU_DIDITAL_SIGNATURE);

    /* 设置证书策略 */
    cps.value = (SCA_BYTE *)def_cps;
    cps.size = sizeof(def_cps) - 1;
    sca_cert_ext_add_cp(usercert, "2.16.840.1.114414.1.7.23.1", SCA_CP_CPS, &cps);
    sca_cert_ext_add_cp(usercert, "2.23.140.1.2.1", SCA_CP_DEFAULT, NULL);

    cps.value = (SCA_BYTE *)def_cps1;
    cps.size = sizeof(def_cps1) - 1;
    sca_cert_ext_add_cp(usercert, "2.16.840.1.114414.1.7.23.1", SCA_CP_CPS, &cps);

    /* 签发证书，用 CA 的私钥签发 */
    sca_cert_sign(usercert, SCA_MD_SHA1, key);

    /* 验证证书，用 CA 的公钥验证 */
    sca_cert_verify(usercert, key);

    /* 编码证书输出 */
    sca_cert_enc(usercert, "user.cer");

    /*---------------------------------------------------*/

    sca_cert_destroy(usercert);
    sca_cert_destroy(cert);
    sca_csr_destroy(req);
    sca_destroy_key(userkey);
    sca_destroy_key(key);

    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/
