#include <sca_trace.h>
#include <sca_key.h>

#include "sca_cmd_test.h"

/*===========================================================================*/

int sca_cmd_test(struct sca_cmd_opt *opt)
{
    SCA_KEY *key = NULL;

    if (!opt) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return SCA_ERR_NULL_PARAM;
    }

    SCA_TRACE("num = %d\n", opt->arg_num);

    if (opt->arg_num > 0) {
        SCA_TRACE("arg[0] = %s\n", opt->args[0]);
    }

    // key = sca_gen_key(SCA_RSA, 2048);
    key = sca_load_key(SCA_UNKNOW, "123456", "/home/huowj/openssl-src/SimpleCA/src/test.key");

    // sca_enc_key(key, NULL, "test.key");
    // sca_enc_pub_key(key, "test.pub");

    sca_destroy_key(key);
    return SCA_ERR_SUCCESS;
}

/*===========================================================================*/
