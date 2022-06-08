#include <sca_trace.h>

#include "sca_cmd_list.h"
#include "sca_cmd_help.h"
#include "sca_cmd_genkey.h"
#include "sca_cmd_test.h"

#include "../sca_err/sca_cmd_err.h"

/*===========================================================================*/

/* 版本信息 */
static int sca_cmd_version(struct sca_cmd_opt *opt);

/* 无参指南 */
static const char cmd_help_no_args[] = 
    "版本号：./simpleca -version\n"
    "帮助：./simpleca -help\n"
    "输入：./simpleca -in\n"
    "输出：./simpleca -out\n"
    "测试：./simpleca -test\n"
    "生成密钥：./simpleca -genkey\n";

/*===========================================================================*/

/* 默认的内置选项表 */
struct sca_cmd_opt def_cmd_list[] = {
    { CMD_VERSION, NULL, 0, 0, 0, CMD_PRIORITY_VERSION, sca_cmd_version },

    CMD_HELP_DEF_OPTS,
    CMD_INPUT_DEF_OPTS,
    CMD_OUTPUT_DEF_OPTS,
    CMD_TEST_DEF_OPTS,
    CMD_GENKEY_DEF_OPTS,
    CMD_RSA_BITLEN_DEF_OPTS,
    CMD_KEY_NAME_DEF_OPTS,
    CMD_KEY_PASSWD_DEF_OPTS
};

/*===========================================================================*/

void sca_cmd_opt_parse(int count, const char *args[])
{
    int ret = 0;
    const char **opts = NULL;
    SCA_CMD_LIST *cmd_list = NULL;
    struct sca_cmd_opt *opt = NULL;

    if (count < 1 || !args || !args[0]) {
        SCA_TRACE_CODE(SCA_ERR_PARAM);
        return;
    } else if (count == 1) {
        SCA_TRACE(cmd_help_no_args);
        return;
    }

    cmd_list = sca_cmd_list_def();
    if (!cmd_list) {
        SCA_TRACE_CODE(SCA_ERR_NULL_POINTER);
        return;
    }

    sca_cmd_list_init(cmd_list);

    opts = args + 1;
    count -= 1;

    /* 首先把命令依次解析，将其保存在列表里，依次执行处理函数 */
    while (sca_cmd_has_next(count, opts)) {
        int num = 0;
        const char *name = opts[0];
        const struct sca_cmd_opt *def = sca_cmd_find_def_opt(name);

        if (!def) {
            ret = SCA_CMD_ERR_NO_THIS_OPT;
            SCA_TRACE_CODE(ret);
            break;
        }

        num = sca_cmd_args_num(count, opts);
        if (num < def->min_num) {
            ret = SCA_CMD_ERR_ARGS_COUNT;
            SCA_TRACE_CODE(ret);
            break;
        } else if (num > def->max_num) {
            ret = SCA_CMD_ERR_ARGS_COUNT;
            SCA_TRACE_CODE(ret);
            break;
        }

        opt = malloc(sizeof(*opt));
        memcpy(opt, def, sizeof(*opt));

        opt->arg_num = num;
        opt->args = sca_cmd_get_args(count, opts);

        ret = sca_cmd_list_push(cmd_list, opt);
        if (ret != SCA_ERR_SUCCESS) {
            SCA_TRACE_CODE(ret);
            break;
        }
        opt = NULL;

        opts = sca_cmd_next(&count, opts, &ret);
        if (!opts || !opts[0]) {
            break;
        }

        if (ret != SCA_ERR_SUCCESS) {
            SCA_TRACE_CODE(ret);
            break;
        }
    }

    if (ret != SCA_ERR_SUCCESS) {
        goto end;
    }

    /* 按照优先级排序 */
    ret = sca_cmd_list_sort(cmd_list);
    if (ret != SCA_ERR_SUCCESS) {
        SCA_TRACE_CODE(ret);
        goto end;
    }

end:
    if (opt) {
        free(opt);
        opt = NULL;
    }

    while ((opt = sca_cmd_list_pop(cmd_list))) {
        if (ret == SCA_ERR_SUCCESS) {
            ret = opt->handler(opt);
        }

        free(opt);
    }
}

int sca_cmd_has_next(int count, const char *args[])
{
    const char *tmp = NULL;
    int i = 0;

    if (!args || !args[0]) {
        return 0;
    }

    while (i < count) {
        tmp = args[i];
        if (!tmp) {
            return 0;
        }

        if (tmp[0] == '-') {
            return 1;
        }

        i++;
    }
    return 0;
}

const char **sca_cmd_next(int *count, const char *args[], int *status)
{
    int num = 0;
    int i = 0;

    const char *tmp = NULL;

    if (!count || !args || !status) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        *status = SCA_ERR_NULL_PARAM;
        return NULL;
    }

    num = *count;
    if (num <= 0 || !args[0]) {
        *status = SCA_ERR_SUCCESS;
        return args;
    }

    while (i < num) {
        tmp = args[i];
        if (!tmp) {
            break;
        }

        if (tmp[0] == '-' && i > 0) {
            break;
        }

        i++;
    }

    num -= i;
    *count = num;

    *status = SCA_ERR_SUCCESS;
    return &args[i];
}

int sca_cmd_is_valid(const char *opt)
{
    if (!opt || !opt[0]) {
        return 0;
    }

    return opt[0] == '-';
}

const char *sca_cmd_get_opt(int count, const char *args[], int index)
{
    if (count <= 0 || index >= (count - 1)) {
        SCA_TRACE_CODE(SCA_ERR_PARAM);
        return NULL;
    }

    if (!args || !args[0]) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return NULL;
    }

    if (!sca_cmd_is_valid(args[0])) {
        SCA_TRACE_CODE(SCA_CMD_ERR_INVALID_OPT);
        return NULL;
    }

    return args[index + 1];
}

const char **sca_cmd_get_args(int count, const char *args[])
{
    if (count <= 0) {
        SCA_TRACE_CODE(SCA_ERR_PARAM);
        return NULL;
    }

    if (!args || !args[0]) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return NULL;
    }

    if (!sca_cmd_is_valid(args[0])) {
        SCA_TRACE_CODE(SCA_CMD_ERR_INVALID_OPT);
        return NULL;
    }

    if (sca_cmd_is_valid(args[1])) {
        return NULL;
    }

    return &args[1];
}

int sca_cmd_args_num(int count, const char *args[])
{
    int i = 0;
    const char *tmp = NULL;

    if (!args) {
        SCA_TRACE_CODE(SCA_ERR_NULL_PARAM);
        return 0;
    }

    if (count <= 0 || !args[0]) {
        return 0;
    }

    if (!sca_cmd_is_valid(args[0])) {
        SCA_TRACE_CODE(SCA_CMD_ERR_INVALID_OPT);
        return 0;
    }

    while (i < count) {
        tmp = args[i];
        if (!tmp) {
            break;
        }

        if (tmp[0] == '-' && i > 0) {
            break;
        }

        i++;
    }

    return i - 1;
}

const struct sca_cmd_opt *sca_cmd_find_def_opt(const char *name)
{
    int i = 0;
    int count = 0;
    const struct sca_cmd_opt *cmd = NULL;

    if (!name || !*name) {
        SCA_TRACE_CODE(SCA_ERR_NULL_STRING);
        return NULL;
    }

    if (name[0] != '-') {
        SCA_TRACE_CODE(SCA_CMD_ERR_INVALID_OPT);
        return NULL;
    }

    name++;

    for (count = sizeof(def_cmd_list) / sizeof(struct sca_cmd_opt); i < count; ++i) {
        if (!strcmp(name, def_cmd_list[i].name)) {
            cmd = &def_cmd_list[i];
            break;
        }
    }

    return cmd;
}

/*===========================================================================*/

int sca_cmd_version(struct sca_cmd_opt *opt)
{
    SCA_TRACE("%s\n", "Version 1.0.0");
    return 0;
}

/*===========================================================================*/
