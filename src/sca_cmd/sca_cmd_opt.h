#ifndef SCA_CMD_OPT_H
#define SCA_CMD_OPT_H

/*===========================================================================*/
/* 命令行选项定义 */
/*===========================================================================*/

/*
 * 添加新选项参数的方式
 *
 * 1.定义命令选项的名称、默认的参数列表（以 NULL 做结尾的指针数组）；
 * 2.打开 sca_cmd_opt.c 文件，给 def_cmd_list 列表添加自定义的命令选项；
 * 3.命令行框架在解析用户传入的命令后会将参数 struct sca_cmd_opt 传入各自命令
 *   模块的 handler 中。
 */

/* 版本命令 */
#define CMD_VERSION "version"

/* 最长的命令长度 */
#define CMD_OPT_MAX_LEN 16

/* 定义每个选项实现需要注册的函数 */
struct sca_cmd_opt;
typedef int (*cmd_opt_handler)(struct sca_cmd_opt *);

/* 命令选项定义表 */
struct sca_cmd_opt
{
    const char *name;  /* 选项名称 */
    const char **args; /* 参数表 */
    int arg_num;       /* 参数数量 */
    int max_num;       /* 参数最大数量 */
    int min_num;       /* 参数最小数量 */
    int priority;      /* 优先级 */

    /* 处理函数 */
    cmd_opt_handler handler;
};

/* 选项解析 */
void sca_cmd_opt_parse(int count, const char *args[]);

/* 是否有下一个命令，如果有，返回 1，否则返回 0 */
int sca_cmd_has_next(int count, const char *args[]);

/* 定位到下一个命令处, 返回剩余选项数量 */
const char **sca_cmd_next(int *count, const char *args[], int *status);

/* 当前参数是否是有效的指令 */
int sca_cmd_is_valid(const char *opt);

/* 获取当前指令的参数 */
const char *sca_cmd_get_opt(int count, const char *args[], int index);

/* 获取当前选项的参数表 */
const char **sca_cmd_get_args(int count, const char *args[]);

/* 返回当前选项的参数数量，args[0] 必须是 - 开头的选项 */
int sca_cmd_args_num(int count, const char *args[]);

/* 根据名称查找默认选项信息 */
const struct sca_cmd_opt *sca_cmd_find_def_opt(const char *name);

/*===========================================================================*/

#endif /* SCA_CMD_OPT_H */
