#ifndef SCA_ERROR_H
#define SCA_ERROR_H

#include "sca_type.h"

/*===========================================================================*/
/* 错误处理 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define SCA_ERR_MAX_MODULES     255                     /* 错误模块表最大容量 */
#define SCA_ERR_MODULE_MASK     0xFF000000U             /* 错误模块掩码 */

#define SCA_ERR_COMMON          1                       /* 通用错误模块 */
#define SCA_ERR_LOG             (SCA_ERR_COMMON + 1)    /* 日志错误模块 */
#define SCA_ERR_LINK            (SCA_ERR_LOG + 1)       /* 链表模块 */
#define SCA_ERR_HASH            (SCA_ERR_LINK + 1)      /* 散列表模块 */
#define SCA_ERR_CMD             (SCA_ERR_HASH + 1)      /* 命令行模块 */

/* 通过模块代码获取基准码 */
#define SCA_ERR_BASIC_BUILD(mod) ((SCA_UINT32)(mod) << 24)

/* 通过错误码获取模块代码, 逻辑右移 */
#define SCA_ERR_MOD_RECOVER(err) ((SCA_UINT32)((err) & SCA_ERR_MODULE_MASK) >> 24)

/* 通用错误 */
#define SCA_ERR_SUCCESS         0x00000000U                             /* 成功 */
#define SCA_ERR_BASE            (SCA_ERR_BASIC_BUILD(SCA_ERR_COMMON))   /* 错误基准码 */
#define SCA_ERR_FAILED          (SCA_ERR_BASE + 1)                      /* 失败 */

#define SCA_ERR_PARAM           (SCA_ERR_FAILED + 1)                    /* 参数错误 */
#define SCA_ERR_NULL_PARAM      (SCA_ERR_PARAM + 1)                     /* 空参数错误 */
#define SCA_ERR_NULL_POINTER    (SCA_ERR_NULL_PARAM + 1)                /* 空指针错误 */
#define SCA_ERR_NULL_STRING     (SCA_ERR_NULL_POINTER + 1)              /* 空的字符串 */

struct sca_err_info {
    union err_id_info {
        unsigned int code;   /* 错误码 */
        unsigned int module; /* 错误模块序号 */
    } err_id;

    const char *desc;        /* 错误描述 */
};

/**
 * 根据错误码获取错误码描述
 * 
 * 参数：
 *     code[in] -- 错误码
 *
 * 返回值：
 *     如果成功，错误码描述；如果失败，返回 NULL。
 */
extern const char *sca_err_desc(SCA_UINT32 code);

/**
 * 根据错误码获取错误模块描述
 * 
 * 参数：
 *     code[in] -- 错误码
 *
 * 返回值：
 *     如果成功，错误模块描述；如果失败，返回 NULL。
 */
extern const char *sca_err_mod_desc(SCA_UINT32 code);

/**
 * 加载内部所有模块的错误码列表
 * 
 * 参数：
 *     void
 *
 * 返回值：
 *     如果成功，错误模块描述；如果失败，返回 NULL。
 */
extern void sca_load_all_err(void);

/**
 * 加载单独模块的错误码列表
 * 
 * 参数：
 *     list[in] -- 错误信息数组
 *
 * 返回值：
 *     void
 *
 * 特殊说明：
 *     本函数不拷贝数据，所以传入的 list；必须指向静态存储区或者堆, 内存由调用者负责维护；
 * 同时每个模块的错误码列表的第一个元素必须为 { module, desc(desc 不能为空) },最后一个
 * 元素必须为 { 0, NULL }。
 *     
 */
extern void sca_load_err_list(const struct sca_err_info *list);

/**
 * 卸载单独模块的错误码列表
 * 
 * 参数：
 *     module[in] -- 错误模块
 *
 * 返回值：
 *     void
 *
 * 特殊说明：
 *     sca_unload_err_list 函数仅仅会将内部缓存的地址清空，而不会释放内存。
 */
extern void sca_unload_err_list(SCA_UINT32 module);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_ERROR_H */
