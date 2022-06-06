#ifndef SCA_TYPEDEF_H
#define SCA_TYPEDEF_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*===========================================================================*/
/* 全局类型定义 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* 基本数据类型定义，我们的目标平台主要是 amd64 所以基本不存在跨平台的问题 */
typedef char            SCA_INT8;
typedef short           SCA_INT16;
typedef int             SCA_INT32;
typedef unsigned char   SCA_UINT8;
typedef unsigned short  SCA_UINT16;
typedef unsigned int    SCA_UINT32;
typedef SCA_UINT8       SCA_BYTE;

/* 二进制数据结构 */
struct sca_data
{
    int size;
    SCA_BYTE *value;
};

#define SCA_DATA_INIT(data) \
    do {\
        (data)->size = 0; \
        (data)->value = NULL; \
    } while (0)

#define SCA_DATA_SET(data, val, len) \
    do { \
        (data)->value = (SCA_BYTE *)(val); \
        (data)->size = (int)(len); \
    } while (0)

#define SCA_DATA_MALLOC(data, len) \
    do {\
        (data)->value = (SCA_BYTE *)malloc((size_t)(len)); \
        (data)->size = (int)(len); \
        memset((data)->value, 0, (size_t)(len)); \
    } while (0)

#define SCA_DATA_DUP(to, src) \
    do {\
        SCA_DATA_MALLOC((to), (src)->size); \
        memcpy((to)->value, (src)->value, (size_t)((to)->size)); \
    } while (0)

#define SCA_DATA_FREE(data) \
    do {\
        free((data)->value); \
        (data)->value = NULL; \
        (data)->size = 0; \
    } while (0)

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* SCA_TYPEDEF_H */
