#ifndef sca_link_H
#define sca_link_H

#include "sca_type.h"

/*===========================================================================*/
/* 双向链表 */
/*===========================================================================*/

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* 双向链表主体结构 */
struct sca_link
{
    struct sca_link_node *head;
    struct sca_link_node *tail;

    int count;
};

/* 链表节点 */
struct sca_link_node
{
    struct sca_link_node *prev;
    struct sca_link_node *next;
};

/* 链表还原 */
void sca_link_reset(struct sca_link *link);

/* 将节点接入尾部 */
SCA_UINT32 sca_link_push(struct sca_link *link, struct sca_link_node *node);

/* 按索引插入节点，如 0 则插在第一个，依次类推，查询节点复杂度为 O(n) */
SCA_UINT32 sca_link_insert(
    struct sca_link *link,
    int index,
    struct sca_link_node *node
);

/* 在目标节点之前插入节点, target 不能为空 */
SCA_UINT32 sca_link_insert_before(
    struct sca_link *link,
    struct sca_link_node *target,
    struct sca_link_node *node
);

/* 在目标节点之后插入节点, target 不能为空 */
SCA_UINT32 sca_link_insert_after(
    struct sca_link *link,
    struct sca_link_node *target,
    struct sca_link_node *node
);

/* 移除尾部节点，同时返回节点地址 */
struct sca_link_node *sca_link_pop(struct sca_link *link);

/* 根据索引移除节点，查询节点复杂度为 O(n) */
struct sca_link_node *sca_link_remove(struct sca_link *link, int index);

/* 移除目标节点, 移除成功返回该节点, 移除时会先查询节点是否存在 */
struct sca_link_node *sca_link_remove_node(
    struct sca_link *link,
    struct sca_link_node *target
);

/* 
 * 强制移除目标节点, 移除成功返回该节点, 移除时不检查节点是否存在，
 * 算法复杂度为 O(1) ；
 *
 * 调用本函数定要万分小心，确保 target 属于 link。
 */
struct sca_link_node *sca_link_remove_force(
    struct sca_link *link,
    struct sca_link_node *target
);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*===========================================================================*/

#endif /* sca_link_H */
