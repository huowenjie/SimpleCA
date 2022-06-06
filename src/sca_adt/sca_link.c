#include <sca_link.h>
#include "../sca_err/sca_link_err.h"

/*===========================================================================*/

void sca_link_reset(struct sca_link *link)
{
    if (!link) {
        return;
    }

    link->head  = NULL;
    link->tail  = NULL;
    link->count = 0;
}

/*-------------------------------------------------------*/

/* 在 target 之前插入节点 */
#define INSERT_BEFORE(target, node) \
    (target)->prev->next = (node); \
    (node)->prev = (target)->prev; \
    (node)->next = (target); \
    (target)->prev = (node);

/* 在 target 之后插入节点 */
#define INSERT_AFTER(target, node) \
    (target)->next->prev = (node); \
    (node)->prev = (target); \
    (node)->next = (target->next); \
    (target)->next = (node);

/* 移除 target */
#define REMOVE(target) \
    (target)->prev->next = (target)->next; \
    (target)->next->prev = (target)->prev;

/*-------------------------------------------------------*/

SCA_UINT32 sca_link_push(struct sca_link *link, struct sca_link_node *node)
{
    if (!link || !node) {
        return SCA_ERR_NULL_PARAM;
    }

    if (link->head) {
        INSERT_AFTER(link->tail, node);
        link->tail = node;
    } else {
        link->head = node;
        link->tail = node;

        node->next = node;
        node->prev = node;
    }

    link->count++;
    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_link_insert(
    struct sca_link *link,
    int index,
    struct sca_link_node *node
)
{
    SCA_UINT32 i;
    struct sca_link_node *add_node = NULL;

    if (!link || !node) {
        return SCA_ERR_NULL_PARAM;
    }

    if (index > link->count) {
        return SCA_ERR_LINK_INDEX_RANGE;
    }

    if (!link->count) {
        /* 链表为空 */
        link->head = node;
        link->tail = node;

        node->next = node;
        node->prev = node;
    } else if (!index) {
        /* 换掉头节点 */
        INSERT_BEFORE(link->head, node);
        link->head = node;
    } else if (index == link->count) {
        /* 换掉尾节点 */
        INSERT_AFTER(link->tail, node);
        link->tail = node;
    } else {
        add_node = link->head;

        /* 先定位到位置，然后插入节点 */
        for (i = 0; i < index; i++) {
            add_node = add_node->next;
        }

        INSERT_BEFORE(add_node, node);
    }

    link->count++;
    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_link_insert_before(
    struct sca_link *link,
    struct sca_link_node *target,
    struct sca_link_node *node
)
{
    if (!link || !target || !node) {
        return SCA_ERR_NULL_PARAM;
    }

    INSERT_BEFORE(target, node);
    if (target == link->head) {
        link->head = node;
    }

    return SCA_ERR_SUCCESS;
}

SCA_UINT32 sca_link_insert_after(
    struct sca_link *link,
    struct sca_link_node *target,
    struct sca_link_node *node
)
{
    if (!link || !target || !node) {
        return SCA_ERR_NULL_PARAM;
    }

    INSERT_AFTER(target, node);
    if (target == link->tail) {
        link->tail = node;
    }

    return SCA_ERR_SUCCESS;
}

struct sca_link_node *sca_link_pop(struct sca_link *link)
{
    struct sca_link_node *ret = NULL;

    if (!link) {
        return NULL;
    }

    ret = link->tail;

    if (ret) {
        if (link->head != ret) {
            REMOVE(ret);
            link->tail = ret->prev;
        } else {
            link->head = NULL;
            link->tail = NULL;
        }

        link->count--;
    }

    return ret;
}

struct sca_link_node *sca_link_remove(struct sca_link *link, int index)
{
    SCA_UINT32 i;
    struct sca_link_node *ret = NULL;

    if (!link) {
        return NULL;
    }

    if (index >= link->count || link->count <= 0) {
        return NULL;
    }

    if (link->count == 1) {
        ret = link->head;

        link->head = NULL;
        link->tail = NULL;
    } else if (!index) {
        ret = link->head;

        REMOVE(link->head);
        link->head = ret->next;
    } else if (index == (link->count - 1)) {
        ret = link->tail;

        REMOVE(link->tail);
        link->tail = ret->prev;
    } else {
        ret = link->head;

        for (i = 0; i < index; i++) {
            ret = ret->next;
        }

        REMOVE(ret);
    }

    link->count--;
    return ret;
}

struct sca_link_node *sca_link_remove_node(struct sca_link *link, struct sca_link_node *target)
{
    SCA_UINT32 i;
    struct sca_link_node *ret = NULL;

    if (!link || !target) {
        return NULL;
    }

    if (!link->count) {
        return NULL;
    }
    
    ret = target;

    if (link->count == 1) {
        REMOVE(ret);
        link->head = NULL;
        link->tail = NULL;
    } else if (link->head == target) {
        REMOVE(ret);
        link->head = ret->next;
    } else if (link->tail == target) {
        REMOVE(ret);
        link->tail = ret->prev;
    } else {
        ret = link->head;

        for (i = 0; i < link->count; i++) {
            if (ret == target) {
                REMOVE(ret);
                break;
            }

            ret = ret->next;
        }

        /* 找不到 target，则不予删除 */
        if (i == link->count) {
            return NULL;
        }
    }

    link->count--;
    return ret;
}

struct sca_link_node *sca_link_remove_force(
    struct sca_link *link,
    struct sca_link_node *target
)
{
    struct sca_link_node *ret = NULL;

    if (!link || !target) {
        return NULL;
    }

    if (!link->count) {
        return NULL;
    }

    ret = target;
    REMOVE(ret);

    if (link->count == 1) {
        link->head = NULL;
        link->tail = NULL;
    } else if (link->head == target) {
        link->head = ret->next;
    } else if (link->tail == target) {
        link->tail = ret->prev;
    }

    link->count--;
    return ret;
}

/*===========================================================================*/
