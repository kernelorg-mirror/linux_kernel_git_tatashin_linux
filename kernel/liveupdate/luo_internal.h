/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#ifndef _LINUX_LUO_INTERNAL_H
#define _LINUX_LUO_INTERNAL_H

#include <linux/liveupdate.h>
#include <linux/uaccess.h>

struct luo_ucmd {
	void __user *ubuffer;
	u32 user_size;
	void *cmd;
};

static inline int luo_ucmd_respond(struct luo_ucmd *ucmd,
				   size_t kernel_cmd_size)
{
	/*
	 * Copy the minimum of what the user provided and what we actually
	 * have.
	 */
	if (copy_to_user(ucmd->ubuffer, ucmd->cmd,
			 min_t(size_t, ucmd->user_size, kernel_cmd_size))) {
		return -EFAULT;
	}
	return 0;
}

/*
 * Handles a deserialization failure: devices and memory is in unpredictable
 * state.
 *
 * Continuing the boot process after a failure is dangerous because it could
 * lead to leaks of private data.
 */
#define luo_restore_fail(__fmt, ...) panic(__fmt, ##__VA_ARGS__)

/**
 * struct luo_block - Internal representation of a serialization block.
 * @list: List head for linking blocks in memory.
 * @ser:  Pointer to the serialized header in preserved memory.
 */
struct luo_block {
	struct list_head list;
	struct luo_block_header_ser *ser;
};

/**
 * struct luo_block_set - A set of blocks that belong to the same object.
 * @blocks:          The list of serialization blocks (struct luo_block).
 * @nblocks:         The number of allocated serialization blocks.
 * @head_pa:         Physical address of the first block header.
 * @entry_size:      The size of each entry in the blocks.
 * @count_per_block: The maximum number of entries each block can hold.
 * @incoming:        True if this block set was restored from the previous kernel.
 */
struct luo_block_set {
	struct list_head blocks;
	long nblocks;
	u64 head_pa;
	size_t entry_size;
	u64 count_per_block;
	bool incoming;
};

/**
 * struct luo_block_it - Iterator for serializing entries into blocks.
 * @bs:         The block set being iterated.
 * @block:      The current block.
 * @i:          The current entry index within @block.
 */
struct luo_block_it {
	struct luo_block_set *bs;
	struct luo_block *block;
	u64 i;
};

#define LUO_BLOCK_SET_INIT(name, _entry_size) {				\
	.blocks = LIST_HEAD_INIT((name).blocks),			\
	.entry_size = _entry_size,					\
}

/**
 * struct luo_file_set - A set of files that belong to the same sessions.
 * @files_list: An ordered list of files associated with this session, it is
 *              ordered by preservation time.
 * @block_set:  The set of serialization blocks.
 * @count:      A counter tracking the number of files currently stored in the
 *              @files_list for this session.
 */
struct luo_file_set {
	struct list_head files_list;
	struct luo_block_set block_set;
	long count;
};

/**
 * struct luo_session - Represents an active or incoming Live Update session.
 * @name:       A unique name for this session, used for identification and
 *              retrieval.
 * @ser:        Pointer to the serialized data for this session.
 * @list:       A list_head member used to link this session into a global list
 *              of either outgoing (to be preserved) or incoming (restored from
 *              previous kernel) sessions.
 * @retrieved:  A boolean flag indicating whether this session has been
 *              retrieved by a consumer in the new kernel.
 * @file_set:   A set of files that belong to this session.
 * @mutex:      protects fields in the luo_session.
 */
struct luo_session {
	char name[LIVEUPDATE_SESSION_NAME_LENGTH];
	struct luo_session_ser *ser;
	struct list_head list;
	bool retrieved;
	struct luo_file_set file_set;
	struct mutex mutex;
};

extern struct rw_semaphore luo_register_rwlock;

int luo_session_create(const char *name, struct file **filep);
int luo_session_retrieve(const char *name, struct file **filep);
void __init luo_session_setup_outgoing(u64 *sessions_pa);
int __init luo_session_setup_incoming(u64 sessions_pa);
int luo_session_serialize(void);
int luo_session_deserialize(void);

int luo_preserve_file(struct luo_file_set *file_set, u64 token, int fd);
void luo_file_unpreserve_files(struct luo_file_set *file_set);
int luo_file_freeze(struct luo_file_set *file_set,
		    struct luo_file_set_ser *file_set_ser);
void luo_file_unfreeze(struct luo_file_set *file_set,
		       struct luo_file_set_ser *file_set_ser);
int luo_retrieve_file(struct luo_file_set *file_set, u64 token,
		      struct file **filep);
int luo_file_finish(struct luo_file_set *file_set);
int luo_file_deserialize(struct luo_file_set *file_set,
			 struct luo_file_set_ser *file_set_ser);
void luo_file_set_init(struct luo_file_set *file_set);
void luo_file_set_destroy(struct luo_file_set *file_set);

void luo_block_set_init(struct luo_block_set *bs, size_t entry_size);
int luo_block_grow(struct luo_block_set *bs, u64 count);
void luo_block_shrink(struct luo_block_set *bs, u64 count);
int luo_block_restore(struct luo_block_set *bs, u64 head_pa);
void luo_block_destroy(struct luo_block_set *bs);
void luo_block_set_clear(struct luo_block_set *bs);
void luo_block_it_init(struct luo_block_it *it, struct luo_block_set *bs);
void *luo_block_it_next(struct luo_block_it *it);
void *luo_block_it_read(struct luo_block_it *it);
void *luo_block_it_prev(struct luo_block_it *it);
void luo_block_it_finalize(struct luo_block_it *it);

int luo_flb_file_preserve(struct liveupdate_file_handler *fh);
void luo_flb_file_unpreserve(struct liveupdate_file_handler *fh);
void luo_flb_file_finish(struct liveupdate_file_handler *fh);
void luo_flb_unregister_all(struct liveupdate_file_handler *fh);
int __init luo_flb_setup_outgoing(u64 *flbs_pa);
void __init luo_flb_setup_incoming(u64 flbs_pa);
void luo_flb_serialize(void);

#ifdef CONFIG_LIVEUPDATE_TEST
void liveupdate_test_register(struct liveupdate_file_handler *fh);
#else
static inline void liveupdate_test_register(struct liveupdate_file_handler *fh) { }
#endif

#endif /* _LINUX_LUO_INTERNAL_H */
