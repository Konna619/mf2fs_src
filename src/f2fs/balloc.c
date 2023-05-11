// SPDX-License-Identifier: GPL-2.0
// adopting NOVA's allocation in NVM to hybridF2FS by HyunKi Byun
// To publish hybridF2FS, updated by Soon Hwang
// SPDX-FileCopyrightText: Copyright (c) 2021 Sogang University
/*
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include <linux/time.h>
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/bitops.h>
#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "balloc.h"

// 分配一个freelist
int f2fs_alloc_block_free_lists(struct f2fs_sb_info *sbi){
	struct free_list *free_list;

	sbi->free_list = kcalloc(1, sizeof(struct free_list), GFP_KERNEL);
	f2fs_info(sbi, "free_lits size=%ld", sizeof(struct free_list));

	if(!sbi->free_list)
		return -ENOMEM;

	free_list = sbi->free_list;
	free_list->block_free_tree = RB_ROOT;
	spin_lock_init(&free_list->s_lock);
	//free_list->index = 0;

	//spin_lock_init(&sbi->nvm_lock);
	// sbi->curr_block=0;
	// sbi->curr_offset=0;

	return 0;
}

// 释放freelist
void f2fs_delete_free_lists(struct f2fs_sb_info *sbi){

	kvfree(sbi->free_list->free_blocks_bitmap);
	kfree(sbi->free_list);
	sbi->free_list = NULL;
}

// 初始化freelist的起始块地址和末地址，留出给sb，cp，sit，nat，saa的空间
static void f2fs_init_free_list(struct f2fs_sb_info *sbi, struct free_list *free_list, int index){

	free_list->nr_blocks = PM_I(sbi)->p_nr_blocks;
	free_list->alloc_node_pages = le32_to_cpu(PM_S(sbi)->valid_node_blk_count);
	free_list->block_start = PM_I(sbi)->p_free_area_blkaddr; // reserved for metadata
	free_list->block_end = free_list->nr_blocks -1;
	free_list->free_block_bitmap_pages = free_list->block_start - PM_I(sbi)->p_fbb_blkaddr;
	free_list->num_free_blocks = 0;
	free_list->num_blocknode = 0;
	// sbi->curr_block = free_area_blkaddr;

	f2fs_info(sbi, "f2fs_init_free_list: free_area_blkaddr = %lu", free_list->block_start);
}

struct f2fs_range_node *f2fs_alloc_blocknode(){
	return f2fs_alloc_range_node();
}

void f2fs_free_blocknode(struct f2fs_range_node *node){
	f2fs_free_range_node(node);
}

// 删除free_list中所有的f2fs_range_node结构体
void f2fs_destroy_range_nodes(struct f2fs_sb_info *sbi){
	struct free_list *free_list = sbi->free_list;
	struct f2fs_range_node *curr = free_list->first_node;
	struct rb_node *curr_rb;
	struct f2fs_range_node *tmp;
	if(!curr)
		return;
	curr_rb = &(curr->node);
	while(curr_rb){
		curr = container_of(curr_rb, struct f2fs_range_node, node);
		tmp = curr;
		curr_rb = rb_next(curr_rb);
		f2fs_free_blocknode(tmp);
	}

	return;
}

// 初始化freelist的空闲块信息和空闲块树
int f2fs_init_pm_blockmap(struct f2fs_sb_info *sbi, int recovery){
	struct rb_root *tree;
	struct f2fs_range_node *blknode;
	struct free_list *free_list;
	int ret;
	unsigned int start, end, range_start, range_end;
	unsigned long *bitmap;

	free_list = sbi->free_list;
	tree = &(free_list->block_free_tree);
	f2fs_init_free_list(sbi, free_list, 0);

	/* */
	if (!recovery){
		free_list->num_free_blocks = free_list->block_end - free_list->block_start +1;//空闲块数
		blknode = f2fs_alloc_blocknode();

		if(!blknode){
			f2fs_err(sbi, "range node alloc failed!");
			return -ENOMEM;
		}

		/* 最大的节点，包含所有空闲块 */
		blknode->range_low = free_list->block_start;
		blknode->range_high = free_list->block_end;
		ret = f2fs_insert_blocktree(tree, blknode);//插入到freelist的红黑树中

		if(ret){
			f2fs_free_blocknode(blknode);
			f2fs_err(sbi, "range node insert failed!");
			return -EINVAL;
		}
		free_list->first_node = blknode;
		free_list->last_node = blknode;
		free_list->num_blocknode =1;
		free_list->free_blocks_bitmap = f2fs_kvmalloc(sbi, (free_list->free_block_bitmap_pages<<PAGE_SHIFT), GFP_KERNEL);
		if(!free_list->free_blocks_bitmap)
			return -ENOMEM;
		memset(free_list->free_blocks_bitmap, 0xff, (free_list->free_block_bitmap_pages<<PAGE_SHIFT));
	} else {
		free_list->free_blocks_bitmap = kmemdup(PM_I(sbi)->p_free_blocks_bitmap_va_start, (free_list->free_block_bitmap_pages<<PAGE_SHIFT), GFP_KERNEL);
		if(!free_list->free_blocks_bitmap)
			return -ENOMEM;
		bitmap = free_list->free_blocks_bitmap;
		start = free_list->block_start;
		end = free_list->nr_blocks;
		for(range_start = start; range_start < end; range_start++){
			range_start = find_next_bit(bitmap, end, range_start);
			if(range_start >= end)
				break;
			range_end = find_next_zero_bit(bitmap, end, range_start);
			f2fs_err(sbi, "find free blocks form %d to %u on pm", range_start, range_end-1);
			f2fs_free_blocks(sbi, range_start, range_end - range_start, false);
			range_start = range_end;
		}

	}
	return 0;
}

static inline int f2fs_rbtree_compare_rangenode(struct f2fs_range_node *curr,
		        unsigned long key, enum node_type type)
{
	if (type == NODE_DIR) {
		if (key < curr->hash)
			return -1;
		if (key > curr->hash)
			return 1;
		return 0;
	}

	/* Block and inode */
	if (key < curr->range_low)
		return -1;
	if (key > curr->range_high)
		return 1;
	
	return 0;
}

int f2fs_find_range_node(struct rb_root *tree, unsigned long key, enum node_type type, struct f2fs_range_node **ret_node){
	struct f2fs_range_node *curr = NULL;
	struct rb_node *temp;
	int compVal;
	int ret = 0;

	temp = tree->rb_node;

	while(temp){
		curr = container_of(temp, struct f2fs_range_node, node);
		compVal = f2fs_rbtree_compare_rangenode(curr, key, type);

		if(compVal == -1){
			temp = temp->rb_left;
		}
		else if(compVal == 1){
			temp = temp->rb_right;
		}
		else{
			ret = 1;
			break;
		}
	}

	*ret_node = curr;
	return ret;
}

int f2fs_insert_range_node(struct rb_root *tree, struct f2fs_range_node *new_node, enum node_type type){
	struct f2fs_range_node *curr;
	struct rb_node **temp, *parent;
	int compVal;

	temp = &(tree->rb_node);
	parent = NULL;

	while(*temp){
		curr = container_of(*temp, struct f2fs_range_node, node);
		compVal = f2fs_rbtree_compare_rangenode(curr, new_node->range_low, type);

		parent = *temp;

		if(compVal == -1){
			temp = &((*temp)->rb_left);
		} else if(compVal ==1){
			temp = &((*temp)->rb_right);
		} else {
			return -EINVAL;
		}
	}
	rb_link_node(&new_node->node, parent, temp);
	rb_insert_color(&new_node->node, tree);

	return 0;
}

int f2fs_insert_blocktree(struct rb_root *tree, struct f2fs_range_node *new_node){
	int ret;

	ret = f2fs_insert_range_node(tree, new_node, NODE_BLOCK);
	

	return ret;
}
	

static long f2fs_alloc_blocks_in_free_list(struct f2fs_sb_info *sbi, struct free_list *free_list, unsigned short btype, enum alloc_type atype, unsigned long num_blocks, unsigned long *new_blocknr, enum nova_alloc_direction from_tail){

	struct rb_root *tree;
	struct f2fs_range_node *curr, *next=NULL, *prev=NULL;
	struct rb_node *temp, *next_node, *prev_node;
	unsigned long curr_blocks;
	bool found = 0;
	unsigned long step = 0;

	if( !free_list->first_node || free_list->num_free_blocks ==0){
		//f2fs_mgs
		return -ENOSPC;
	}

	//atype skip
	//
	
	tree = &(free_list->block_free_tree);

	if(from_tail == ALLOC_FROM_HEAD)
		temp = &(free_list->first_node->node);
	else
		temp = &(free_list->last_node->node);

	while(temp){
		step++;
		curr = container_of(temp, struct f2fs_range_node, node);

		curr_blocks = curr->range_high - curr->range_low + 1;

		if(num_blocks >= curr_blocks){
			/* superpage allocation must succeed */
			if(btype > 0 && num_blocks > curr_blocks)
				goto next;

			/* Otherwise, allocate the whole blocknode */
			if( curr == free_list->first_node) {
				next_node = rb_next(temp);
				if(next_node)
					next = container_of(next_node, struct f2fs_range_node, node);
				free_list->first_node = next;
			}
			
			if( curr == free_list->last_node) {
				prev_node = rb_prev(temp);
				if(prev_node)
					prev = container_of(prev_node, struct f2fs_range_node, node);
				free_list->last_node = prev;
			}

			rb_erase(&curr->node, tree);
			free_list->num_blocknode--;
			num_blocks = curr_blocks;
			*new_blocknr = curr->range_low;
			f2fs_free_blocknode(curr);
			found = 1;
			break;
		}

		/* Allocate partial blocknode */
		if(from_tail == ALLOC_FROM_HEAD) {
			*new_blocknr = curr->range_low;
			curr->range_low += num_blocks;
		}
		else{
			*new_blocknr = curr->range_high + 1 - num_blocks;
			curr->range_high -= num_blocks;
		}

//		nova_update_range_node_checksum(curr);
		found =1;
		break;
next:
		if(from_tail == ALLOC_FROM_HEAD)
			temp = rb_next(temp);
		else
			temp = rb_prev(temp);
	}

	if(free_list->num_free_blocks < num_blocks){
//		f2fs_mgs
		return -ENOSPC;
	}

	if(found == 1){
		free_list->num_free_blocks -= num_blocks;
		if(atype == NODE_PM)
			free_list->alloc_node_pages += num_blocks;
	}
	else {
		//f2fs_mgs
		return -ENOSPC;
	}

	return num_blocks;
}

int f2fs_new_blocks(struct f2fs_sb_info *sbi, unsigned long *blocknr, unsigned int num, unsigned short btype, int zero, enum alloc_type atype, enum nova_alloc_direction from_tail){
	// struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct free_list *free_list;
	void *bp;
	unsigned long num_blocks = 0;
	unsigned long new_blocknr = 0;
	long ret_blocks = 0;
	int i;
	//int retried = 0;
	//struct timespec alloc_time;

	num_blocks = 1; //only needs 1 page for node

	free_list = sbi->free_list;

	spin_lock(&free_list->s_lock);

	ret_blocks = f2fs_alloc_blocks_in_free_list(sbi, free_list, btype, atype, num_blocks, &new_blocknr, from_tail);


	if(ret_blocks > 0){
		//free_list->alloc_data_count++;
		// free_list->alloc_data_pages += ret_blocks;
		for(i=0; i<ret_blocks; i++){
			clear_bit(new_blocknr+i, free_list->free_blocks_bitmap);
		}
	}

	spin_unlock(&free_list->s_lock);

	if(ret_blocks <= 0 || new_blocknr==0){
		return -ENOSPC;
	}

	if (zero){
		bp = (void*)new_blocknr;
		memset(bp, 0, PAGE_SIZE * ret_blocks);
	}

	*blocknr = new_blocknr;

	return ret_blocks;
}

int f2fs_find_free_slot(struct rb_root *tree, unsigned long range_low, unsigned long range_high, struct f2fs_range_node **prev, struct f2fs_range_node **next){
	struct f2fs_range_node *ret_node = NULL;
	struct rb_node *tmp;
	int ret;

	ret = f2fs_find_range_node(tree, range_low, NODE_BLOCK, &ret_node);
	if(ret){
		return -EINVAL;
	}

	if(!ret_node){
		*prev=*next=NULL;
	}
	else if(ret_node->range_high < range_low){
		*prev=ret_node;
		tmp = rb_next(&ret_node->node);
		if(tmp)
			*next = container_of(tmp, struct f2fs_range_node, node);
		else
			*next=NULL;
	}
	else if(ret_node->range_low > range_high){
		*next = ret_node;
		tmp = rb_prev(&ret_node->node);
		if(tmp)
			*prev = container_of(tmp, struct f2fs_range_node, node);
		else
			*prev=NULL;
	}
	else{
		return -EINVAL;
	}

	return 0;
}

int f2fs_free_blocks(struct f2fs_sb_info *sbi, unsigned long blocknr, int num, bool is_node){

	// struct f2fs_sb_info *sbi = F2FS_SB(sb);
	struct rb_root *tree;
	unsigned long block_low;
	unsigned long block_high;
	unsigned long num_blocks=0;
	struct f2fs_range_node *prev = NULL;
	struct f2fs_range_node *next = NULL;
	struct f2fs_range_node *curr = NULL;
	struct free_list *free_list;
	int cpuid;
	int new_node_used = 0;
	int ret;
	int i;

	if(num <= 0){
			f2fs_err(sbi,  "%s ERROR: free %d", __func__, num);
			return -EINVAL;
	}

	cpuid = 0;

	curr = f2fs_alloc_blocknode();
	if(curr == NULL)
		return -ENOMEM;

	free_list = sbi->free_list;
	spin_lock(&free_list->s_lock);

	tree = &(free_list->block_free_tree);

	num_blocks = num; //number of blocks
	block_low = blocknr;
	block_high = blocknr + num_blocks - 1;


	if(block_low < free_list->block_start || block_high > free_list->block_end){
//	if(blocknr < free_list->block_start || blocknr+num > free_list->block_end +1){
		f2fs_err(sbi, "free lbocks %lu to %lu, free list %d, start %lu, end %lu",
				block_low, block_high,
				0, free_list->block_start, free_list->block_end);
		ret = -EIO;
		goto out;
	}

	ret = f2fs_find_free_slot(tree, block_low, block_high, &prev, &next);

	if(ret){
		f2fs_err(sbi, "%s: find free slot fail: %d", __func__, ret);
		goto out;
	}

	if(prev && next && (block_low == prev->range_high +1) && (block_high + 1 == next->range_low)){
		/*fits the hole*/
		rb_erase(&next->node, tree);
		free_list->num_blocknode--;
		prev->range_high = next->range_high;
		if(free_list->last_node == next)
			free_list->last_node = prev;
		f2fs_free_blocknode(next);
		goto block_found;
	}
	if(prev && (block_low == prev->range_high + 1 )){
		/*Aligns left*/
		prev->range_high += num_blocks;
		goto block_found;
	}
	if(next && (block_high + 1 == next->range_low)){
		/*Aligns right*/
		next->range_low -= num_blocks;
		goto block_found;
	}

	/*Aligns somewhere in the middle */
	curr->range_low = block_low;
	curr->range_high = block_high;
	new_node_used = 1;
	ret = f2fs_insert_blocktree(tree, curr);
	if(ret){
		new_node_used=0;
		goto out;
	}
	if(!prev)
		free_list->first_node = curr;
	if(!next)
		free_list->last_node = curr;

	free_list->num_blocknode++;

block_found:
	free_list->num_free_blocks += num_blocks;
	if(is_node)
		free_list->alloc_node_pages -= num_blocks;
	for(i=0; i<num; i++){
		set_bit(blocknr+i, free_list->free_blocks_bitmap);
	}
	//printk("free blocks from %lu to %lu on pm \n", blocknr, blocknr+num-1);

out:
	spin_unlock(&free_list->s_lock);
	if(new_node_used == 0)
		f2fs_free_blocknode(curr);

	return ret;	
}
