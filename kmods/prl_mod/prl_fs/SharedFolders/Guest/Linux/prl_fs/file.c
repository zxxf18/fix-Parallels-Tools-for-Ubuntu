/*
 *   prlfs/file.c
 *
 *   Copyright (C) 1999-2016 Parallels International GmbH
 *   Author: Vasily Averin <vvs@parallels.com>
 *
 *   Parallels Linux shared folders filesystem
 *
 *   File related functions and definitions
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include "prlfs.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#define FILE_DENTRY(f) ((f)->f_path.dentry)
#else
#define FILE_DENTRY(f) ((f)->f_dentry)
#endif

static int prlfs_open(struct inode *inode, struct file *filp)
{
	char *buf, *p;
	int buflen, ret;
	struct super_block *sb = inode->i_sb;
	struct dentry *dentry = FILE_DENTRY(filp);
	struct prlfs_file_info pfi;
	struct prlfs_fd *pfd;

	DPRINTK("ENTER\n");
	init_pfi(&pfi, 0, 0, 0, filp->f_flags);
	buflen = PATH_MAX;
	buf = kmalloc(buflen, GFP_KERNEL);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	memset(buf, 0, buflen);
	p = prlfs_get_path(dentry, buf, &buflen);
	if (IS_ERR(p)) {
		ret = PTR_ERR(p);
		goto out_free;
	}
	pfd = kmalloc(sizeof(struct prlfs_fd), GFP_KERNEL);
	if (pfd == NULL) {
		ret = -ENOMEM;
		goto out_free;
	}
	memset(pfd, 0, sizeof(struct prlfs_fd));
	DPRINTK("file %s\n", p);
	DPRINTK("flags %x\n", pfi.flags);
	ret = host_request_open(sb, &pfi, p, buflen);
	if (ret < 0)
		kfree(pfd);
	else {
		pfd->fd = pfi.fd;
		pfd->sfid = pfi.sfid;
		filp->private_data = pfd;
	}
	dentry->d_time = 0;
out_free:
	kfree(buf);
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static int prlfs_release(struct inode *inode, struct file *filp)
{
	struct super_block *sb = inode->i_sb;
	struct prlfs_file_info pfi;
	int ret;

	DPRINTK("ENTER\n");
	init_pfi(&pfi, PFD(filp)->fd, PFD(filp)->sfid, 0, 0);
	ret = host_request_release(sb, &pfi);
	if (ret < 0)
		printk(KERN_ERR "prlfs_release returns error (%d)\n", ret);
	kfree(filp->private_data);
	filp->private_data = NULL;
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static unsigned char prlfs_filetype_table[PRLFS_FILE_TYPE_MAX] = {
	DT_UNKNOWN,
	DT_REG,
	DT_DIR,
	DT_LNK,
};

static int prlfs_fill_dir(struct file *filp,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
					struct dir_context *ctx,
#else
					void *dirent, filldir_t filldir,
#endif
					loff_t *pos, void *buf, int buflen)
{
	struct super_block *sb;
	prlfs_dirent *de;
	int offset, ret, name_len, rec_len;
	u64 ino;
	u8 type;

	DPRINTK("ENTER\n");
	assert(FILE_DENTRY(filp));
	assert(FILE_DENTRY(filp)->d_sb);
	sb = FILE_DENTRY(filp)->d_sb;
	offset = 0;
	ret = 0;

	while (1) {
		de = (prlfs_dirent *)(buf + offset);
		if (offset + sizeof(prlfs_dirent) > buflen)
			goto out;

		name_len = de->name_len;
		if (name_len == 0)
			goto out;

		rec_len = PRLFS_DIR_REC_LEN(name_len);
		if (rec_len + offset > buflen) {
			printk(PFX "invalid rec_len %d "
			       "(name_len %d offset %d buflen %d)\n",
				rec_len, name_len, offset, buflen);
			ret = -EINVAL;
			goto out;
		}
		if (de->name[name_len] != 0) {
			printk(PFX "invalid file name "
			       "(name_len %d offset %d buflen %d)\n",
				name_len, offset, buflen);
			ret = -EINVAL;
			goto out;
		}
		type = de->file_type;
		if (type >= PRLFS_FILE_TYPE_MAX) {
			printk(PFX "invalid file type: %x, "
				"use UNKNOWN type instead "
				"(name_len %d offset %d buflen %d)\n",
				type, name_len, offset, buflen);
			type = PRLFS_FILE_TYPE_UNKNOWN;
		}
		type = prlfs_filetype_table[type];
		ino = iunique(sb, PRLFS_GOOD_INO);
		DPRINTK("filldir: name %s len %d, offset %lld, "
						"de->type %d -> type %d\n",
			 de->name, name_len, (*pos), de->file_type, type);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
		if (!dir_emit(ctx, de->name, name_len, ino, type))
#else
		if (filldir(dirent, de->name, name_len, (*pos), ino, type) < 0)
#endif
			goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
		ctx->pos++;
#endif
		offset += rec_len;
		(*pos)++;
	}
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
static int prlfs_readdir(struct file *filp, struct dir_context *ctx)
#else
static int prlfs_readdir(struct file *filp, void *dirent, filldir_t filldir)
#endif
{
	struct prlfs_file_info pfi;
	struct super_block *sb;
	int ret, len, buflen;
	void *buf;
	off_t prev_offset;

	DPRINTK("ENTER\n");
	ret = 0;
	init_pfi(&pfi, PFD(filp)->fd, PFD(filp)->sfid,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
		ctx->pos,
#else
		filp->f_pos,
#endif
		0);
	assert(FILE_DENTRY(filp));
	assert(FILE_DENTRY(filp)->d_sb);
	sb = FILE_DENTRY(filp)->d_sb;
	buflen = PAGE_SIZE;
	buf = kmalloc(buflen, GFP_KERNEL);
	if (buf == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	while (pfi.flags == 0) {
		len = buflen;
		memset(buf, 0, len);
		ret = host_request_readdir(sb, &pfi, buf, &len);
		if (ret < 0)
			break;

		prev_offset = pfi.offset;
		ret = prlfs_fill_dir(filp,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
					ctx,
#else
					dirent, filldir,
#endif
					&pfi.offset, buf, len);
		if (ret < 0)
			break;
		if (pfi.offset == prev_offset)
			break;
	}
	kfree(buf);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
	ctx->pos = pfi.offset;
#else
	filp->f_pos = pfi.offset;
#endif
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

static ssize_t prlfs_rw(struct file *filp, char *buf, size_t size,
			loff_t *off, unsigned int rw, int user, int flags)
{
	ssize_t ret;
	struct dentry *dentry;
	struct super_block *sb;
	struct prlfs_file_info pfi;
	struct buffer_descriptor bd;

	DPRINTK("ENTER\n");
	if (rw >= 2) {
		printk(PFX "Incorrect rw operation %d\n", rw);
		BUG();
	}
	ret = 0;
	init_pfi(&pfi, PFD(filp)->fd, PFD(filp)->sfid, *off, rw);
	dentry = FILE_DENTRY(filp);

	if (size == 0)
		goto out;

	sb = dentry->d_sb;
	init_buffer_descriptor(&bd, buf, size,(rw == 0) ? 1 : 0,
						(user == 0) ? 0 : 1);
	bd.flags = flags;
	ret = host_request_rw(sb, &pfi, &bd);
	if (ret < 0)
		goto out;

	size = bd.len;
	(*off) += size;
	ret = size;
out:
	DPRINTK("EXIT returning %lld\n", (long long)ret);
	return ret;
}

static ssize_t prlfs_read(struct file *filp, char *buf, size_t size,
								loff_t *off)
{
	return prlfs_rw(filp, buf, size, off, 0, 1, TG_REQ_COMMON);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)

#define prlfs_inode_lock(i) inode_lock(i)
#define prlfs_inode_unlock(i) inode_unlock(i)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)

#define prlfs_inode_lock(i) mutex_lock(&(i)->i_mutex)
#define prlfs_inode_unlock(i) mutex_unlock(&(i)->i_mutex)

#else

#define prlfs_inode_lock(i) down(&(i)->i_sem)
#define prlfs_inode_unlock(i) up(&(i)->i_sem)

#endif

static ssize_t prlfs_write(struct file *filp, const char *buf, size_t size,
								 loff_t *off)
{
	ssize_t ret;
	struct dentry *dentry = FILE_DENTRY(filp);
	struct inode *inode = dentry->d_inode;

	prlfs_inode_lock(inode);
	ret = prlfs_rw(filp, (char *)buf, size, off, 1, 1, TG_REQ_COMMON);
	dentry->d_time = 0;
	if (ret < 0)
		goto out;

	if (inode->i_size < *off)
		inode->i_size = *off;
out:
	prlfs_inode_unlock(inode);
	return ret;
}


static inline
struct page *__prlfs_get_page(struct vm_area_struct *vma, loff_t off)
{
	struct page *page;
	char *buf;
	ssize_t ret;

	if (!vma->vm_file)
		return ERR_PTR(EINVAL);

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return ERR_PTR(ENOMEM);

	buf = kmap(page);
	ret = prlfs_rw(vma->vm_file, buf, PAGE_SIZE, &off, 0, 0, TG_REQ_PF_CTX);
	if (ret < 0) {
		kunmap(page);
		put_page(page);
		return ERR_PTR(EIO);
	}
	if (ret < PAGE_SIZE)
		memset(buf + ret, 0, PAGE_SIZE - ret);
	flush_dcache_page(page);
	kunmap(page);
	return page;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)

static inline
int __prlfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page;
	loff_t off;
	int ret;

	DPRINTK("ENTER\n");
	off = vmf->pgoff << PAGE_SHIFT;
	page = __prlfs_get_page(vma, off);

	if (IS_ERR(page))
		ret = PTR_ERR(page) == ENOMEM ? VM_FAULT_OOM : VM_FAULT_SIGBUS;
	else {
		ret = 0;
		vmf->page = page;
	}

	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
static int prlfs_fault(struct vm_fault *vmf)
{
	return __prlfs_fault(vmf->vma, vmf);
}
#else
static int prlfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return __prlfs_fault(vma, vmf);
}
#endif

static struct vm_operations_struct prlfs_vm_ops = {
	.fault	= prlfs_fault,
};

#else // LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)

static struct page *prlfs_nopage(struct vm_area_struct *vma,
				 unsigned long address,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
				 int *type
#else
				 int unused
#endif
	)
{
	struct page *page;
	loff_t off;
	int ret;

	off = (address - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);
	page = __prlfs_get_page(vma, off);

	if (IS_ERR(page)) {
		if (PTR_ERR(page) == ENOMEM) {
			ret = VM_FAULT_OOM;
			page = NOPAGE_OOM;
		} else {
			ret = VM_FAULT_SIGBUS;
			page = NOPAGE_SIGBUS;
		}
	} else
		ret = VM_FAULT_MAJOR;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
	if (type)
		*type = ret;
#endif

	DPRINTK("EXIT returning %ld\n", PTR_ERR(page));
	return page;
}

static struct vm_operations_struct prlfs_vm_ops = {
	.nopage	= prlfs_nopage
};

#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 26)


static int prlfs_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret = 0;
	DPRINTK("ENTER\n");
	/* currently prlfs do not implement ->writepage */
	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE)) {
		ret = -EINVAL;
		goto out;
	}
	vma->vm_ops = &prlfs_vm_ops;
out:
	DPRINTK("EXIT returning %d\n", ret);
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
#ifdef PRL_SIMPLE_SYNC_FILE
int simple_sync_file(struct file *filp, struct dentry *dentry, int datasync)
{
	return 0;
}
#endif
#endif

struct file_operations prlfs_file_fops = {
	.open		= prlfs_open,
	.read           = prlfs_read,
	.write		= prlfs_write,
	.llseek         = generic_file_llseek,
	.release	= prlfs_release,
	.mmap		= prlfs_mmap,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
	.fsync		= noop_fsync,
#else
	.fsync		= simple_sync_file,
#endif
};

struct file_operations prlfs_dir_fops = {
	.open		= prlfs_open,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
	.iterate	= prlfs_readdir,
#else
	.readdir	= prlfs_readdir,
#endif
	.release	= prlfs_release,
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
};
