/*
 *	prltg.c
 *	Parallels ToolGate driver
 *	Copyright (c) 1999-2016 Parallels International GmbH. All rights reserved.
 *	Author:	Vasily Averin <vvs@parallels.com>
 */

#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/hash.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <asm/io.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#include <linux/libata-compat.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#define PRLVTG_MMAP
#include <linux/mm.h>
#include <video/vga.h>
#endif

#include "prltg_compat.h"
#include "Toolgate/Guest/Linux/Interfaces/prltg.h"
#include "Toolgate/Interfaces/Tg.h"

#define MODNAME		"prl_tg"
#define DRV_VERSION	"1.3.6"
#define DRIVER_LOAD_MSG	"Parallels Toolgate driver " DRV_VERSION " loaded"
#define PFX		MODNAME ": "

static char version[] = KERN_INFO DRIVER_LOAD_MSG "\n";

/* define to 1 to enable copious debugging info */
#undef DRV_DEBUG

/* define to 1 to disable lightweight runtime debugging checks */
#undef DRV_NDEBUG

#ifdef DRV_DEBUG
/* note: prints function name for you */
#  define DPRINTK(fmt, args...) printk(KERN_DEBUG "%s: " fmt, __FUNCTION__ , ## args)
#else
#  define DPRINTK(fmt, args...)
#endif

#ifdef DRV_NDEBUG
#  define assert(expr) do {} while (0)
#else
#  define assert(expr) \
        if(!(expr)) {					\
        printk( "Assertion failed! %s,%s,%s,line=%d\n",	\
        #expr,__FILE__,__FUNCTION__,__LINE__);		\
        }
#endif

typedef enum {
	TOOLGATE = 0,
	VIDEO_TOOLGATE = 1
} board_t;

static struct file_operations prl_vtg_fops;
static struct file_operations prl_tg_fops;

/* indexed by board_t, above */
static struct {
	const char *name;
	char *nick;
	struct file_operations *fops;
} board_info[] = {
	{ "Parallels ToolGate", TOOLGATE_NICK_NAME, &prl_tg_fops },
	{ "Parallels Video ToolGate", VIDEO_TOOLGATE_NICK_NAME, &prl_vtg_fops },
};

static struct pci_device_id prl_tg_pci_tbl[] = {
	{0x1ab8, 0x4000, PCI_ANY_ID, PCI_ANY_ID, 0, 0, TOOLGATE },
	{0x1ab8, 0x4005, PCI_ANY_ID, PCI_ANY_ID, 0, 0, VIDEO_TOOLGATE },
	{0,}
};
MODULE_DEVICE_TABLE (pci, prl_tg_pci_tbl);

#define TG_DEV_FLAG_MSI (1<<0)

struct tg_dev {
	board_t board;
	int drv_flags;
	unsigned int irq;
	unsigned long base_addr;
	spinlock_t queue_lock;	/* protects queue of submitted requests */
	struct list_head pending;
	struct work_struct work;
	struct pci_dev *pci_dev;
	spinlock_t lock;	/* protects device's port IO operations */
	unsigned int flags;
#ifdef PRLVTG_MMAP
	resource_size_t mem_phys, mem_size;
#endif
};

struct rq_list_entry {
	struct list_head list;
	struct completion waiting;
	TG_PAGED_REQUEST *req;
	int processed; /* protected by queue_lock */
	/* Physical address of first page of request */
	dma_addr_t phys;
	/* First page of request descriptor */
	struct page *pg;
};

/*
 * Build request pin vmalloced pages in memory to prevent swapping.
 * Also, pages got from userspace pinned too. Those pages must be
 * released at completion. As all request structures are shared between
 * lot of places - the list to store pages is good enough.
 */
struct up_list_entry {
	struct list_head list;
	int count;
	/* user pages must be marked dirty if device touched them */
	unsigned writable;
	struct page *p[0];
};

/* The rest of these values should never change. */

/* Symbolic offsets to registers. */
enum TgRegisters {
	TG_PORT_STATUS = 0,
	TG_PORT_MASK = 0,
	TG_PORT_SUBMIT = 0x8,
	TG_PORT_CANCEL = 0x10,
	TG_MAX_PORT = 0x18
};

#define VTG_HASH_BITS	4
#define VTG_HASH_SIZE	(1UL << VTG_HASH_BITS)
#define VTG_HASH_MASK	(VTG_HASH_SIZE-1)

DEFINE_SPINLOCK(vtg_hash_lock);
static struct list_head vtg_hashtable[VTG_HASH_SIZE];

struct filp_private {
	struct list_head	filp_list;
	spinlock_t		filp_lock;
};

struct vtg_buffer {
	atomic_t		refcnt;
	struct draw_bdesc	bdesc;
};

struct vtg_hash_entry {
	unsigned int		id;
	unsigned int		used;
	struct list_head	filp_list;
	struct list_head	hash_list;
	struct file		*filp;
	struct vtg_buffer	*vtg_buffer;
};

/* Port IO primitives */
static __inline u32
tg_in32(struct tg_dev *dev, unsigned long port)
{
	u32 x;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	x = inl(dev->base_addr + port);
	spin_unlock_irqrestore(&dev->lock, flags);
	return (x);
}

static __inline unsigned long
tg_in(struct tg_dev *dev, unsigned long port)
{
	unsigned long x, flags;

	spin_lock_irqsave(&dev->lock, flags);
	insl(dev->base_addr + port, &x, sizeof(unsigned long) >> 2);
	spin_unlock_irqrestore(&dev->lock, flags);
	return (x);
}

static __inline void
tg_out32(struct tg_dev *dev, unsigned long port, u32 val)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	outl(val, dev->base_addr + port);
	spin_unlock_irqrestore(&dev->lock, flags);
}

static __inline void
tg_out(struct tg_dev *dev, unsigned long port, unsigned long long val)
{
	unsigned long flags;

	DPRINTK("send %llx\n", val);
	spin_lock_irqsave(&dev->lock, flags);
	outsl(dev->base_addr + port, &val, sizeof(unsigned long long) >> 2);
	spin_unlock_irqrestore(&dev->lock, flags);
}

/* Interrupt's bottom half */
static void tg_do_work(struct work_struct *work)
{
	struct list_head completed;
	struct list_head *tmp, *n;
	struct rq_list_entry *p;
	struct tg_dev *dev = container_of(work, struct tg_dev, work);
	unsigned long flags;

	DPRINTK("ENTER\n");

	INIT_LIST_HEAD(&completed);
	spin_lock_irqsave(&dev->queue_lock, flags);
	list_for_each_safe(tmp, n, &dev->pending) {
		p = list_entry(tmp, struct rq_list_entry, list);
		if (p->req->Status == TG_STATUS_PENDING)
			continue;
		list_move(&p->list, &completed);
		p->processed = 1;
	}
	spin_unlock_irqrestore(&dev->queue_lock, flags);
	/* enable Toolgate's interrupt */
	if (!(dev->flags & TG_DEV_FLAG_MSI))
		tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);
	list_for_each_safe(tmp, n, &completed) {
		p = list_entry(tmp, struct rq_list_entry, list);
		complete(&p->waiting);
	}
	DPRINTK("EXIT\n");
}

static void tg_cancel_all(struct tg_dev *dev)
{
	struct list_head cancelled;
	struct list_head *tmp, *n;
	struct rq_list_entry *p;
	unsigned long flags;

	DPRINTK("ENTER\n");

	INIT_LIST_HEAD(&cancelled);
	spin_lock_irqsave(&dev->queue_lock, flags);
	list_for_each_safe(tmp, n, &dev->pending) {
		p = list_entry(tmp, struct rq_list_entry, list);
		if (p->req->Status == TG_STATUS_PENDING) {
			list_move(&p->list, &cancelled);
			p->processed = 1;
		}
	}
	spin_unlock_irqrestore(&dev->queue_lock, flags);

	list_for_each(tmp, &cancelled) {
		p = list_entry(tmp, struct rq_list_entry, list);
		tg_out(dev, TG_PORT_CANCEL, p->phys);
	}
	/* waiting host's confirmation up to several seconds */
	list_for_each_safe(tmp, n, &cancelled) {
		int timeout = 1;

		p = list_entry(tmp, struct rq_list_entry, list);
		while ((p->req->Status == TG_STATUS_PENDING) &&
							(timeout < 4*HZ)) {
			msleep(timeout);
			timeout *= 2;
		}
		if (p->req->Status == TG_STATUS_PENDING)
			/* Host don't cancel request. If we free it we can get
			 * the memory corruption if host will handle it later.
			 * If we don't free it, we'll leak the memory if host
			 * forget about this request. I think memory leak is
			 * better than memory corruption */
			 printk(KERN_ERR PFX "Host don't handle "
					"request's cancel %p\n", p->req);
		else
			complete(&p->waiting);
	}
	DPRINTK("EXIT\n");
}

static void tg_submit(TG_PAGED_REQUEST *dst, struct pci_dev *pdev, int flags)
{
	unsigned long lock_flags;
	struct rq_list_entry rq;
	struct tg_dev *dev = pci_get_drvdata(pdev);
	int ret = 0, processed;

	DPRINTK("ENTER\n");

	/*
	 * Request memory allocated via vmalloc, so this conversion is possible and
	 * also no any offset inside page needed.
	 */
	rq.pg = vmalloc_to_page(dst);
	rq.phys = pci_map_page(pdev, vmalloc_to_page(dst), 0, PAGE_SIZE,
			       PCI_DMA_BIDIRECTIONAL);

	if (!rq.phys) {
		DPRINTK("Can not allocate memory for DMA mapping\n");
		goto out;
	}

	/* First page must be pinned, others should be pinned by build_request */
	page_cache_get(rq.pg);

	tg_out(dev, TG_PORT_SUBMIT, rq.phys);
	/* is request already completed? */
	if (dst->Status != TG_STATUS_PENDING)
		goto out;

	INIT_LIST_HEAD(&rq.list);
	init_completion(&rq.waiting);
	rq.req = dst;
	rq.processed = 0;
	spin_lock_irqsave(&dev->queue_lock, lock_flags);
	/* we can miss interrupt */
	if (dst->Status != TG_STATUS_PENDING) {
		spin_unlock_irqrestore(&dev->queue_lock, lock_flags);
		goto out;
	}
	list_add_tail(&rq.list, &dev->pending);
	spin_unlock_irqrestore(&dev->queue_lock, lock_flags);
	/* request can be handled by host, interrupted by signal
         * or cancelled by suspend */
	DPRINTK("waiting\n");
	if (flags & TG_REQ_PF_CTX)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
		ret = wait_for_completion_killable(&rq.waiting);
#else
		wait_for_completion(&rq.waiting);
#endif
	else
		ret = wait_for_completion_interruptible(&rq.waiting);
	if (ret >= 0)
		goto out;

	DPRINTK("interrupted by signal\n");
	if (dst->Status != TG_STATUS_PENDING)
		goto out_wait;

	tg_out(dev, TG_PORT_CANCEL, rq.phys);
	DPRINTK("cancelled\n");

	if (dst->Status == TG_STATUS_PENDING)
		goto out_wait;

	spin_lock_irqsave(&dev->queue_lock, lock_flags);

	processed = rq.processed;
	if (!processed)
		list_del(&rq.list);

	spin_unlock_irqrestore(&dev->queue_lock, lock_flags);

	if (!processed)
		/* Now we are sure that nobody will
		 * complete this request */
		goto out;

out_wait:
	/* we must wait for completion, it accessed rq struct*/
	DPRINTK("waiting for completion\n");
	wait_for_completion(&rq.waiting);

out:
	page_cache_release(rq.pg);
	pci_unmap_page(pdev, rq.phys, PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
	DPRINTK("EXIT\n");
	return;
}

#define INLINE_SIZE(a)	(((a)->InlineByteCount+sizeof(u64)-1)&~(sizeof(u64)-1))

static int paged_request_size(TG_REQ_DESC *sdesc)
{
	TG_REQUEST *src;
	TG_BUFFER *sbuf;
	int dpages, dsize, nbuf;

	src = sdesc->src;
	sbuf = sdesc->sbuf;
	dsize = sizeof(TG_PAGED_REQUEST) + INLINE_SIZE(src);
	for (nbuf = 0; nbuf < src->BufferCount; ++nbuf, ++sbuf) {
		dsize += sizeof(TG_PAGED_BUFFER);
		if (sbuf->ByteCount) {
			int npages = ((sbuf->u.Va & ~PAGE_MASK) +
				sbuf->ByteCount + ~PAGE_MASK) >> PAGE_SHIFT;
			dsize += npages * sizeof(u64);
		}
	}
	/*
	 * If the request is large enough it needs its own page list
	 * note1: first page index is part of TG_PAGED_REQUEST
	 * note2: page indices are part of request, we may need more
	 * pages to fit all page indicies, so we iterate until all fit
	 */
	for (dpages = 1; ; ) {
		long delta = 1 + ((dsize - 1) >> PAGE_SHIFT) - dpages;

		if (!delta)
			break;
		dpages += delta;
		dsize += delta * sizeof(u64);
	}
	return dsize;
}

static inline void release_user_pages(struct list_head *up_list)
{
	struct up_list_entry *uple, *tmp;
	int i;

	list_for_each_entry_safe(uple, tmp, up_list, list) {
		list_del_init(&uple->list);

		if (uple->writable)
			for(i = 0; i < uple->count; i++)
				SetPageDirty(uple->p[i]);

		for(i = 0; i < uple->count; i++)
			page_cache_release(uple->p[i]);

		kfree(uple);
	}
}

/* releases request pages taken on request build stage */
static void put_request_pages(TG_PAGED_BUFFER *dbuf, TG_BUFFER *sbuf, int nbuf,
			      struct list_head *up_list,
			      struct pci_dev *dev)
{
	int i, j, npages;

	for (i = 0 ; i < nbuf; i++, sbuf++) {
		u64 *pfn;

		npages = ((dbuf->Va & ~PAGE_MASK) +
				dbuf->ByteCount + ~PAGE_MASK) >> PAGE_SHIFT;

		pfn = (u64 *)(dbuf + 1);
		for (j = 0; j < npages; j++, pfn++)
			pci_unmap_page(dev, *pfn << PAGE_SHIFT, PAGE_SIZE,
				       PCI_DMA_BIDIRECTIONAL);

		dbuf = (TG_PAGED_BUFFER *)((u64 *)(dbuf + 1) + npages);
	}

	release_user_pages(up_list);
}

static TG_PAGED_BUFFER *map_user_request(TG_PAGED_BUFFER *buf, TG_BUFFER *sbuf,
					 int npages, struct pci_dev *dev,
					 struct list_head *up_list)
{
	struct up_list_entry *uple;
	int i, got, mapped = 0;
	u64 *pfn;

	uple = (struct up_list_entry *)kmalloc(sizeof(struct up_list_entry) +
					       sizeof(struct page *) * npages,
					       GFP_KERNEL);
	if (!uple)
		goto err;

	uple->writable = buf->Writable;
	uple->count = npages;

	down_read(&current->mm->mmap_sem);
	/* lock userspace pages */
	got = prl_get_user_pages(
			     sbuf->u.Va, npages,
			     sbuf->Writable,
			     uple->p, NULL);
	up_read(&current->mm->mmap_sem);

	if (got < npages)
		goto err_put;

	buf = (TG_PAGED_BUFFER *)((u64 *)buf + npages);
	pfn = (u64 *)buf - 1;

	for (; npages > 0; npages--, mapped++) {
		dma_addr_t addr = pci_map_page(dev, uple->p[npages-1], 0,
					       PAGE_SIZE,
					       PCI_DMA_BIDIRECTIONAL);
		if (!addr)
			goto err_unmap;

		*(pfn--) = (u64)addr >> PAGE_SHIFT;
	}

	list_add(&uple->list, up_list);
	return buf;

err_unmap:
	for (i = 0; i < mapped; i++, pfn++)
		pci_unmap_page(dev, *pfn << PAGE_SHIFT, PAGE_SIZE,
			       PCI_DMA_BIDIRECTIONAL);

err_put:
	for(i = 0; i < got; i++)
		page_cache_release(uple->p[i]);

	kfree(uple);
err:
	return ERR_PTR(-ENOMEM);
}

static TG_PAGED_BUFFER *map_kernel_request(TG_PAGED_BUFFER *buf, TG_BUFFER *sbuf,
					 int npages, struct pci_dev *dev)
{
	int i;
	u64 *pfn = (u64 *)buf;
	char *buffer = (char *)sbuf->u.Buffer;

	for (i = 0; i < npages; i++, buffer += PAGE_SIZE) {
		dma_addr_t addr;
		struct page *pg = virt_to_page(buffer);

		addr = pci_map_page(dev, pg, 0, PAGE_SIZE,
				    PCI_DMA_BIDIRECTIONAL);

		if (!addr)
			goto err;

		*(pfn++) = addr >> PAGE_SHIFT;
	}

	return (TG_PAGED_BUFFER *)((u64 *)buf + npages);

err:
	for (; i > 0; i--, pfn--)
		pci_unmap_page(dev, *pfn << PAGE_SHIFT, PAGE_SIZE,
			       PCI_DMA_BIDIRECTIONAL);

	return ERR_PTR(-ENOMEM);
}

static int map_internal_req(TG_UINT64 *pages, char* mem, int count,
			    struct list_head *up_list, struct pci_dev *dev)
{
	int i;
	struct up_list_entry *uple;

	uple = (struct up_list_entry *)kmalloc(sizeof(struct up_list_entry) +
					       sizeof(struct page *) * count,
					       GFP_KERNEL);

	if (!uple)
		return -ENOMEM;

	uple->writable = 0;
	uple->count = 0;

	for (i = 0; i < count; i++, mem += PAGE_SIZE, uple->count++) {
		uple->p[i] = vmalloc_to_page(mem);
		page_cache_get(uple->p[i]);

		pages[i] = pci_map_page(dev, uple->p[i], 0, PAGE_SIZE,
					PCI_DMA_BIDIRECTIONAL) >> PAGE_SHIFT;
		if (!pages[i]) {
			page_cache_release(uple->p[i]);
			goto err;
		}
	}

	list_add(&uple->list, up_list);
	return 0;
err:
	for (i = 0; i < uple->count; i++) {
		pci_unmap_page(dev, pages[i] << PAGE_SHIFT,
			       PAGE_SIZE, PCI_DMA_BIDIRECTIONAL);
		page_cache_release(uple->p[i]);
	}
	kfree(uple);
	return -ENOMEM;
}

static inline void unmap_internal_req(TG_UINT64 *pages, int count, struct pci_dev *dev)
{
	int i;

	for (i = 0; i < count; i++)
		pci_unmap_page(dev, pages[i] << PAGE_SHIFT, PAGE_SIZE,
			       PCI_DMA_BIDIRECTIONAL);
}

static int build_request(TG_REQ_DESC *sdesc, TG_PAGED_REQUEST *dst, int dsize,
			 struct pci_dev *dev, struct list_head *up_list)
{
	TG_REQUEST *src;
	TG_BUFFER *sbuf;
	TG_PAGED_BUFFER *dbuf;
	int npages, dpages;
	int nbuf;
	int ret;

	DPRINTK("ENTER\n");
	src = sdesc->src;

	dst->RequestSize = dsize;
	dst->Request = src->Request;
	dst->Status = TG_STATUS_PENDING;
	dst->InlineByteCount = src->InlineByteCount;
	dst->BufferCount = src->BufferCount;

	dpages = (((unsigned long)dst & ~PAGE_MASK) +
				dst->RequestSize + ~PAGE_MASK) >> PAGE_SHIFT;

	ret = map_internal_req(dst->RequestPages, (char*)dst, dpages, up_list, dev);

	if (ret < 0)
		goto out;

	sbuf = sdesc->sbuf;
	if (src->InlineByteCount != 0)
		memcpy(&dst->RequestPages[dpages], sdesc->idata,
							src->InlineByteCount);

	dbuf = (TG_PAGED_BUFFER *)
		((char *)&dst->RequestPages[dpages] + INLINE_SIZE(src));

	for (nbuf = 0; nbuf < src->BufferCount; nbuf++, sbuf++) {
		if (!sbuf->ByteCount) {
			dbuf->Va = 0;
			dbuf->ByteCount = 0;
			dbuf->Writable = 0;
			dbuf->Reserved = 0;
			dbuf++;
			continue;
		}

		dbuf->Va = sbuf->u.Va;
		dbuf->ByteCount = sbuf->ByteCount;
		dbuf->Writable = sbuf->Writable;
		dbuf->Reserved = 0;

		npages = ((sbuf->u.Va & ~PAGE_MASK) +
			sbuf->ByteCount + ~PAGE_MASK) >> PAGE_SHIFT;

		if (sbuf->Userspace == 1)
			dbuf = map_user_request(dbuf + 1, sbuf, npages, dev, up_list);
		else
			dbuf = map_kernel_request(dbuf + 1, sbuf, npages, dev);

		if (IS_ERR(dbuf)) {
			ret = PTR_ERR(dbuf);
			goto err;
		}
	}
	ret = 0;
out:
	DPRINTK("EXIT, returning %d\n", ret);
	return ret;

err:
	unmap_internal_req(dst->RequestPages, dpages, dev);
	dbuf = (TG_PAGED_BUFFER *)
		((char *)&dst->RequestPages[dpages] + INLINE_SIZE(src));
	/* release previous buffer pages */
	put_request_pages(dbuf, sdesc->sbuf, nbuf, up_list, dev);
	goto out;
}

static void complete_request(TG_REQ_DESC *sdesc, TG_PAGED_REQUEST *dst,
			     struct pci_dev *dev, struct list_head *up_list)
{
	TG_REQUEST *src;
	TG_BUFFER *sbuf;
	TG_PAGED_BUFFER *dbuf;
	int dpages, nbuf;

	DPRINTK("ENTER\n");
	src = sdesc->src;
	src->Status = dst->Status;
	if (src->InlineByteCount != dst->InlineByteCount)
		printk(PFX "InlineByteCounts are not equal: src %d dst %d\n",
			src->InlineByteCount, dst->InlineByteCount);

	dpages = (((unsigned long)dst & ~PAGE_MASK) +
			dst->RequestSize + ~PAGE_MASK) >> PAGE_SHIFT;

	unmap_internal_req(dst->RequestPages, dpages, dev);

	if (src->InlineByteCount != 0) {
		if (dst->Status == TG_STATUS_SUCCESS)
			memcpy(sdesc->idata, &dst->RequestPages[dpages],
				src->InlineByteCount);
	}
	sbuf = sdesc->sbuf;
	dbuf = (TG_PAGED_BUFFER *)
		((char *)&dst->RequestPages[dpages] + INLINE_SIZE(src));

	for (nbuf = 0; nbuf < src->BufferCount; nbuf++, sbuf++) {
		int npages;
		u64 *pfn;

		if (!sbuf->ByteCount) {
			dbuf++;
			continue;
		}

		npages = ((sbuf->u.Va & ~PAGE_MASK) +
			sbuf->ByteCount + ~PAGE_MASK) >> PAGE_SHIFT;

		pfn = (u64 *)(dbuf + 1);
		if (dst->Status == TG_STATUS_SUCCESS)
			sbuf->ByteCount = dbuf->ByteCount;

		dbuf = (TG_PAGED_BUFFER *)((u64 *)(dbuf + 1) + npages);

		for (; npages > 0; npages--, pfn++)
			pci_unmap_page(dev, (*pfn) << PAGE_SHIFT, PAGE_SIZE,
				       PCI_DMA_BIDIRECTIONAL);
	}

	release_user_pages(up_list);

	DPRINTK("EXIT\n");
	return;
}

static int complete_userspace_request(char *u, TG_REQ_DESC *sdesc)
{
	int i, ret;
	TG_REQUEST *src;
	TG_BUFFER *sbuf;

	DPRINTK("ENTER\n");
	ret = 0;

	src = sdesc->src;
	/* copy request status back to userspace */
	if (copy_to_user(u, src, sizeof(TG_REQUEST)))
		ret = -EFAULT;

	u += sizeof(TG_REQUEST);
	/* copy inline data back to userspace */
	if ((src->InlineByteCount != 0) && (src->Status == TG_STATUS_SUCCESS) &&
	    (copy_to_user(u, sdesc->idata, src->InlineByteCount)))
		ret = -EFAULT;

	sbuf = sdesc->sbuf;
	u += INLINE_SIZE(src) + offsetof(TG_BUFFER, ByteCount);
	for (i = 0; i < src->BufferCount; i++) {
		/* copy buffer's ButeCounts back to userspace */
		if ((src->Status != TG_STATUS_CANCELLED) &&
		    copy_to_user(u, &sbuf->ByteCount, sizeof(sbuf->ByteCount)))
			ret = -EFAULT;
		sbuf++;
		u += sizeof(TG_BUFFER);
	}
	DPRINTK("EXIT, returning %d\n", ret);
	return ret;
}

int call_tg_sync(struct pci_dev *pdev, TG_REQ_DESC *sdesc)
{
	TG_PAGED_REQUEST *dst;
	int ret, dsize;
	struct list_head up_list;

	DPRINTK("ENTER\n");
	INIT_LIST_HEAD(&up_list);
	dsize = paged_request_size(sdesc);
	dst = vmalloc(dsize);
	if (dst == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	build_request(sdesc, dst, dsize, pdev, &up_list);
	tg_submit(dst, pdev, sdesc->flags);
	complete_request(sdesc, dst, pdev, &up_list);
	vfree(dst);
	ret = 0;
out:
	DPRINTK("EXIT, returning %d status %x \n", ret, sdesc->src->Status);
	return ret;
}
EXPORT_SYMBOL(call_tg_sync);

static struct vtg_buffer * replace_buffer(TG_REQ_DESC *);

static inline void put_vtg_buffer(struct vtg_buffer *vb)
{
	if (vb && atomic_dec_and_test(&vb->refcnt)) {
		kfree(vb->bdesc.u.pbuf);
		kfree(vb);
	}
}

static ssize_t
prl_tg_write(struct file *file, const char __user *buf, size_t nbytes,
								 loff_t *ppos)
{
	const struct inode *ino = FILE_DENTRY(file)->d_inode;
	struct tg_dev *dev = PDE_DATA(ino);
	TG_REQ_DESC sdesc;
	TG_REQUEST hdr, *src;
	TG_BUFFER *sbuf = NULL;
	TG_PAGED_REQUEST *dst;
	struct vtg_buffer *vb = NULL;
	void *ureq, *u;
	int ssize, dsize;
	int i, ret;
	struct list_head up_list;

	DPRINTK("ENTER\n");

	INIT_LIST_HEAD(&up_list);

	if ((nbytes != sizeof(TG_REQUEST *)) && !PRL_32BIT_COMPAT_TEST) {
		ret = -EINVAL;
		goto err;
	}
	ureq = 0;
	/* read userspace pointer */
	if (copy_from_user(&ureq, buf, nbytes)) {
		ret = -EFAULT;
		goto err;
	}
	src = &hdr;
	/* read request header from userspace */
	if (copy_from_user(src, ureq, sizeof(TG_REQUEST))) {
		ret = -EFAULT;
		goto err;
	}
	/*
	 * requests up to TG_REQUEST_SECURED_MAX are for drivers only and are
	 * denied by guest driver if come from user space to maintain guest
	 * kernel integrity (prevent malicious code from sending FS requests)
	 * dynamically assigned requests start from TG_REQUEST_MIN_DYNAMIC
	 */
	if (src->Request <= TG_REQUEST_SECURED_MAX) {
		ret = -EINVAL;
		goto err;
	}
	memset(&sdesc, 0, sizeof(TG_REQ_DESC));
	sdesc.src = src;
	u = ureq + sizeof(TG_REQUEST);
	if (src->InlineByteCount) {
		sdesc.idata = vmalloc(src->InlineByteCount);
		if (sdesc.idata == NULL) {
			ret = -ENOMEM;
			goto err;
		}
		if (copy_from_user(sdesc.idata, u, src->InlineByteCount)) {
			ret = -EFAULT;
			goto err_vm;
		}
	}
	u += INLINE_SIZE(src);
	if (src->BufferCount) {
		/* allocate memory for request's buffers */
		ssize = src->BufferCount * sizeof(TG_BUFFER);
		sbuf = vmalloc(ssize);
		if (!sbuf) {
			ret = -ENOMEM;
			goto err_vm;
		}
		/* copy buffer descriptors from userspace */
		if (copy_from_user(sbuf, u, ssize)) {
			ret = -EFAULT;
			goto err_vm;
		}
		sdesc.sbuf = sbuf;
		/* Mark buffers as 'Userspace' */
		for (i = 0; i < src->BufferCount; i++, sbuf++)
			sbuf->Userspace = 1;

		if (src->Request == TG_REQUEST_GL_COMMAND)
			vb = replace_buffer(&sdesc);
	}
	/* calculate size of the paged request */
	dsize = paged_request_size(&sdesc);

	/* allocater the memory for paged request */
	dst = vmalloc(dsize);
	if (dst == NULL) {
		ret = -ENOMEM;
		goto err_vtg;
	}
	/* filling the paged request */
	ret = build_request(&sdesc, dst, dsize, dev->pci_dev, &up_list);
	if (ret)
		goto err_vm1;
	/* submittng paged request to host */
	tg_submit(dst, dev->pci_dev, TG_REQ_COMMON);
	/* complete request */
	complete_request(&sdesc, dst, dev->pci_dev, &up_list);
	/* copy requiered data back to userspace */
	ret = complete_userspace_request(ureq, &sdesc);
err_vm1:
	/* free allocated memory */
	vfree(dst);

err_vtg:
	if (vb)
		put_vtg_buffer(vb);
err_vm:
	if (sdesc.sbuf)
		vfree(sdesc.sbuf);
	if (sdesc.idata)
		vfree(sdesc.idata);
err:
	DPRINTK("EXIT, returning %d\n", ret);
	return ret;
}

static inline void get_vtg_buffer(struct vtg_buffer *vb)
{
	if (vb)
		atomic_inc(&vb->refcnt);
}

static struct vtg_buffer * replace_buffer(TG_REQ_DESC *sdesc)
{
	TG_REQUEST *src;
	TG_BUFFER *sbuf;
	struct vtg_buffer *vb = NULL;
	unsigned id;
	struct list_head *head, *tmp;
	struct vtg_hash_entry *p;

	src = sdesc->src;
	if (src->BufferCount != 4)
		goto out;

	if (src->InlineByteCount < sizeof(unsigned)*3)
		goto out;

	id = *((unsigned *)sdesc->idata + 2);

	head = &vtg_hashtable[hash_ptr((void *)(unsigned long)id, VTG_HASH_BITS)];
	spin_lock(&vtg_hash_lock);
	list_for_each(tmp, head) {
		p = list_entry(tmp, struct vtg_hash_entry, hash_list);
		if (p->id == id) {
			vb = p->vtg_buffer;
			get_vtg_buffer(vb);
			p->used++;
			break;
		}
	}
	spin_unlock(&vtg_hash_lock);

	if (!vb)
		goto out;

	sbuf = sdesc->sbuf;
	sbuf += 3;
	sbuf->u.Va = vb->bdesc.u.va;
	sbuf->ByteCount = vb->bdesc.bsize;
	sbuf->Writable = 0;
	sbuf->Userspace = 0;

out:
	return vb;
}

static int prl_vtg_open (struct inode *inode, struct file *filp)
{
	struct filp_private *fp;
	int ret;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	ret = -ENOMEM;
	fp = kmalloc(sizeof(*fp), GFP_KERNEL);
	if (fp == NULL)
		goto out;

	memset (fp, 0, sizeof(*fp));
	spin_lock_init(&fp->filp_lock);
	INIT_LIST_HEAD(&fp->filp_list);
	filp->private_data = fp;
#ifdef FMODE_ATOMIC_POS
	filp->f_mode &= ~FMODE_ATOMIC_POS;
#endif
	ret = 0;
out:
	return ret;
}

static int prl_tg_open (struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

#ifdef FMODE_ATOMIC_POS
	filp->f_mode &= ~FMODE_ATOMIC_POS;
#endif
	return 0;
}

static int prl_vtg_release (struct inode *inode, struct file *filp)
{
	struct filp_private *fp;
	struct vtg_hash_entry *p;

	fp = filp->private_data;
	p = NULL;

	while (!list_empty(&fp->filp_list)) {
		struct list_head *tmp;

		spin_lock(&fp->filp_lock);
		if (unlikely(list_empty(&fp->filp_list))) {
			spin_unlock(&fp->filp_lock);
			break;
		}
		tmp = fp->filp_list.next;
		list_del(tmp);
		p = list_entry(tmp, struct vtg_hash_entry, filp_list);
		spin_unlock(&fp->filp_lock);
		spin_lock(&vtg_hash_lock);
		list_del(&p->hash_list);
		spin_unlock(&vtg_hash_lock);
		put_vtg_buffer(p->vtg_buffer);
		kfree(p);
	}
	kfree(fp);
	module_put(THIS_MODULE);
	return 0;
}

static int prl_tg_release(struct inode *inode, struct file *filp)
{
	(void)inode;
	(void)filp;
	module_put(THIS_MODULE);
	return 0;
}

static int prl_vtg_ioctl(struct inode *inode, struct file *filp,
			unsigned int cmd, unsigned long arg)
{
	struct vtg_hash_entry *vhe, *p;
	struct vtg_buffer *vb, *old_vb;
	struct filp_private *fp;
	struct list_head *head, *tmp, *n;
	int ret;

	fp = filp->private_data;
	old_vb = NULL;
	ret = -ENOTTY;

	switch (cmd) {
	case VIDTG_CREATE_DRAWABLE:
		ret = -ENOMEM;
		vhe = kmalloc(sizeof(*vhe), GFP_KERNEL);
		if (vhe == NULL)
			goto out;

		INIT_LIST_HEAD(&vhe->filp_list);
		INIT_LIST_HEAD(&vhe->hash_list);
		vhe->id = arg;
		vhe->filp = filp;
		vhe->vtg_buffer = NULL;
		vhe->used = 0;

		head = &vtg_hashtable[hash_ptr((void *)(unsigned long)vhe->id, VTG_HASH_BITS)];
		spin_lock(&vtg_hash_lock);
		list_for_each(tmp, head) {
			p = list_entry(tmp, struct vtg_hash_entry, hash_list);
			if (p->id == arg) {
				spin_unlock(&vtg_hash_lock);
				kfree(vhe);
				ret = -EINVAL;
				goto out;
			}
		}
		list_add(&vhe->hash_list, head);
		spin_unlock(&vtg_hash_lock);
		spin_lock(&fp->filp_lock);
		list_add(&vhe->filp_list, &fp->filp_list);
		spin_unlock(&fp->filp_lock);
		ret = 0;
		break;
	case VIDTG_CLIP_DRAWABLE: {
		struct draw_bdesc hdr;
		int size;
		void __user *ptr;

		ret = -EFAULT;
		if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr)))
			goto out;
		hdr.used = 0;

		ret = -ENOMEM;
		vb = (struct vtg_buffer *)kmalloc(sizeof(*vb), GFP_KERNEL);
		if (!vb)
			goto out;

		memset(vb, 0, sizeof(*vb));
		size = hdr.bsize;
		vb->bdesc.bsize = size;
		vb->bdesc.u.pbuf = kmalloc(size, GFP_KERNEL);
		if (!vb->bdesc.u.pbuf)
			goto out_free;

		vb->bdesc.id = hdr.id;
		atomic_set(&vb->refcnt, 1);

		ptr = (void __user *)hdr.u.pbuf;

		ret = -EFAULT;
		if (copy_from_user(vb->bdesc.u.pbuf, ptr, size))
			goto out_vfree;

		head = &vtg_hashtable[hash_ptr((void *)(unsigned long)hdr.id, VTG_HASH_BITS)];
		ret = -EINVAL;
		spin_lock(&vtg_hash_lock);
		list_for_each(tmp, head) {
			p = list_entry(tmp, struct vtg_hash_entry, hash_list);
			if (p->id == hdr.id) {
				if (p->filp == filp) {
					old_vb = p->vtg_buffer;
					p->vtg_buffer = vb;
					hdr.used = p->used;
					p->used = 0;
					ret = 0;
				}
				break;
			}
		}
		spin_unlock(&vtg_hash_lock);
		if (ret)
			goto out_vfree;
		put_vtg_buffer(old_vb);
		if (copy_to_user((void __user *)arg, &hdr, sizeof(hdr)))
			ret = -EFAULT;
		break;
	}
	case VIDTG_DESTROY_DRAWABLE:
		head = &vtg_hashtable[hash_ptr((void *)arg, VTG_HASH_BITS)];
		ret = -EINVAL;
		p = NULL;
		spin_lock(&vtg_hash_lock);
		list_for_each_safe(tmp, n, head) {
			p = list_entry(tmp, struct vtg_hash_entry, hash_list);
			if (p->id == arg) {
				if (p->filp == filp) {
					old_vb = p->vtg_buffer;
					p->vtg_buffer = NULL;
					list_del(&p->hash_list);
					ret = 0;
				}
				break;
			}
		}
		spin_unlock(&vtg_hash_lock);
		if (!ret) {
			spin_lock(&fp->filp_lock);
			list_del(&p->filp_list);
			spin_unlock(&fp->filp_lock);
			put_vtg_buffer(old_vb);
			kfree(p);
		}
		break;
#ifdef PRLVTG_MMAP
	case VIDTG_GET_MEMSIZE: {
		const struct inode *ino = FILE_DENTRY(filp)->d_inode;
		struct tg_dev *dev = PDE_DATA(ino);
		unsigned int memsize = dev->mem_size;
		ret = copy_to_user((void __user *)arg, &memsize, sizeof(memsize));
		break;
	}
	case VIDTG_ACTIVATE_SVGA: {
		outb(0xae, VGA_SEQ_I);
		outb((arg == 0) ? 0 : 1, VGA_SEQ_D);
		ret = 0;
		break;
	}
#endif
	}
out:
	return ret;

out_vfree:
	kfree(vb->bdesc.u.pbuf);
out_free:
	kfree(vb);
	goto out;
}

#ifdef HAVE_UNLOCKED_IOCTL
static long prl_vtg_unlocked_ioctl(struct file *filp,
			unsigned int cmd, unsigned long arg)
{
	return prl_vtg_ioctl(NULL, filp, cmd, arg);
}
#endif

#ifdef PRLVTG_MMAP
static int prlvtg_mmap(struct file *filp, struct vm_area_struct *vma)
{
	const struct inode *ino = FILE_DENTRY(filp)->d_inode;
	struct tg_dev *dev = PDE_DATA(ino);
	unsigned long len = vma->vm_end - vma->vm_start;

	if (len > dev->mem_size)
		return -EINVAL;
	return vm_iomap_memory(vma, (phys_addr_t)dev->mem_phys, len);
}
#endif

static struct file_operations prl_vtg_fops = {
	.write		= prl_tg_write,
#ifdef HAVE_OLD_IOCTL
	.ioctl		= prl_vtg_ioctl,
#endif
#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl	= prl_vtg_unlocked_ioctl,
#endif
	.open		= prl_vtg_open,
	.release	= prl_vtg_release,
#ifdef PRLVTG_MMAP
	.mmap		= prlvtg_mmap,
#endif
};

static struct file_operations prl_tg_fops = {
	.write		= prl_tg_write,
	.open		= prl_tg_open,
	.release	= prl_tg_release,
};

/* The interrupt handler */
static irqreturn_t prl_tg_interrupt(int irq, void *dev_instance)
{
	struct tg_dev *dev = (struct tg_dev *) dev_instance;
	int status = TG_MASK_COMPLETE;
	int ret = 0;

	if (!(dev->flags & TG_DEV_FLAG_MSI))
		status = tg_in32(dev, TG_PORT_STATUS);
	if (status) {
		/* if it is toolgate's interrupt schedule bottom half */
		ret = 1;
		schedule_work(&dev->work);
	}
	DPRINTK("prl_tg exiting interrupt, ret %d\n", ret);
	return IRQ_RETVAL(ret);
}

/* Initialize PCI device */
static int prl_tg_initialize(struct pci_dev *pdev, struct tg_dev *dev)
{
	int rc;

	DPRINTK ("ENTER\n");

	/* enable device (incl. PCI PM wakeup), and bus-mastering */
	rc = pci_enable_device(pdev);
	if (rc) {
		printk(KERN_ERR PFX "could not enable device\n");
		goto out;
	}

	rc = -ENODEV;

	/* make sure PCI base addr 0 is PIO */
	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_IO)) {
		printk(KERN_ERR PFX "region #0 not a PIO resource\n");
		goto err_out;
	}

	/* check for weird/broken PCI region reporting */
	if (pci_resource_len(pdev, 0) < TG_MAX_PORT) {
		printk(KERN_ERR PFX "Invalid PCI region size(s)\n");
		goto err_out;
	}

#ifdef PRLVTG_MMAP
	if (dev->board == VIDEO_TOOLGATE) {
		const int memres = 1;
		if (!(pci_resource_flags(pdev, memres) & IORESOURCE_MEM)) {
			printk(KERN_ERR PFX "region #%d not a MEM resource\n", memres);
			goto err_out;
		}
		dev->mem_phys = pci_resource_start(pdev, memres);

		// read VESA regs for MEMSIZE
		outb(0xa0, VGA_SEQ_I);
		dev->mem_size = inl(VGA_SEQ_D);
		printk(KERN_INFO
			"%s: memory physaddr %llx, size %lldMb\n",
			board_info[dev->board].name,
			dev->mem_phys, dev->mem_size);
		dev->mem_size *= 1024 * 1024;
	}
#endif
	/* Set DMA ability. Only lower 4G is possible to address */
	rc = pci_set_dma_mask(pdev,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
		DMA_64BIT_MASK
#else
		DMA_BIT_MASK(64)
#endif
		);
	if (rc) {
		printk(KERN_ERR "no usable DMA configuration\n");
		goto err_out;
	}

	rc = pci_request_region(pdev, 0, board_info[dev->board].nick);
	if (rc) {
		printk(KERN_ERR PFX "could not reserve PCI I/O and memory resources\n");
		goto err_out;
	}

	dev->base_addr = pci_resource_start(pdev, 0);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
	rc = pci_enable_msi(pdev);
	if (rc == 0)
		dev->flags |= TG_DEV_FLAG_MSI;
#endif
	dev->irq = pdev->irq;

	rc = request_irq(dev->irq, prl_tg_interrupt,
		(dev->flags & TG_DEV_FLAG_MSI) ? 0 : IRQF_SHARED, board_info[dev->board].nick, dev);
	if (rc) {
		pci_release_region(pdev, 0);
err_out:
		if (dev->board != VIDEO_TOOLGATE)
			pci_disable_device(pdev);
	}

out:
	DPRINTK("EXIT, returning %d\n", rc);
	return rc;
}

static int prl_tg_init_one(struct pci_dev *pdev,
						   const struct pci_device_id *ent)
{
	struct tg_dev *dev;
	struct proc_dir_entry *p;
	int rc;
	char proc_file[16];

/* when built into the kernel, we only print version if device is found */
#ifndef MODULE
	static int printed_version;
	if (!printed_version++)
		printk(version);
#endif

	DPRINTK ("ENTER\n");

	assert(pdev != NULL);
	assert(ent != NULL);

	rc = -ENOMEM;
	dev = kmalloc(sizeof(struct tg_dev), GFP_KERNEL);
	if (!dev)
		goto out;
	dev->flags = 0;
#ifdef PRLVTG_MMAP
	dev->mem_phys = 0, dev->mem_size = 0;
#endif
	spin_lock_init(&dev->lock);
	spin_lock_init(&dev->queue_lock);
	INIT_LIST_HEAD(&dev->pending);
	dev->pci_dev = pdev;
	dev->board = ent->driver_data;
	snprintf(proc_file, 16, "driver/%s", board_info[dev->board].nick);

	/* masks interrupts on the device probing */
	/* ayegorov@:
	 * Masking of interrupt at this step is illegal, i.e. first we have to
	 * initialize 'base_addr' variable in 'dev' data structure. Also I have
	 * commented this line, because we should know exactly should this function
	 * call be here or not!
	tg_out32(dev, TG_PORT_MASK, 0); */

	rc = prl_tg_initialize(pdev, dev);
	if (rc) {
		kfree(dev);
		goto out;
	}

	pci_set_drvdata(pdev, dev);

	INIT_WORK(&dev->work, tg_do_work);

	/* enable interrupt */
	tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);

	p = prltg_proc_create_data(proc_file,
		S_IWUGO | ((dev->board == VIDEO_TOOLGATE) ? S_IRUGO : 0),
		NULL, board_info[dev->board].fops, dev);
	if (p)
		PROC_OWNER(p, THIS_MODULE);
	else
		printk(KERN_WARNING "cannot create %s proc entry\n", proc_file);

	printk(KERN_INFO "detected %s, base addr %08lx, IRQ %d\n",
		board_info[ent->driver_data].name, dev->base_addr, dev->irq);

out:
	DPRINTK("EXIT, returning %d\n", rc);
	return rc;
}

/* Deinitialize PCI device */
static void prl_tg_deinitialize(struct pci_dev *pdev, struct tg_dev *dev)
{
	DPRINTK("ENTER\n");

	synchronize_irq(dev->irq);
	free_irq(dev->irq, dev);
	if (dev->flags & TG_DEV_FLAG_MSI) {
		dev->flags &= ~TG_DEV_FLAG_MSI;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
		pci_disable_msi(pdev);
#endif
	}
	flush_scheduled_work();

	pci_release_region(pdev, 0);
	if (dev->board != VIDEO_TOOLGATE)
		pci_disable_device(pdev);

	DPRINTK("EXIT\n");
}

static void prl_tg_remove_one(struct pci_dev *pdev)
{
	struct tg_dev *dev = pci_get_drvdata(pdev);
	char proc_file[16];

	DPRINTK("ENTER\n");

	assert(dev != NULL);

	snprintf(proc_file, 15, "driver/%s", board_info[dev->board].nick);
	remove_proc_entry(proc_file, NULL);
	tg_out32(dev, TG_PORT_MASK, 0);
	prl_tg_deinitialize(pdev, dev);
	pci_set_drvdata(pdev, NULL);
	kfree(dev);

	DPRINTK("EXIT\n");
}

#ifdef CONFIG_PM
static int prl_tg_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct tg_dev *dev = pci_get_drvdata(pdev);

	/* VvS: I don't found a way to detect hibernate on all linuxes,
	 * therore we'll cancel all request on each suspend */
	tg_cancel_all(dev);

	tg_out32(dev, TG_PORT_MASK, 0);
	prl_tg_deinitialize(pdev, dev);

	return 0;
}

static int prl_tg_resume(struct pci_dev *pdev)
{
	struct tg_dev *dev = pci_get_drvdata(pdev);
	int rc;

	rc = prl_tg_initialize(pdev, dev);
	if (!rc)
		tg_out32(dev, TG_PORT_MASK, TG_MASK_COMPLETE);

	return rc;
}
#endif /* CONFIG_PM */

static struct pci_driver prl_tg_pci_driver = {
	.name		= MODNAME,
	.id_table	= prl_tg_pci_tbl,
	.probe		= prl_tg_init_one,
	.remove		= prl_tg_remove_one,
#ifdef CONFIG_PM
	.suspend	= prl_tg_suspend,
	.resume		= prl_tg_resume,
#endif /* CONFIG_PM */
};

static int __init prl_tg_init_module(void)
{
	int i;

/* when a module, this is printed whether or not devices are found in probe */
#ifdef MODULE
	printk(version);
#endif
	for (i = 0; i < VTG_HASH_SIZE; i++)
		INIT_LIST_HEAD(&vtg_hashtable[i]);

	/* we don't return error when devices probing fails,
	 * it's required for proper supporting hot-pluggable device */
	return pci_register_driver(&prl_tg_pci_driver);
}

static void __exit prl_tg_cleanup_module(void)
{
	pci_unregister_driver(&prl_tg_pci_driver);
}

MODULE_AUTHOR ("Parallels International GmbH");
MODULE_DESCRIPTION ("Parallels toolgate driver");
MODULE_LICENSE("GPL");
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 0)
MODULE_INFO (supported, "external");
#endif

module_init(prl_tg_init_module);
module_exit(prl_tg_cleanup_module);
