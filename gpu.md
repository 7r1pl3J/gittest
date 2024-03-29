

### 架构

![GPU管理模型](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/gpu_management_model.png) 

![](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/image-20230716222710906.png)

![总体概述](https://github.com/fxlin/mali/raw/main/figs/archoverview.png)



流式多处理器（Streaming Multiprocessor、SM)是 GPU 的基本单元，每个 GPU 都由一组 SM 构成，SM 中最重要的结构就是计算核心 Core



**MIMO**

- CPU通过MMIO与GPU进行通信。
- 支持 DMA 硬件引擎传输大量数据，但应通过 MMIO 写入命令。

**GPU context**

代表GPU当前状态，每个context有自己的page table，多个context可以同时共存（可以视为类似进程的概念？），使用 Mali GPU 驱动程序时，用户应用程序首先需要创建并初始化`kbase_context`内核对象。这涉及用户应用程序打开驱动程序文件并使用生成的文件描述符进行一系列`ioctl`调用。对象`kbase_context`负责管理每个打开的驱动程序文件的资源，并且对于每个文件句柄来说都是唯一的。

**Page Table** 

- gpu页表，和CPU的page table功能一样，用于VA到PA的映射，访问GPU的地址空间
- 驻留在 GPU 内存中，其物理地址位于 GPU 通道描述符中。
- 所有通过GPU Channel提交的命令和程序都在相应的GPU虚拟地址空间中执行。
- GPU页表不仅将GPU虚拟地址翻译成GPU设备物理地址，而且将其翻译成CPU物理地址。这使得GPU页表能够将**GPU内存和CPU主内存统一到统一的GPU虚拟地址空间中**。

**GPU Channel**。

- 任何操作（例如启动内核）都是由 CPU 发出的命令驱动的。
- **命令流被提交到称为 GPU Channel的硬件单元。**
- 每个 GPU 上下文可以有一个或多个 GPU Channel。每个GPU上下文包含GPU Channel Descriptors（每个描述符被创建为GPU内存中的内存对象）。
- 每个GPU Channel Descriptor存储GPU Channel 的设置，其中包括***页表***。
- **每个GPU Channel 都有一个专用的命令缓冲区，该缓冲区分配在 CPU 通过 MMIO 可见的 GPU 内存中。**

**PCIe 条**。

- PCIe 的基址寄存器（BAR）作为 MMIO 的窗口，在 GPU 启动时进行配置。
- GPU 控制寄存器和 GPU 内存孔径映射到 BAR 上。
- 设备驱动程序使用此映射的 MMIO 窗口来配置 GPU 并访问 GPU 内存。

CPU和GPU通信主要有几下几种方式：

- 通过PCIe BAR空间映射出来的寄存器
- 通过PCIe BAR空间把GPU的内存映射到CPU的地址空间中
- 通过GPU的页表把CPU的系统内存映射到GPU的地址空间中
- 通过MSI中断

根据CPU和GPU是否共享内存，可分为两种类型的CPU-GPU架构：

![img](https://qiankunli.github.io/public/upload/kubernetes/cpu_gpu.png)

上图左是**分离式架构**，CPU和GPU各自有独立的缓存和内存，它们通过PCI-e等总线通讯。这种结构的缺点在于 PCI-e 相对于两者具有低带宽和高延迟，数据的传输成了其中的性能瓶颈。目前使用非常广泛，如PC、智能手机等。
上图右是**耦合式架构**，CPU 和 GPU 共享内存和缓存。AMD 的 APU 采用的就是这种结构。

在存储管理方面，分离式结构中 CPU 和 GPU 各自拥有独立的内存，两者共享一套虚拟地址空间，必要时会进行内存拷贝。对于耦合式结构，GPU 没有独立的内存，与 CPU 共享系统内存，由 MMU 进行存储管理。

### pipeline

这里以render pipeline为例，主要包括三部分：

- Vertex处理，做MPV（Model，View， Project trasform）和Screen mapping坐标变换，clip裁剪
- Rasterization处理，主要遍历三角形
- Fragment处理，差值计算处理顶点颜色，纹理贴图等

![GPU pipeline](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/gpu_pipeline.png)



一个典型的 GPU 设备的工作流程是:

1. 应用层调用 GPU 支持的某个 API，如 OpenGL 或 CUDA
2. OpenGL 或 CUDA 库（或者OpenCL），通过 UMD (User Mode Driver)，提交 work 到 KMD (Kernel Mode Driver)
3. Kernel Mode Driver 写 CSR MMIO，把它提交给 GPU 硬件
4. GPU 硬件开始工作… 完成后，DMA 到内存，发出中断给 CPU
5. CPU 找到中断处理程序 —— Kernel Mode Driver 此前向 OS Kernel 注册过的 —— 调用它
6. 中断处理程序找到是哪个 workload 被执行完毕了，…最终驱动唤醒相关的应用



而在gpu硬件视角来看，这种work其实就是job，Mali将所有的API 任务经过GPU驱动处理后，会将任务分解成一个个可以在GPU硬件上执行的Job（工作任务），这个任务交由Job Manager来管理，通过一个Job Description文件来描述每个Job具体要做的事情，Job Description 中包含了要处理的数据项指针地址，比如顶点缓存存储的位置和Shader程序存储的位置，通过ioctl发送给Kernel模块转换成硬件的Warp执行任务。


Job Manager是一种用于任务分配的结构。一个render pass中会包含多种job。一般而言，render pass被分解为vertex job,compute job,tile job和fragment job等等，vertex job和compute job进入no-fragment队列执行，fragment进入fragment队列执行

![Midgard软件接口](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/mali_midgard_jobs.png)

![image-20230806172837631](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/image-20230806172837631.png)

由上面我们大致就可以总结出gpu 驱动的主要作用：

1.控制  控制state，设置各种寄存器等等，设备驱动负责向硬件发送命令、配置设备参数、启动和停止设备等操作。

2.内存管理  对应的也就是数据，包括与cpu共享的内存管理，DMA管理，各种内存映射，缓存管理，页表维护管理等等。

3 任务管理  包括任务队列的管理维护，以及任务的调度等等。  

这三个方面共同构成了GPU驱动的核心功能，使得GPU可以高效地执行图形渲染和计算任务，提供强大的计算和图形处理能力。驱动在操作系统内核空间中运行，与用户空间的应用程序进行交互，实现应用程序与GPU硬件之间的桥梁，从而让应用程序可以充分利用GPU的性能和功能。

### gpu申请内存/释放

当我们用ioctl 指定mem_alloc时，最终会从linux 系统的内存管理模块分配出内存，分配的内存返回给gpu驱动后，可以写入gpu执行所需的数据（job，顶点，纹理之类的），这些数据的写入是用户通过ioctl完成的，当数据写入完成后，就可以trigger kernel driver来执行GPU硬件工作，这个时候GPU硬件需要读取前面准备好的数据，这时需要借助GPU MMU来完成地址的转换工作，否则GPU没有办法完成数据的正确读取。释放的话就是alloc_pages 对应的 free_pages

显卡使用内存，有两种的典型场景。

1. 预先分配。即预先分配好内存，然后直接使用。
2. 延迟分配。不预先分配物理内存，仅在map时分配虚拟内存，并设置page fault处理接口。当实际使用这段内存时，触发page fault，在page fault处理接口分配内存。



![img](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/alloc_memory.svg)



### job创建、提交与执行

当用户向内存填充完数据之后，用户通过ioctl 将该内存 “提交” 给gpu，视作一个job，具体的其实是个建立映射的过程，即让gpu 页表可以映射到该内存。

![img](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/use_memory.svg)

![img](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/job_submit.svg)



Mali GPU Job可以理解成GPU硬件能理解的IR(中间语言)，gpu driver将上层user的api（ioctl）转化为job的描述，然后将job的内存地址告诉gpu硬件，gpu硬件的job executor 就开始解析这些job，从而驱动gpu硬件完成相应工作。![img](https://blogimg-1314041910.cos.ap-guangzhou.myqcloud.com/job.png)

## 数据结构/接口

mali 驱动为用户提供的部分接口如下:

| 序号 | 命令                         |                             功能                             |
| :--- | :--------------------------- | :----------------------------------------------------------: |
| 1    | KBASE_IOCTL_MEM_ALLOC        | 分配内存区域，内存区域中的页会映射到GPU中，可选择同时映射到CPU |
| 2    | KBASE_IOCTL_MEM_QUERY        |                       查询内存区域属性                       |
| 3    | KBASE_IOCTL_MEM_FREE         |                         释放内存区域                         |
| 4    | KBASE_IOCTL_MEM_SYNC         |        同步数据，使得CPU和GPU可以及时看到对方操作结果        |
| 5    | KBASE_IOCTL_MEM_COMMIT       |                    改变内存区域中页的数量                    |
| 6    | KBASE_IOCTL_MEM_ALIAS        |   为某个内存区域创建别名，即多个GPU虚拟地址指向同一个区域    |
| 7    | KBASE_IOCTL_MEM_IMPORT       |             将CPU使用的内存页映射到GPU地址空间中             |
| 8    | KBASE_IOCTL_MEM_FLAGS_CHANGE |                       改变内存区域属性                       |
|      |                              |                                                              |

gpu driver 用 region来描述一段内存区域，一段内存区域会有用于映射该区域时gpu/cpu用于内存映射的内存分配对象 即 cpu_alloc,gpu_alloc，分别跟踪gpu/cpu当前正在使用的页面。

```c
struct kbase_va_region {
	struct rb_node rblink;
	struct list_head link;

	struct rb_root *rbtree;	/* Backlink to rb tree */

	u64 start_pfn;		/* The PFN in GPU space */
	size_t nr_pages;
	/* Initial commit, for aligning the start address and correctly growing
	 * KBASE_REG_TILER_ALIGN_TOP regions */
	size_t initial_commit;
	unsigned long flags;

	size_t extent; /* nr of pages alloc'd on PF */

	struct kbase_mem_phy_alloc *cpu_alloc; /* the one alloc object we mmap to the CPU when mapping this region */
	struct kbase_mem_phy_alloc *gpu_alloc; /* the one alloc object we mmap to the GPU when mapping this region */

	/* List head used to store the region in the JIT allocation pool */
	struct list_head jit_node;
	/* The last JIT usage ID for this region */
	u16 jit_usage_id;
	/* The JIT bin this allocation came from */
	u8 jit_bin_id;

	int    va_refcnt; /* number of users of this va */
};

```

可以看到通过start_pfn，nr_pages 即可得出region的范围

而更具体的物理页描述由struct kbase_mem_phy_alloc 描述

```c

//如果kbase_mem_phy_alloc没有与另一个区域或客户端（cpu）共享，则应仅在不持有内核映射的情况下更改nents或*pages。

struct kbase_mem_phy_alloc {
	struct kref kref;                          // 引用计数，记录该分配对象的使用者数
	atomic_t gpu_mappings;                      // 映射到GPU的次数计数，表示不同GPU VA区域对物理页面的引用次数
	atomic_t kernel_mappings;                   // 在CPU中映射的次数计数，防止在仍然持有映射时更改标志或收缩页面
	size_t nents;                               // 元素数量，范围为0到N
	struct tagged_addr *pages;                  // 元素数组，只有0到nents之间的元素是有效的
	struct list_head mappings;                  // CPU内存映射的链表
	struct list_head evict_node;                // 驱逐列表中用于存储此分配的节点
	size_t evicted;                             // 页面被驱逐时的物理支持大小
	struct kbase_va_region *reg;                // 创建此分配的区域结构的后向引用，如果已释放，则为NULL
	enum kbase_memory_type type;                // 缓冲区的类型
	struct kbase_vmap_struct *permanent_map;    // 分配的内核端映射
	unsigned long properties;                   // 属性的位掩码，例如KBASE_MEM_PHY_ALLOC_LARGE
	union {
#if defined(CONFIG_DMA_SHARED_BUFFER)
		struct {
			struct dma_buf *dma_buf;
			struct dma_buf_attachment *dma_attachment;
			unsigned int current_mapping_usage_count;
			struct sg_table *sgt;
		} umm;
#endif /* defined(CONFIG_DMA_SHARED_BUFFER) */
		struct {
			u64 stride;
			size_t nents;
			struct kbase_aliased *aliased;
		} alias;
		struct {
			struct kbase_context *kctx;
			size_t nr_struct_pages;
		} native;
		struct kbase_alloc_import_user_buf {
			unsigned long address;
			unsigned long size;
			unsigned long nr_pages;
			struct page **pages;
			/* 高位(1<<31)的current_mapping_usage_count
			 * 指定该导入在导入时已被固定
			 * 请参见PINNED_ON_IMPORT
			 */
			u32 current_mapping_usage_count;
			struct mm_struct *mm;
			dma_addr_t *dma_addrs;
		} user_buf;
	} imported;
};
```

## 映射流程

gpu申请内存主要有两种方式，一种是gpu驱动直接调用调用内核提供的内存分配函数来申请页；另一种则是通过导入cpu侧的用户内存实现共享，使用KBASE_MEM_TYPE_IMPORTED_USER_BUF类型，gpu驱动会通过get_user_pages获取该用户内存所对应的页并增加其引用计数（确保gpu使用该页面的时候不会被释放），页面会填充到kbase_mem_phy_alloc的pages数组中，在gpu不再使用该内存的时候，pages会将该页面删除并减少其引用计数。

KBASE_IOCTL_MEM_ALLOC 以及 KBASE_IOCTL_MEM_IMPORT 都可以映射内存页到gpu中，这里我们先以 KBASE_IOCTL_MEM_IMPORT为例

传参/返回值：

```c
union kbase_ioctl_mem_alloc {
	struct {
		__u64 va_pages;//待分配内存区域最多容纳的物理页数量，驱动会留出对应大小的虚拟内存空间
		__u64 commit_pages;//当前需为该内存区域分配的物理页数量，可以通过KBASE_IOCTL_MEM_COMMIT调整
		__u64 extent;
		__u64 flags;//内存区域属性 ，是否可映射/读写权限等
	} in;
	struct {
		__u64 flags;
		__u64 gpu_va;//分配内存区域在gpu中的虚拟地址
	} out;
};
```



其调用链大致如下

```c
drivers/gpu/arm/b_r32p0/mali_kbase_core_linux.c

kbase_api_mem_alloc()
|
| BASE_MEM_SAME_VA
|
|-> kbase_mem_alloc()
    |
    |-> kbase_check_alloc_flags()
    |
    |-> kbase_alloc_free_region()
    |
    |-> kbase_reg_prepare_native()
    |
    |-> kbase_alloc_phy_pages()
    |
    |-> kctx->pending_regions[cookie_nr] = reg
```

在kbase_api_mem_alloc()函数中，若是64位进程的话，则指定 flags |= BASE_MEM_SAME_VA ，含义是CPU和GPU使用相同的虚拟地址（数值上）。

kbase_mem_alloc()首先调用`kbase_check_alloc_flags()`来检查应用传入的flags是否合法 ,主要的规则是

```
1 内存区域必须映射到GPU中，映射属性可以是只读、仅可写、可读写
2 CPU和GPU至少有一方是可以读内存区域的，否则分配物理页没有意义
3 同样，至少有一方是可以写内存区域的，否则分配物理页没有意义
```

然后调用kbase_alloc_free_region（）来创建一个region

主要是通过kzalloc分配region对象，初始化相关元素

```c
	new_reg->va_refcnt = 1;
	new_reg->cpu_alloc = NULL; /* no alloc bound yet */
	new_reg->gpu_alloc = NULL; /* no alloc bound yet */
	new_reg->rbtree = rbtree;
	new_reg->flags = zone | KBASE_REG_FREE;
	new_reg->flags |= KBASE_REG_GROWABLE;
	new_reg->start_pfn = start_pfn;
	new_reg->nr_pages = nr_pages;//来自我们传入的参数，in.commit_pages
```

kbase_reg_prepare_native()函数则主要负责初始化`reg->cpu_alloc`和`reg->gpu_alloc`

```c
reg->cpu_alloc = kbase_alloc_create(kctx, reg->nr_pages,
			KBASE_MEM_TYPE_NATIVE);
//kbase_alloc_create仅仅调用了kmalloc完成结构体的内存分配，以及结构体内pages数组的分配

reg->cpu_alloc->imported.native.kctx = kctx;
	if (kbase_ctx_flag(kctx, KCTX_INFINITE_CACHE)
	    && (reg->flags & KBASE_REG_CPU_CACHED)) {
		reg->gpu_alloc = kbase_alloc_create(kctx, reg->nr_pages,
				KBASE_MEM_TYPE_NATIVE);
		if (IS_ERR_OR_NULL(reg->gpu_alloc)) {
			kbase_mem_phy_alloc_put(reg->cpu_alloc);
			return -ENOMEM;
		}
		reg->gpu_alloc->imported.native.kctx = kctx;
	} else {// 我们不指定KBASE_REG_CPU_CACHED ，reg->cpu_alloc和reg->gpu_alloc会指向同一个对象
		reg->gpu_alloc = kbase_mem_phy_alloc_get(reg->cpu_alloc);
	}
			
```

然后调用`kbase_alloc_phy_pages()`为`reg->cpu_alloc`分配物理页,该函数会调用->kbase_alloc_phy_pages_helper()->kbase_mem_pool_alloc_pages()->...->alloc_page()，向buddy system请求物理页。

之后将reg挂载到`kctx->pending_regions`数组中：

```c
	/* mmap needed to setup VA? */
	if (*flags & BASE_MEM_SAME_VA) {
		unsigned long prot = PROT_NONE;
		unsigned long va_size = va_pages << PAGE_SHIFT;
		unsigned long va_map = va_size;
		unsigned long cookie, cookie_nr;
		unsigned long cpu_addr;

		/* Bind to a cookie */
		if (!kctx->cookies) {
			dev_err(dev, "No cookies available for allocation!");
			kbase_gpu_vm_unlock(kctx);
			goto no_cookie;
		}
		/* return a cookie */
		cookie_nr = __ffs(kctx->cookies);
		kctx->cookies &= ~(1UL << cookie_nr);//在数组中找个空位位置
		BUG_ON(kctx->pending_regions[cookie_nr]);
		kctx->pending_regions[cookie_nr] = reg;
        cookie = cookie_nr + PFN_DOWN(BASE_MEM_COOKIE_BASE);
		cookie <<= PAGE_SHIFT;
        if (kctx->api_version < KBASE_API_VERSION(10, 1) ||
		    kctx->api_version > KBASE_API_VERSION(10, 4)) {
			*gpu_va = (u64) cookie;//返回cookie
			return reg;
		}

```

可以看出来，此处并没有建立gpu_va到物理页的映射，gpu_va值是一个cookie，这个值将会在真正建立映射时被使用。

如何建立映射？gpu驱动自定义了kbase_mmap函数作为mmap函数，该函数主要流程

```c
kbase_mmap(struct file *file, struct vm_area_struct *vma)
|  //struct vm_area_struct 为linux中描述虚拟内存区域的结构体
| BASE_MEM_SAME_VA
|
|-> kbase_region_tracker_find_region_enclosing_address()
|//这里做一些大小的判断，如是否会oversize，以及剩余页的计算&更新
|-> kbase_cpu_mmap()
    |
    |-> kbase_get_cpu_phy_pages()//通过region得到物理页
    |
    |-> vm_insert_pfn()
    |
    |-> kbase_mem_phy_alloc_get()
    |
    |-> kctx->pending_regions[cookie_nr] = reg
```

调用   kbase_region_tracker_find_region_enclosing_address

```
 reg = kbase_region_tracker_find_region_enclosing_address(kctx,
  (u64)vma->vm_pgoff << PAGE_SHIFT); 找到gpu_va（也就是那个cookie所对应的region）
```

建立映射

```c
if (!kaddr) {
		unsigned long addr = vma->vm_start + aligned_offset;

		vma->vm_flags |= VM_PFNMAP;
		for (i = 0; i < nr_pages; i++) {
			phys_addr_t phys;

			phys = as_phys_addr_t(page_array[i + start_off]);
			err = vm_insert_pfn(vma, addr, PFN_DOWN(phys));//建立映射
			if (WARN_ON(err))
				break;

			addr += PAGE_SIZE;
		}
	}

	map->region = kbase_va_region_alloc_get(kctx, reg);
	map->free_on_close = free_on_close;
	map->kctx = kctx;
	map->alloc = kbase_mem_phy_alloc_get(reg->cpu_alloc);
	map->count = 1; /* start with one ref */

	if (reg->flags & KBASE_REG_CPU_CACHED)
		map->alloc->properties |= KBASE_MEM_PHY_ALLOC_ACCESSED_CACHED;

	list_add(&map->mappings_list, &map->alloc->mappings);

```



```c
	/*
	 * VM_DONTCOPY - don't make this mapping available in fork'ed processes
	 * VM_DONTEXPAND - disable mremap on this region
	 * VM_IO - disables paging
	 * VM_DONTDUMP - Don't include in core dumps (3.7 only)
	 * VM_MIXEDMAP - Support mixing struct page*s and raw pfns.
	 *               This is needed to support using the dedicated and
	 *               the OS based memory backends together.
	 */
	/*
	 * This will need updating to propagate coherency flags
	 * See MIDBASE-1057
	 */
vma的flag位设置，可以看出子进程是不共享该gpu内存的
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0))
	vma->vm_flags |= VM_DONTCOPY | VM_DONTDUMP | VM_DONTEXPAND | VM_IO;
#else
	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND | VM_RESERVED | VM_IO;
```

与直接分配物理页不同，KBASE_IOCTL_MEM_IMPORT可以导入cpu的地址到gpu，

>  //如果一个内存区域与 CPU 的一致性（coherent）相关，那么这段内存会立即被导入（imported）并映射到 GPU 上。这意味着 CPU 对该内存的修改将立即反映在 GPU 上，而 GPU 对该内存的修改也将立即反映在 CPU 上，以保持一致性。
> //另一方面，如果内存区域与 CPU 的一致性无关，则会调用 get_user_pages 函数进行一个检查。在这种情况下，get_user_pages 函数会被调用，但是传入的页参数是 NULL，这会导致页错误（page fault），但不会将页面映射在内存中。然后，只有在指定该内存区域作为外部资源的作业周围，才会将该内存区域固定在内存中。有点类似linux内核的cow（写时复制）
>
> 这里需要区分固定和获取页面引用两种概念：
>
> 1. **固定页面（Page Pinning）**：对应接口如pin_user_pages()
>
>    - **定义**：固定页面是指将页面锁定在物理内存中，使其不会被操作系统的页面置换机制所替换出去。这样可以确保在页面固定期间，该页面的数据在内存中保持不变。
>    - **用途**：常用于需要临时性地确保某些页面不被换出，例如在进行高性能的数据处理、DMA（直接内存访问）传输、硬件操作等情况下。
>    - **注意**：固定页面可能导致内存紧张，因为固定的页面不能被页面置换机制回收，从而占用了额外的物理内存。
>
> 2. **获取页面引用（Page Reference**：对应接口如get_user_pages（）
>
>    - **定义**：获取页面引用是指通过操作系统提供的函数获取对页面的引用（类似于指针），可以用于读取或操作页面的数据，而不会使页面被固定。
>    - **用途**：常用于需要读取页面数据，而不需要对页面进行固定或写入操作的情况下。获取页面引用不会影响页面置换机制。
>    - **注意**：获取页面引用并不会阻止页面被替换，因此页面的数据可能在任何时候都会被置换出去。
>
>    还需要注意的是pin_user_pages()除了固定了对应的页面以外，还会增加对应页面的引用计数，unpin操作的时候会执行对应相反的操作。
>
>    显然，当gpu需要使用物理内存时，需要固定该物理内存区域从而提供更可靠的性能和一致的访问延迟。

传入的参数为

```c
union kbase_ioctl_mem_import {
	struct {
		__u64 flags; //内存页属性
		__u64 phandle;//需要导入的虚拟地址
		__u32 type;//外部内存的类型，由base_mem_import_type定义
		__u32 padding;//额外的虚拟地址页数，用于在导入的缓冲区后附加更多的虚拟地址页。
	} in;
	struct {
		__u64 flags;
		__u64 gpu_va;//返回地gpu_va ，同样也是个cookie
		__u64 va_pages;//gpu va分配的大小
	} out;
};
```



```
kbase_mem_import
-----kbase_check_import_flags
-----kbase_mem_from_user_buffer
```

kbase_check_import_flags负责检查导入的内存属性，主要要满足以下条件

```
1，flag被设置
2，gpu没有该内存的执行权限
3，该内存在gpu发生page fault时不可拓展
4，gpu至少要有读或写该内存的权限
5, 如果是secure内存，那么cpu要有读的权限
```

导入内存的type一般都是BASE_MEM_IMPORT_TYPE_USER_BUFFER，另外两个type分别需要CONFIG_DMA_SHARED_BUFFER或CONFIG_COMPAT条件。

此时会直接调用copy_from_user 获取userbuf地址和长度

```c
copy_from_user(&user_buffer, phandle,
				sizeof(user_buffer))// buff是struct base_mem_import_user_buffer，用来描述一个user buf的，只有addr和length两个元素，kbase_ioctl_mem_import.in中的phandle就对应这个
```

如果拷贝的返回为0（也就是拷贝成功），则会调用

```c
kbase_mem_from_user_buffer(kctx,
					(unsigned long)uptr, user_buffer.length,
					va_pages, flags);
同时会有一个结构体来描述该user_buf属性
		struct kbase_alloc_import_user_buf {
			unsigned long address;
			unsigned long size;
			unsigned long nr_pages;
			struct page **pages;
			
			/* top bit (1<<31) of current_mapping_usage_count
			 * specifies that this import was pinned on import
			 * See PINNED_ON_IMPORT
			 */
			u32 current_mapping_usage_count;//最高位设为1的话代表已经被import
			struct mm_struct *mm;
			dma_addr_t *dma_addrs;
		} user_buf;
					
					
```

该函数流程如下

```c


	static struct kbase_va_region *kbase_mem_from_user_buffer(
		struct kbase_context *kctx, unsigned long address,
		unsigned long size, u64 *va_pages, u64 *flags)
{
...
flag判断以及va_pages的size判断

//指定BASE_MEM_IMPORT_SHARED ，也就是导入的是cpu、gpu的共享区域
	if (*flags & BASE_MEM_IMPORT_SHARED)
		shared_zone = true;
	if (shared_zone) {//TODO 
		*flags |= BASE_MEM_NEED_MMAP;
		zone = KBASE_REG_ZONE_SAME_VA;
		rbtree = &kctx->reg_rbtree_same;
	} else
		rbtree = &kctx->reg_rbtree_custom;
//分配相应大小的region，以及完成结构体的分配
reg = kbase_alloc_free_region(rbtree, 0, *va_pages, zone);

	reg->gpu_alloc = kbase_alloc_create(kctx, *va_pages,
			KBASE_MEM_TYPE_IMPORTED_USER_BUF);
	reg->cpu_alloc = kbase_mem_phy_alloc_get(reg->gpu_alloc);
	
初始化region flags，这与前面的flag检查基本对应

	reg->flags &= ~KBASE_REG_FREE;//正在使用
	reg->flags |= KBASE_REG_GPU_NX; /* user buf都是没有执行权限的 */
	reg->flags &= ~KBASE_REG_GROWABLE; /* 不可拓展 */
//分配struct page
	if (reg->gpu_alloc->properties & KBASE_MEM_PHY_ALLOC_LARGE)
		user_buf->pages = vmalloc(*va_pages * sizeof(struct page *));
	else
		user_buf->pages = kmalloc_array(*va_pages,
				sizeof(struct page *), GFP_KERNEL);

    
    	if (reg->flags & KBASE_REG_SHARE_BOTH) {
		pages = user_buf->pages;
		*flags |= KBASE_MEM_IMPORT_HAVE_PAGES;
	}
    //如果一个内存区域与 CPU 的一致性（coherent）相关，那么这段内存会立即被导入（imported）并映射到 GPU 上。这意味着 CPU 对该内存的修改将立即反映在 GPU 上，而 GPU 对该内存的修改也将立即反映在 CPU 上，以保持一致性。
//另一方面，如果内存区域与 CPU 的一致性无关，则会调用 get_user_pages 函数进行一个检查。在这种情况下，get_user_pages 函数会被调用，但是传入的页参数是 NULL，这会导致页错误（page fault），但不会将页面映射在内存中。然后，只有在指定该内存区域作为外部资源的作业周围，才会将该内存区域固定在内存中。
    
    	if (reg->flags & KBASE_REG_SHARE_BOTH) {
		pages = user_buf->pages;//如果我们不设置该flag，page为null，设置了的话，pages就会直接填充进去
		*flags |= KBASE_MEM_IMPORT_HAVE_PAGES;
	}
    	write = reg->flags & (KBASE_REG_CPU_WR | KBASE_REG_GPU_WR);
    //fault page&& get pages
    //get_user_pages() 函数会尝试将指定的用户空间地址区域映射到内核空间，获取到的物理页框通过 pages 参数返回，映射得到的虚拟内存区域结构体指针通过 vmas 参数返回。该函数返回成功映射的页数，如果出现错误则返回一个负值。
#if KERNEL_VERSION(5, 9, 0) > LINUX_VERSION_CODE
	faulted_pages = get_user_pages(address, *va_pages,
			write ? FOLL_WRITE : 0, pages, NULL);
#else
	/* pin_user_pages 函数不能使用 NULL 的 pages 参数进行调用。这意味着在调用 pin_user_pages 函数时，必须传递一个非空的 pages 参数，以指定用于存储页面引用的数组。
如果在 pages 参数为 NULL 的情况下进行页面引用操作，则使用 get_user_pages 函数代替。在此情况下，只要不使用 FOLL_GET 标志，传递 NULL 的 pages 参数是安全的。
此时的pages为null，但这并不影响faulted_pages为引用address的物理页数量，只是未填充到pages中。 
我在翻阅get_user_pages的时候确实看到了对应的源码实现：
在__get_user_pages()中：
ret = get_gate_page(mm, start & PAGE_MASK,
						gup_flags, &vma,
						pages ? &pages[i] : NULL);
	 */
	if (pages != NULL) {
		faulted_pages =
			pin_user_pages(address, *va_pages, write ? FOLL_WRITE : 0, pages, NULL);
	} else {
		faulted_pages =
			get_user_pages(address, *va_pages, write ? FOLL_WRITE : 0, pages, NULL);
	}

#endif
...
    if (faulted_pages != *va_pages)//只有在获取页面引用时发生错误时，才会进入 fault_mismatch 分支。
 
        goto fault_mismatch;
    
    reg->gpu_alloc->nents = 0;
	reg->extent = 0;
	if (pages) {//设置了KBASE_REG_SHARE_BOTH
		struct device *dev = kctx->kbdev->dev;
		struct tagged_addr *pa = kbase_get_gpu_phy_pages(reg);
//返回reg->gpu_alloc->pages，即gpu_alloc管理的pages数组

		//设置最高位，代表该页已经被import
        user_buf->current_mapping_usage_count |= PINNED_ON_IMPORT;

		offset_within_page = user_buf->address & ~PAGE_MASK;
		remaining_size = user_buf->size;
		for (i = 0; i < faulted_pages; i++) {
			unsigned long map_size =
				MIN(PAGE_SIZE - offset_within_page, remaining_size);
			dma_addr_t dma_addr = dma_map_page(dev, pages[i],
				offset_within_page, map_size, DMA_BIDIRECTIONAL);

			if (dma_mapping_error(dev, dma_addr))
				goto unwind_dma_map;

			user_buf->dma_addrs[i] = dma_addr;
			pa[i] = as_tagged(page_to_phys(pages[i]));//将该页放入gpu_alloc中 

			remaining_size -= map_size;
			offset_within_page = 0;
		}

		reg->gpu_alloc->nents = faulted_pages;
	}
	return reg;//不过pages是否为null，只要正确执行获取页面了，就都可以返回reg，只是未指定share both的时候 reg的pages为null。
    
    
unwind_dma_map:
	while (i--) {
		dma_unmap_page(kctx->kbdev->dev,
				user_buf->dma_addrs[i],
				PAGE_SIZE, DMA_BIDIRECTIONAL);
	}
   fault_mismatch:
	if (pages) {//这个时候，该内存区域还未被填充到region中，所以unpin该内存区域之前并不需要解除cpu侧的映射（也就是上面if pages那段没进去，pages未被填充，dma也未映射）
		for (i = 0; i < faulted_pages; i++)
			kbase_unpin_user_buf_page(pages[i]);
	}
no_page_array:
invalid_flags:
	kbase_mem_phy_alloc_put(reg->cpu_alloc);
	kbase_mem_phy_alloc_put(reg->gpu_alloc);
no_alloc_obj:
	kfree(reg);
no_region:
bad_size:
	return NULL;     
```

回到kbase_mem_import

```c
//import的页需要映射虚拟地址，这里与kbase_mem_alloc类似
	if (*flags & (BASE_MEM_SAME_VA | BASE_MEM_NEED_MMAP)) {
		/* Bind to a cookie */
		if (!kctx->cookies)
			goto no_cookie;
		/* return a cookie */
		*gpu_va = __ffs(kctx->cookies);
		kctx->cookies &= ~(1UL << *gpu_va);
		BUG_ON(kctx->pending_regions[*gpu_va]);
		kctx->pending_regions[*gpu_va] = reg;
		/* relocate to correct base */
		*gpu_va += PFN_DOWN(BASE_MEM_COOKIE_BASE);
		*gpu_va <<= PAGE_SHIFT;
	}else if (*flags & KBASE_MEM_IMPORT_HAVE_PAGES)  {
		/* 调用gpu的mmap 将页映射到gpu内存中 */
		if (kbase_gpu_mmap(kctx, reg, 0, *va_pages, 1) != 0)
			goto no_gpu_va;
		/* return real GPU VA */
		*gpu_va = reg->start_pfn << PAGE_SHIFT;
	} else {//啥也木有，貌似返回的是通过页号计算的物理地址？
		/* we control the VA, but nothing to mmap yet */
		if (kbase_add_va_region(kctx, reg, 0, *va_pages, 1) != 0)
			goto no_gpu_va;
		/* return real GPU VA */
		*gpu_va = reg->start_pfn << PAGE_SHIFT;
	}
	/* clear out private flags */
	*flags &= ((1UL << BASE_MEM_FLAGS_NR_BITS) - 1);

	kbase_gpu_vm_unlock(kctx);

	return 0;
no_reg:
bad_flags:
	*gpu_va = 0;
	*va_pages = 0;
	*flags = 0;
	return -ENOMEM;

```



kbase_gpu_mmap->()kbase_mmu_insert_pages（）->kbase_mmu_insert_pages_no_flush（） 创建ate页表项，插入到pgd中，也就是完成了gpu侧物理页映射虚拟地址的过程。

```c
//插入页表项过程代码片段：			
for (i = 0; i < count; i++) {
				unsigned int ofs = vindex + i;
				u64 *target = &pgd_page[ofs];

				/* Warn if the current page is a valid ATE
				 * entry. The page table shouldn't have anything
				 * in the place where we are trying to put a
				 * new entry. Modification to page table entries
				 * should be performed with
				 * kbase_mmu_update_pages()
				 */
				WARN_ON((*target & 1UL) != 0);

				*target = kbase_mmu_create_ate(kbdev,
					phys[i], flags, cur_level, group_id);
			}
			num_of_valid_entries += count;
		}

		mmu_mode->set_num_valid_entries(pgd_page, num_of_valid_entries);

		if (dirty_pgds && count > 0 && !newly_created_pgd)
			*dirty_pgds |= 1ULL << cur_level;

		phys += count;
		insert_vpfn += count;
		remain -= count;
```

而cpu侧的映射如何建立？应该就是mmap中的处理，但接受到的值应该是个cookie？到底怎么得到相同值的虚拟地址的

`do_shared_fault()` 是 Linux 内核中处理共享内存缺页中断的函数，我们使用mmap导入共享内存的时候便指定了VM_SHARED，当 CPU 触发 Page Fault 并需要访问 GPU 分配的虚拟地址空间时，会调用这个函数来解决共享内存缺页。

在这个函数中，操作系统会检查导致 Page Fault 的虚拟地址，并尝试解决缺页。对于共享内存缺页中断，需要在 CPU 和 GPU 之间进行协作，将 GPU 分配的虚拟地址空间映射到 CPU 的页表中，从而使得 CPU 能够正确访问 GPU 分配的虚拟地址空间。

具体的实现细节可能因操作系统版本和 GPU 驱动程序而有所差异，但在一般情况下，`do_shared_fault()` 函数会涉及操作系统的页错误处理程序与 GPU 驱动程序之间的协同工作，以完成对 GPU 分配虚拟地址空间的正确映射。如果您有更多关于这个函数的代码或文档，我可以帮您更具体地分析和解释。







漏洞点：当没有KBASE_REG_SHARE_BOTH标志，通过提交一个列出该区域作为外部资源的原子作业，临时填充.pages数组，将页面映射到Mali的主机用户空间映射中（该映射为VM_PFNMAP），然后让作业完成，这会导致Mali在不清除主机用户空间映射中相应PTE的情况下释放.pages数组中页面的引用。

我不确定正确的修复方法是禁止从没有KBASE_REG_SHARE_BOTH标志的KBASE_MEM_TYPE_IMPORTED_USER_BUF区域中导入页面，还是确保在其后备内存消失时正确清除主机虚拟映射，或者两者都需要？我还没有详细研究其他区域类型是否存在类似问题。
