# qemu note

## 启动流程

https://www.cnblogs.com/LoyenWang/p/13796537.html
https://www.cnblogs.com/LoyenWang/p/13943005.html

上述第一篇给了一个极简版的 qemu 例子
大致来说，

1. 用户态的 qemu 先直接打开 kvm 文件
   
   ```c
   kvm_fd = open("/dev/kvm", O_RDWR);
   ```

2. 然后再频繁通过 ioctl 和 kvm 交互，设置 vm / vcpu / hva<->gpa
   
   ```c
     /* create VM */vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
   assert(vm_fd >= 0);
   /* create VCPU */vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
   assert(vcpu_fd >= 0);
   /* open tiny_kernel binary file */
       tiny_kernel_fd = open("./kernel/bin", O_RDONLY);
   assert(tiny_kernel_fd > 0);
   /* map 4K into memory */
   userspace_addr = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
   assert(userspace_addr > 0);
   /* read tiny_kernel binary into the memory */
   ret = read(tiny_kernel_fd, userspace_addr, PAGE_SIZE);
   assert(ret >= 0);
   /* set user memory region */
   mem.slot = 0;
   mem.flags = 0;
   mem.guest_phys_addr = 0;
   mem.memory_size = PAGE_SIZE;
   mem.userspace_addr = (unsignedlong)userspace_addr;
   ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &mem);
   assert(ret >= 0);
   ```
   
    vcpu 放在 vm 的一个 slot 里，本质上内存管理是 vm 级别的，而执行一个 guest os 是 vcpu 级别

3. 执行完成后获得 kvm_fd, vm_fd, vcpu_fd. 此时可以通过 MMIO 的形式映射一个运行时 kvm_run，以便日后实时操作：
   
   ```c
   /* get kvm_run */
   
   mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
   assert(mmap_size >= 0);
   kvm_run = (structkvm_run *)mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
   assert(kvm_run >= 0);
   ```

4. 设置 vcpu 状态

文中给的是一个 ARM 的例子

```c
ret = ioctl(vcpu_fd, KVM_GET_SREGS, &sregs);
assert(ret >= 0);
sregs.cs.base = 0;
sregs.cs.selector = 0;
ret = ioctl(vcpu_fd, KVM_SET_SREGS, &sregs);
memset(&regs, 0, sizeof(structkvm_regs));
regs.rip = 0;
ret = ioctl(vcpu_fd, KVM_SET_REGS, &regs);
assert(ret >= 0);
```

在 qemu 9.0.0 的 x86 中，实际上是 kvm_cpu_exec()->kvm_arch_put_registers()->kvm_put_sregs2()->kvm_vcpu_ioctl(CPU(cpu), KVM_SET_SREGS2, &sregs)

5. qemu 开始运行，并挂在 ioctl 上等待回复
   
   ```c
    /* vcpu run */while(1) {
    ret = ioctl(vcpu_fd, KVM_RUN, NULL);
    assert(ret >= 0);
   
   switch(kvm_run->exit_reason) {
            caseKVM_EXIT_HLT:
                printf("----KVM EXIT HLT----\n");
                close(kvm_fd);
                close(tiny_kernel_fd);
                return0;
            caseKVM_EXIT_IO:
                putchar(*(((char*)kvm_run) + kvm_run->io.data_offset));
                break;
            default:
                printf("Unknow exit reason: %d\n", kvm_run->exit_reason);
                break;
        }
   }
   ```

在 qemu 9.0.0 中实际上是在 kvm_cpu_exec() 结尾处理的。为了支持同时模拟多个 cpu，qemu 会在之前优先用 qemu_thread_create() 分出一个线程专门处理这个 cpu 的模拟

### 其他子模块

##### big qemu lock

bql_lock 是 qemu 全局的大锁。以前有专供磁盘IO访问的 AioContext 锁，不过现在已经被移除了 http://blog.vmsplice.net/2024/01/qemu-aiocontext-removal-and-how-it-was.html

其实如果不需要修改整个 qemu 的状态，只针对一个 vcpu，可以不用 bql，或者自己在线程定义锁。不过目前 zyr 的方案还是先拿了 bql 再操作

##### qemu object model

qemu 的 OOP 实现，主要用于添加设备。很难绷的一点是，为了用c写出c++的特性，qemu 自己整了一套虚拟/继承/多态体系，完全是重新做了一遍轮子。

所有类的构造函数是 .class_init
单个对象的构造函数是 .instance_init

类的结构还得专门写在一个 qom.json 里

##### meson

qemu 使用 meson 构建，所以添加新文件需要修改对应文件夹的 meson.build
meson 基于 python，本质上是 make 和 cmakefile 的上位替代。
不过既然都用上 meson+ninjia 了，那 QOM 为什么不使用基于 c++ 的方法呢

### 调试输出

可以 info_report/warn_report/error_report，也可以指定条件或者是否只执行一次

由于 guest os 启动后可能会刷新屏幕，因此被刷掉的内容可以在 log 文件查看（ qemu 启动参数后加句 2>&1 | tee log）

## 添加 shm

先对目前添加的代码简要分析。

### 最简的执行流

1. accel/kvm/kvm-all.c 中的 do-while 循环。通过一个 iotcl 每次接收 vcpu 的请求。当发现退出原因是 hypercall 时，加大锁并进入新定义的函数 `kvm_arch_handle_hypercall` 处理

```c
        switch (run->exit_reason) {
        case KVM_EXIT_IO:
            ......
        case KVM_EXIT_HYPERCALL:
            bql_lock();
            ret = kvm_arch_handle_hypercall(cpu, run);
            bql_unlock();
            break;
        default:
            ret = kvm_arch_handle_exit(cpu, run);
            break;
        }
```

2. `kvm_arch_handle_hypercall` 使用假参数 a0,a1,a2 拼出一个 Guest OS 中的 user给的地址和表示操作类型的 enum。
   
   qemu 拿着这个地址经过 gva->gpa 的手动查询后，获取真正的共享内存参数，传给 `consume_memdev` 
   
   ```c
       addr = (a0 << 32) + a1;
   
       switch (a2)
       {
           ......
       case HC_APPEND_MEMORY_REGION:
           append_memory_region_arg arg;
           MemoryRegion *append_memory = get_append_memory();
           cpu_physical_memory_rw(addr, &arg, sizeof(append_memory_region_arg), false);
           // info_report("KVM: APPEND_MEMORY_REGION: path=%s name=%s pages=%d offset=%d flags=%x",
           //         arg.path, arg.name, arg.pages, arg.offset, arg.flags);
           Object *obj = create_append_memdev(arg.path, arg.name, arg.pages * 0x1000, arg.flags);
           consume_memdev(append_memory, arg.offset, obj);
           run->hypercall.ret = append_memory->addr;
           break;
       default:
           error_report("KVM: unknown hypercall a2=%lx", a2);
           run->hypercall.ret = -1;
           break;
       }
   ```

3. `consume_memdev` 调用了 qemu 自带的接口，将参数指定的内存段加入管理
   
   ```c
   void consume_memdev(MemoryRegion *mr, uint64_t addr, Object *obj)
   {
       HostMemoryBackend *backend = MEMORY_BACKEND(obj);
       MemoryRegion *seg = machine_consume_memdev(current_machine, backend);
       memory_region_add_subregion(mr, addr, seg);
   }
   ```

### 更多细节

##### 为什么 qemu 可以处理 KVM_EXIT_HYPERCALL ？

在 kvm 初始化时加了一条 `kvm_vm_enable_cap`，使得 hypercall 可以被传回 qemu：

```c
int kvm_arch_init(MachineState *ms, KVMState *s)
{
    ......   
    /* 
    *  [Magic number]: 1 << 12
    *  see linux - arch/x86/kvm/x86.c:
    *  KVM_EXIT_HYPERCALL_VALID_MASK (1 << KVM_HC_MAP_GPA_RANGE)
    */   
    ret = kvm_vm_enable_cap(s, KVM_CAP_EXIT_HYPERCALL, 0, 1 << 12);
    if (ret < 0)
    {
        error_report("kvm: Failed to enable cap 201: %s",
                     strerror(-ret));
        return ret;
    }
}
```

经过初始化之后，也只有 `KVM_HC_MAP_GPA_RANGE` 这一条 hypercall 的特定参数可以被直接传入 qemu 处理。

##### append_memory 是如何定义的？

检查它是如何被使用的：

```c
MemoryRegion *append_memory = get_append_memory();
cpu_physical_memory_rw(addr, &arg, sizeof(append_memory_region_arg), false);
```

append_memory 指向一个 MemoryRegion 类型的量。它是一个全局变量，跟随 `system_memory` 和 `system_io` 做初始化：

```c
\\ system/physmem.c
static MemoryRegion *system_memory;
static MemoryRegion *system_io;
static MemoryRegion *append_memory;

static void memory_map_init(void)
{
    system_memory = g_malloc(sizeof(*system_memory));

    memory_region_init(system_memory, NULL, "system", UINT64_MAX);
    address_space_init(&address_space_memory, system_memory, "memory");

    system_io = g_malloc(sizeof(*system_io));
    memory_region_init_io(system_io, NULL, &unassigned_io_ops, NULL, "io",
                          65536);
    address_space_init(&address_space_io, system_io, "I/O");

    append_memory = g_malloc(sizeof(*append_memory));
    memory_region_init(append_memory, NULL, "append", UINT64_MAX);
}

MemoryRegion *get_append_memory(void)
{
    return append_memory;
}

\\ include/exec//address-spaces.h

/* Get the root append memory region.  This interface should only be used
 * temporarily until a proper bus interface is available.
 */
MemoryRegion *get_append_memory(void);
```

在机器启动时， append_memory 被标记为  system_memory 的子区间(subregion)

```c
static void pc_q35_init(MachineState *machine)
{
    ......
    MemoryRegion *append_memory = get_append_memory();
    hwaddr append_memory_start;
    ......
    /* append memory init*/
    {
        if (x86ms->above_4g_mem_size == 0)
        {
            warn_report("x86ms->above_4g_mem_size == 0");
        }
        append_memory_start = x86ms->above_4g_mem_start + x86ms->above_4g_mem_size;
        info_report("append_memory_start: %lx", append_memory_start);
        memory_region_add_subregion(system_memory, append_memory_start,
                                    append_memory);
    }
```

而用户发出 hypercall 时，它们生成的区间则是 append_memory 的子区间（见 `consume_memdev`）

##### 新创建的内存区间 obj 是怎么定义的

这涉及 qemu 的 QOM(qemu object model) 系统，它重写了一遍 OOP 语言该干的事。

我们想给 append_memory 加一个 allow_create 属性，控制映射文件不存在时是否创建一个文件，但不直接改 `MemoeyRegion` 结构。于是在 `backends/hostmem-file.c` 中为 `HostMemoryBackendFile` 增加一个成员变量。

```c
struct HostMemoryBackendFile {
    HostMemoryBackend parent_obj;

    char *mem_path;
    uint64_t align;
    uint64_t offset;
    bool discard_data;
    bool is_pmem;
    bool readonly;
    bool allow_create; // added
    OnOffAuto rom;
};
```

使用 QOM 远比添加变量麻烦，还需要：

1. 父类构造：在上述代码中 `HostMemoryBackend parent_obj;` 是 `HostMemoryBackendFile` 的父类。因此需要修改 `bool file_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)` 中的初始化。

2. 子类构造：还需要填写 TypeInfo 完成自己的构造：
   
   ```c
   static void
   file_backend_instance_init(Object *obj)
   {
       HostMemoryBackendFile *fb = MEMORY_BACKEND_FILE(obj);
       fb->allow_create = true;
       MEMORY_BACKEND(fb)->share = true;
   }
   
   static const TypeInfo file_backend_info = {
       .name = TYPE_MEMORY_BACKEND_FILE,
       .parent = TYPE_MEMORY_BACKEND,
       .class_init = file_backend_class_init,
       .instance_init = file_backend_instance_init, \\ added
       .instance_finalize = file_backend_instance_finalize,
       .instance_size = sizeof(HostMemoryBackendFile),
   };
   ```

3. 登记属性：（没详细查，大概是为了重载跟一系列 get_type get_name 用法吧）
   
   新加的属性需要给出单独的读写函数，并在另外的 json 中登记：
   
   ```c
   static bool file_memory_backend_get_allow_create(Object *obj, Error **errp)
   {
       ......
   }
   
   static void file_memory_backend_set_allow_create(Object *obj, bool value,
                                                 Error **errp)
   {
       HostMemoryBackend *backend = MEMORY_BACKEND(obj);
       HostMemoryBackendFile *fb = MEMORY_BACKEND_FILE(obj);
       ......
   }
   
   static void
   file_backend_class_init(ObjectClass *oc, void *data)
   {
       HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);
       ......
       object_class_property_add_bool(oc, "allow-create",
           file_memory_backend_get_allow_create, file_memory_backend_set_allow_create);
       object_class_property_set_description(oc, "allow-create",
           "Whether to create the file if it does not exist");
   }
   
   \\ qapi/qom.json
   
   { 'struct': 'MemoryBackendFileProperties',
     'base': 'MemoryBackendProperties',
     'data': { '*align': 'size',
               '*offset': 'size',
               '*discard-data': 'bool',
               'mem-path': 'str',
               '*pmem': { 'type': 'bool', 'if': 'CONFIG_LIBPMEM' },
               '*readonly': 'bool',
               '*rom': 'OnOffAuto',
               '*allow-create': 'bool'} }
   ```
   
   这里的 `MEMORY_BACKEND` `MEMORY_BACKEND_FILE` 大致相当于 `dynamic_cast`

4. 创建后用  python 风格指定每个参数，并通过 `object_property_add_child` 挂载：
   
   ```c
   Object *create_append_memdev(const char *path, const char *name, ram_addr_t size, uint64_t flags)
   {
       Object *obj;
       Error **errp = &error_warn;
   
       if (!path)
       {
           warn_report("append memory without path is invalid");
           return NULL;
       }
       obj = object_new(TYPE_MEMORY_BACKEND_FILE);
       if (!object_property_set_str(obj, "mem-path", path, errp))
       {
           goto out;
       }
       if (!object_property_set_int(obj, "size", size, errp))
       {
           goto out;
       }
       if (!object_property_set_bool(obj, "allow-create", flags & FLAG_ALLOW_CREATE, errp))
       {
           goto out;
       }
       if (!object_property_set_bool(obj, "share", flags & FLAG_SHARE, errp))
       {
           goto out;
       }
   
       object_property_add_child(object_get_objects_root(), name ?: path,
                                 obj);
       if (!user_creatable_complete(USER_CREATABLE(obj), errp))
       {
           goto out;
       }
       // object_unref(obj);
       return obj;
   out:
       object_unref(obj);
       return NULL;
   }
   ```
   
   `object_property_add_child` 即是要求当前创建对象的生命周期不超过父结点。当父结点(此处是 objects_root 相当于全局变量了)析构时，当前结点也会析构。这个生命周期的关系对父子结点的类型不作要求
    

##### qemu 对外如何创建共享文件

这部分已经有现成的写法在 `system/physmem.c` `backends/hostmem-file.c`，只是为了适配新增的 `allow_create` 属性改一些接口
