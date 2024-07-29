- 分析了 ioctl 在 kvm 上的定义和分发，`sev_mem_...` -> `kvm_arch_vm_ioctl` -> `kvm_vm_ioctl`  -> `kvm_dev_ioctl` 
- 找 `arch/x86/coco/tdx/` `arch/x86/virt/vmx/tdx/`  中 TDX 对应的接口。目前 Linux 内这部分代码很少，不需要修改这块，只需要保证最后 shm 的接口跟这边形式差不多就行。
- `tools/testing/selftests/kvm/x86_64` 是 Linux 自带的测试，参考这个来手敲 vmcall
- 从 Linux 调 vmcall 到 qemu：
- - qemu 可以收到 hypercall，但是 qemu 无法从对应地址上拿到东西，可能是 hva<->gpa 这段有问题。
- 从用户到 Linux：
- - 第一个想法是用户程序通过 `/dev/kvm` 打开 kvm，然后我直接在 kvm_dev_ioctl 或者 kvm_vm_ioctl 里加新操作就好了，但实际发现 Guest 端并不能开 kvm（这些 Trusted VM 都没有嵌套虚拟化），放弃
- - 之后的想法是写成一个新设备放进 `/dev` 然后在启动时 `misc_register()` 它，但是似乎太复杂。也尝试直接修改 `/dev/shm`，但是 ipc 相关的设备也比较麻烦，或许可以做但耗时
- - 现在用最暴力的办法，在 `do_sys_openat2` 直接截获特定文件名创建特殊文件，然后通过定义新的 `struct file` 内的 `const struct file_operations` 支持创建操作。映射到用户地址空间可以通过 `.mmap` 子操作来搞，需要看看其他文件类型的 `.mmap` 怎么做的

### 上面提到的问题

```c
int kvm_arch_handle_hypercall(CPUState *cs, struct kvm_run *run)
{
    hwaddr addr;
    unsigned long a0 = run->hypercall.args[0] >> 12; // strange shift to bypass checker in kvm ...
    unsigned long a1 = run->hypercall.args[1] - 1;
    unsigned long a2 = run->hypercall.args[2];

    info_report("KVM: hypercall a0=%lx a1=%lx a2=%lx", a0, a1, a2);

    addr = (a0 << 32) + a1;

    switch (a2)
    {
    ......
       case HC_APPEND_MEMORY_REGION:
        append_memory_region_arg arg;
        MemoryRegion *append_memory = get_append_memory();
        info_report("before memory rw");
        cpu_physical_memory_rw(addr, &arg, sizeof(append_memory_region_arg), false);
        info_report("KVM: APPEND_MEMORY_REGION: path=%s name=%s pages=%d offset=%d flags=%x",\
                arg.path, arg.name, arg.pages, arg.offset, arg.flags);
        //Object *obj = create_append_memdev(arg.path, arg.name, arg.pages * 0x1000, arg.flags);
        Object *obj = create_append_memdev("1.txt", NULL, 1, 0x3);
        consume_memdev(append_memory, arg.offset, obj);
        run->hypercall.ret = append_memory->addr;
        info_report("KVM: return shm address: %lx", append_memory->addr);
        break;
    ......
```

- 代码中 addr 收到的地址是对的（设 a0=0, a1 传完整 64 位地址，没有问题）
- ` cpu_physical_memory_rw(addr, &arg, sizeof(append_memory_region_arg), false);` 一句的结果是全0，应该有bug。
- `Object *obj = create_append_memdev("1.txt", NULL, 1, 0x3);` 手动构造一组参数后，对外的共享文件也是对的。
- offset 的参数目前是 0。还没想好咋搞，Guest OS 这边得在正常的地址之外空出一段来存。
