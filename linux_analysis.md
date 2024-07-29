在 ioctl 中加入 shm for tdx 相关内容。

以下代码描述均基于 Linux v6.2 根目录。

## 学着 SEV 的方式写

自底向上找需要修改哪些部分。

### 为新操作定义常量

找到 Linux/arch/x86 中关于 SEV 的部分：

https://docs.kernel.org/virt/kvm/x86/amd-memory-encryption.html

挑选一个常量  KVM_SEV_LAUNCH_MEASURE

查到它在代码的 `arch/x86/kvm/svm/sev.c`，通过函数 `sev_mem_...` 引用

```c
int sev_mem_enc_ioctl(struct kvm *kvm, void __user *argp)
{
    ......
    struct kvm_sev_cmd sev_cmd;
    int r;

    if (!sev_enabled)
        return -ENOTTY;

    if (!argp)
        return 0;

    if (copy_from_user(&sev_cmd, argp, sizeof(struct kvm_sev_cmd)))
        return -EFAULT;

    mutex_lock(&kvm->lock);

    /* Only the enc_context_owner handles some memory enc operations. */
    if (is_mirroring_enc_context(kvm) &&
        !is_cmd_allowed_from_mirror(sev_cmd.id)) {
        r = -EINVAL;
        goto out;
    }

    case KVM_SEV_INIT:
        r = sev_guest_init(kvm, &sev_cmd);
        break;
    case KVM_SEV_LAUNCH_START:
        r = sev_launch_start(kvm, &sev_cmd);
        break;
    case KVM_SEV_LAUNCH_UPDATE_DATA:
        r = sev_launch_update_data(kvm, &sev_cmd);
        break;
    case KVM_SEV_LAUNCH_UPDATE_VMSA:
        r = sev_launch_update_vmsa(kvm, &sev_cmd);
        break;
    case KVM_SEV_LAUNCH_MEASURE:
        r = sev_launch_measure(kvm, &sev_cmd);
        break;
```

### 从` sev_..._ioctl` 到 `kvm_arch_vm_ioctl`

而这一系列函数在 `arch/x86/kvm/svm/svm.c` 引入，在 `arch/x86/kvm/svm/svm.h` 中声明

```c
static struct kvm_x86_ops svm_x86_ops __initdata = {
    .name = "kvm_amd",
    ......
    .mem_enc_ioctl = sev_mem_enc_ioctl,
    .mem_enc_register_region = sev_mem_enc_register_region,
    .mem_enc_unregister_region = sev_mem_enc_unregister_region,
    .guest_memory_reclaimed = sev_guest_memory_reclaimed,
```

而 `mem_enc_ioctl` 这个子类又需要做下列处理：

1. 在 `arch/x86/include/asm/kvm_host.h` 添加函数声明。

```c
int (*mem_enc_ioctl)(struct kvm *kvm, void __user *argp);
```

注意这里的 `__user` 是一个指向用户空间的地址，linux会做静态检查。可参考上面的 `sev_mem_enc_ioctl` 完成 `copy_from_user` 等等操作。

https://docs.kernel.org/core-api/kernel-api.html

2. 在 `arch/x86/include/asm/kvm-x86-ops.h` 注册函数名。

```c
KVM_X86_OP_OPTIONAL(mem_enc_ioctl)
```

3. 在 `arch/x86/kvm/x86.c` 的 `kvm_arch_vm_ioctl` 中添加方法名

```c
long kvm_arch_vm_ioctl(struct file *filp,
               unsigned int ioctl, unsigned long arg)
{
    ......
    case KVM_MEMORY_ENCRYPT_OP: {
        r = -ENOTTY;
        if (!kvm_x86_ops.mem_enc_ioctl)
            goto out;

        r = static_call(kvm_x86_mem_enc_ioctl)(kvm, argp);
        break;
    }
```

其中 `kvm_x86_ops.mem_enc_ioctl` 是上面第一步给的定义，`static_call(kvm_x86_mem_enc_ioctl)(kvm, argp);` 则是宏控制的，需要加上 `kvm_x86_` 前缀。

### 从 `kvm_ach_vm_ioctl` 到 `kvm` 设备

上面的函数是在 `virt/kvm/kvm_main.c` 中 `kvm_vm_ioctl` 的末尾调用的。 `kvm_vm_ioctl` 自己处理了一些通用的操作，把剩下的架构相关操作交给  `kvm_ach_vm_ioctl` 

这个函数的地址被包括在同文件中 `kvm_vm_fops` 的定义里，使得文件具有了 ioctl 属性，可以被 syscall 找到对应实现。

```c
static const struct file_operations kvm_vm_fops = {
    .release        = kvm_vm_release,
    .unlocked_ioctl = kvm_vm_ioctl,
    .llseek        = noop_llseek,
    KVM_COMPAT(kvm_vm_compat_ioctl),
};

bool file_is_kvm(struct file *file)
{
    return file && file->f_op == &kvm_vm_fops;
}
EXPORT_SYMBOL_GPL(file_is_kvm);

static int kvm_dev_ioctl_create_vm(unsigned long type)
{
    kvm = kvm_create_vm(type, fdname);
    ......
    file = anon_inode_getfile("kvm-vm", &kvm_vm_fops, kvm, O_RDWR);
    ......
    return fd;
    ......
```

注意，被调用 `kvm_vm_ioctl` 的 fd 并不是 kvm 的 fd（也不是 vcpu 的），而是属于一个 vm 的。这三者的关系可参考这个例子：

```c
kvm_fd = open("/dev/kvm", O_RDWR);
vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
assert(vm_fd >= 0);
vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
assert(vcpu_fd >= 0);
```

其中可见 `vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);`。没错，上述的 `kvm_dev_ioctl_create_vm` 是在 `/dev/kvm`这个文件的 ioctl 中被调用的：

```c
static long kvm_dev_ioctl(struct file *filp,
              unsigned int ioctl, unsigned long arg)
{
    long r = -EINVAL;

    switch (ioctl) {
    case KVM_GET_API_VERSION:
        if (arg)
            goto out;
        r = KVM_API_VERSION;
        break;
    case KVM_CREATE_VM:
        r = kvm_dev_ioctl_create_vm(arg);
    ......
```

而整个 kvm （及其 ioctl 设置）又始于 `virt/kvm/kvm_main.c`

```c
static struct file_operations kvm_chardev_ops = {
    .unlocked_ioctl = kvm_dev_ioctl,
    .llseek        = noop_llseek,
    KVM_COMPAT(kvm_dev_ioctl),
};

static struct miscdevice kvm_dev = {
    KVM_MINOR,
    "kvm",
    &kvm_chardev_ops,
};

int kvm_init(void *opaque, unsigned vcpu_size, unsigned vcpu_align,
          struct module *module)
{
    struct kvm_cpu_compat_check c;
    int r;
    int cpu;
    ......
    r = misc_register(&kvm_dev);
    ......
```

## tdx 在 Linux 中的接口

目前这一版(linux v6.2)预留的接口很少，在 `arch/x86/coco/tdx/` 目录下，很多实现不全。

有两个稍微提一下， 

```c
/*
 * Wrapper for standard use of __tdx_hypercall with no output aside from
 * return code.
 */
static inline u64 _tdx_hypercall(u64 fn, u64 r12, u64 r13, u64 r14, u64 r15)
{
    struct tdx_hypercall_args args = {
        .r10 = TDX_HYPERCALL_STANDARD,
        .r11 = fn,
        .r12 = r12,
        .r13 = r13,
        .r14 = r14,
        .r15 = r15,
    };

    return __tdx_hypercall(&args, 0);
}

/*
 * Used for TDX guests to make calls directly to the TD module.  This
 * should only be used for calls that have no legitimate reason to fail
 * or where the kernel can not survive the call failing.
 */
static inline void tdx_module_call(u64 fn, u64 rcx, u64 rdx, u64 r8, u64 r9,
                   struct tdx_module_output *out)
{
    if (__tdx_module_call(fn, rcx, rdx, r8, r9, out))
        panic("TDCALL %lld failed (Buggy TDX module!)\n", fn);
}
```

- tdx_hypercall：请求 TDX VMM(hypervisor) 执行 hypercall。 经过寄存器保存恢复后 (`arch/x86/virt/vmx/tdx/tdxcall.S`)，最终被转为 tdcall 指令
- tdx_module_call：Guest TD 向 TDX module 请求服务。 在寄存器保存恢复后（`arch/x86/virt/vmx/tdx/tdxcall.S`），如果是 guest TD 发起的，则转为 tdcall；如果是 host 端发起的调用，则先通过 seamcall 指令进入  TDX module，再 tdcall。这两种方式分别对应 TDX module 中 guest 或 host 端的接口。

```asm
\\ arch/x86/virt/vmx/tdx/tdxcall.S
SYM_FUNC_START(__tdx_hypercall)
    FRAME_BEGIN

    /* Save callee-saved GPRs as mandated by the x86_64 ABI */
    push %r15
    push %r14
    push %r13
    push %r12

    /* Mangle function call ABI into TDCALL ABI: */
    /* Set TDCALL leaf ID (TDVMCALL (0)) in RAX */
    xor %eax, %eax

    /* Copy hypercall registers from arg struct: */
    movq TDX_HYPERCALL_r10(%rdi), %r10
    movq TDX_HYPERCALL_r11(%rdi), %r11
    movq TDX_HYPERCALL_r12(%rdi), %r12
    movq TDX_HYPERCALL_r13(%rdi), %r13
    movq TDX_HYPERCALL_r14(%rdi), %r14
    movq TDX_HYPERCALL_r15(%rdi), %r15

    movl $TDVMCALL_EXPOSE_REGS_MASK, %ecx

    /*
     * For the idle loop STI needs to be called directly before the TDCALL
     * that enters idle (EXIT_REASON_HLT case). STI instruction enables
     * interrupts only one instruction later. If there is a window between
     * STI and the instruction that emulates the HALT state, there is a
     * chance for interrupts to happen in this window, which can delay the
     * HLT operation indefinitely. Since this is the not the desired
     * result, conditionally call STI before TDCALL.
     */
    testq $TDX_HCALL_ISSUE_STI, %rsi
    jz .Lskip_sti
    sti
.Lskip_sti:
    tdcall
    ......

\\ arch/x86/virt/vmx/tdx/tdxcall.S
.macro TDX_MODULE_CALL host:req
    /*
     * R12 will be used as temporary storage for struct tdx_module_output
     * pointer. Since R12-R15 registers are not used by TDCALL/SEAMCALL
     * services supported by this function, it can be reused.
     */

    /* Callee saved, so preserve it */
    push %r12

    /*
     * Push output pointer to stack.
     * After the operation, it will be fetched into R12 register.
     */
    push %r9

    /* Mangle function call ABI into TDCALL/SEAMCALL ABI: */
    /* Move Leaf ID to RAX */
    mov %rdi, %rax
    /* Move input 4 to R9 */
    mov %r8,  %r9
    /* Move input 3 to R8 */
    mov %rcx, %r8
    /* Move input 1 to RCX */
    mov %rsi, %rcx
    /* Leave input param 2 in RDX */

    .if \host
    seamcall
    /*
     * SEAMCALL instruction is essentially a VMExit from VMX root
     * mode to SEAM VMX root mode.  VMfailInvalid (CF=1) indicates
     * that the targeted SEAM firmware is not loaded or disabled,
     * or P-SEAMLDR is busy with another SEAMCALL.  %rax is not
     * changed in this case.
     *
     * Set %rax to TDX_SEAMCALL_VMFAILINVALID for VMfailInvalid.
     * This value will never be used as actual SEAMCALL error code as
     * it is from the Reserved status code class.
     */
    jnc .Lno_vmfailinvalid
    mov $TDX_SEAMCALL_VMFAILINVALID, %rax
.Lno_vmfailinvalid:

    .else
    tdcall
    .endif

    /*
     * Fetch output pointer from stack to R12 (It is used
     * as temporary storage)
     */
    pop %r12
    ......
```

## host 端的 hypercall 响应

在 `linux_old1/arch/x86/kvm/x86.c` 的 `kvm_emulate_hypercall` 中，调用了 `kvm_xen_hypercall` 或者 `kvm_hv_hypercall`，并最终生成 vmcall 指令。不过这都是在 host 端的 Linux 发生的事情，跟当前要改的作为 Guest OS 的 Linux 关系不大。

作为 Guest OS 如何调 vmcall 呢？我在 `tools/testing/selftests/kvm/x86_64` 里找到了许多类似描述，不过可以先试试 `arch/x86/include/asm/kvm_para.h` 中的

```c
static inline long kvm_hypercall3(unsigned int nr, unsigned long p1,
                  unsigned long p2, unsigned long p3)
{
    long ret;

    if (cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
        return tdx_kvm_hypercall(nr, p1, p2, p3, 0);

    asm volatile(KVM_HYPERCALL
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(p2), "d"(p3)
             : "memory");
    return ret;
}
```
