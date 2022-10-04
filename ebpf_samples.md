# EBPF samples

## linux/sample/bpf
Patch those [modification](https://patchwork.ozlabs.org/project/netdev/patch/20190518004639.20648-1-mcroce@redhat.com/) before build bpf sample.

## Kprobe
Developer can attach eBPF program wherever in kernel via `kprobe` module. But pleaseb remeber that `kprobe` is not the standard eBPF API, Iterations of kernel version may make `kprobe` type program meaningless.<br>
The `eBPF` program wii be triggered when attached function is called. developer can get input parameter via macro `PT_REGS_PARM${parameter_index}`.<br>
```c
#define PT_REGS_PARM1(x) (__PT_REGS_CAST(x)->__PT_PARM1_REG)
#define PT_REGS_PARM2(x) (__PT_REGS_CAST(x)->__PT_PARM2_REG)
#define PT_REGS_PARM3(x) (__PT_REGS_CAST(x)->__PT_PARM3_REG)
#define PT_REGS_PARM4(x) (__PT_REGS_CAST(x)->__PT_PARM4_REG)
#define PT_REGS_PARM5(x) (__PT_REGS_CAST(x)->__PT_PARM5_REG)
#define __PT_PARM1_REG rdi
#define __PT_PARM2_REG rsi
#define __PT_PARM3_REG rdx
#define __PT_PARM4_REG rcx
#define __PT_PARM5_REG r8
```
The `x86` arch register description is as below figure : <br>
<img src=./picture/ebpf/x86_register_doc.jpg width=500px><br>
Sample show how to peek Wi-Fi security key in userspace when success associated :<br>

Kernel Space :
```c
#include <linux/version.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "trace_common.h"
typedef uint32_t u32;
typedef uint8_t u8;
#define _(P)                                                                   \
        ({                                                                     \
                typeof(P) val = 0;                                             \
                bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
                val;                                                           \
        })
#if 1
#define KEY2STR(x) _((x)[0]), _((x)[1])
#else
#define KEY2STR(x) _((x)[])
#endif

/*** ieee80211_key_alloc
* @param1 chiper
* @param2 idx
* @param3 key_len
* @param4 key_data
* @param5 seq_len
* @param6 seq
* @param7 cs
* @Return : the pointer of ieee80211_key structure.
* */
SEC("kprobe/ieee80211_key_alloc")
int bpf_prog(struct pt_regs *ctx) {
        size_t key_len = (size_t)PT_REGS_PARM3(ctx);
        u8 *key_data = (u8 *)PT_REGS_PARM4(ctx);
        u64 *key_data_format = (u64 *)key_data;
        char fmt[] = "ieee80211_key_alloc: key len %ld\n\t%llx %llx";
        if (key_data)
                bpf_trace_printk(fmt, sizeof(fmt), key_len, KEY2STR(key_data_format));
        else
                bpf_trace_printk(fmt, sizeof(fmt), key_len, 0xff);
        return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
```
Tip : `eBPF` program works in `eBPF` virtual machine, it's illege to access kernel address directly. Developer should call `bpf_probe_read_kernel` or `bpf_probe_read` (those function are similar in x86 arch, but may be difference in other arch).<br>
User Space :
```c
#include <stdio.h>
#include <bpf/libbpf.h>

int main(int argc, char **argv) {
        struct bpf_object *obj;
        struct bpf_program *prog;
        char filename[256];
        struct bpf_link *link = NULL;

        snprintf(filename, sizeof(filename), "wifi_key_query_kern.o");

        obj = bpf_object__open_file(filename, NULL);
        if (libbpf_get_error(obj)) {
                fprintf(stderr, "ERROR : opening BPF object file failed\n");
                return 0;
        }
        prog = bpf_object__find_program_by_name(obj, "bpf_prog");
        if (!prog) {
                fprintf(stderr, "ERROR: ebpf program not found\n");
                goto cleanup;
        }

        if (bpf_object__load(obj)) {
                fprintf(stderr, "ERROR: loading BPF object file failed\n");
                goto cleanup;
        }
        link = bpf_program__attach(prog);
        if (libbpf_get_error(link)) {
                fprintf(stderr, "ERROR: bpf_program__attach failed\n");
                link = NULL;
                goto cleanup;
        }

        read_trace_pipe();

cleanup:
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 0;
}
```

<img src=./picture/ebpf/wifi_1_result.png width=700px><br>

## Kretprobe
In `x86` architecture, the function return value will be restore in `EAX` register.<br>
For a sample increased fucntion like below : <br>
```c
int func1(int param) {
        return param + 1;
}
```
The assembly will be : <br>
We can notify the input value was increased and restore at `EAX` register.<br>
```sh
0000000000001129 <func1>:
    1129:       f3 0f 1e fa             endbr64
    112d:       55                      push   %rbp
    112e:       48 89 e5                mov    %rsp,%rbp
    1131:       89 7d fc                mov    %edi,-0x4(%rbp)
    1134:       8b 45 fc                mov    -0x4(%rbp),%eax
    1137:       83 c0 01                add    $0x1,%eax
    113a:       5d                      pop    %rbp
    113b:       c3                      retq
```
In `libbpf`, user can access return value via macro `PT_REGS_RC()` when target function was traped at `kretprobe`.<br>
```c
#define PT_REGS_RC(x) (__PT_REGS_CAST(x)->__PT_RC_REG
#define __PT_RC_REG eax
```

## Uprobe
Patch below patch before compile `libbpf`. This patch reference [[PATCH v3 bpf-next 1/4] libbpf: support function name-based attach uprobes](https://lore.kernel.org/bpf/1643645554-28723-2-git-send-email-alan.maguire@oracle.com/)<br>
```patch
diff --git a/tools/lib/bpf/libbpf.c b/tools/lib/bpf/libbpf.c
index e89cc9c885b3..7186c03a9bd4 100644
--- a/tools/lib/bpf/libbpf.c
+++ b/tools/lib/bpf/libbpf.c
@@ -11024,8 +11024,9 @@ static long elf_find_relative_offset(const char *filename, Elf *elf, long addr)
        pr_warn("elf: failed to find prog header containing 0x%lx in '%s'\n", addr, filename);
        return -ENOENT;
 }
-
-/* Return next ELF section of sh_type after scn, or first of that type if scn is NULL. */
+/* Return next ELF section of sh_type after scn, or first of that type
+ * if scn is NULL.
+ */
 static Elf_Scn *elf_find_next_scn_by_type(Elf *elf, int sh_type, Elf_Scn *scn)
 {
        while ((scn = elf_nextscn(elf, scn)) != NULL) {
@@ -11034,9 +11035,47 @@ static Elf_Scn *elf_find_next_scn_by_type(Elf *elf, int sh_type, Elf_Scn *scn)
                if (!gelf_getshdr(scn, &sh))
                        continue;
                if (sh.sh_type == sh_type)
-                       return scn;
+                       break;
        }
-       return NULL;
+       return scn;
+}
+/* For Position-Independent Code-based libraries, a table of trampolines
++ * (Procedure Linking Table) is used to support resolution of symbol
++ * names at linking time.  The goal here is to find the offset associated
++ * with the jump to the actual library function.  If we can instrument that
++ * locally in the specific binary (rather than instrumenting glibc say),
++ * overheads are greatly reduced.
++ *
++ * The method used is to find the .plt section and determine the offset
++ * of the relevant entry (given by the base address plus the index
++ * of the function multiplied by the size of a .plt entry).
++ */
+static ssize_t elf_find_plt_offset(Elf *elf, size_t ndx)
+{
+       Elf_Scn *scn = NULL;
+       size_t shstrndx;
+
+       if (elf_getshdrstrndx(elf, &shstrndx)) {
+               pr_debug("elf: failed to get section names section index: %s\n",
+                        elf_errmsg(-1));
+               return -LIBBPF_ERRNO__FORMAT;
+       }
+       while ((scn = elf_find_next_scn_by_type(elf, SHT_PROGBITS, scn))) {
+               long plt_entry_sz, plt_base;
+               const char *name;
+               GElf_Shdr sh;
+
+               if (!gelf_getshdr(scn, &sh))
+                       continue;
+               name = elf_strptr(elf, shstrndx, sh.sh_name);
+               if (!name || strcmp(name, ".plt") != 0)
+                       continue;
+               plt_base = sh.sh_addr;
+               plt_entry_sz = sh.sh_entsize;
+               return plt_base + (ndx * plt_entry_sz);
+       }
+       pr_debug("elf: no .plt section found\n");
+       return -LIBBPF_ERRNO__FORMAT;
 }

 /* Find offset of function name in object specified by path.  "name" matches
@@ -11048,7 +11087,7 @@ static long elf_find_func_offset(const char *binary_path, const char *name)
        bool is_shared_lib, is_name_qualified;
        char errmsg[STRERR_BUFSIZE];
        long ret = -ENOENT;
-       size_t name_len;
+       size_t name_len, sym_ndx = -1;
        GElf_Ehdr ehdr;
        Elf *elf;

@@ -11130,10 +11169,10 @@ static long elf_find_func_offset(const char *binary_path, const char *name)
                        /* ...but we don't want a search for "foo" to match 'foo2" also, so any
                         * additional characters in sname should be of the form "@@LIB".
                         */
-                       if (!is_name_qualified && sname[name_len] != '\0' && sname[name_len] != '@')
+                       if (!is_name_qualified && strlen(sname) > name_len && sname[name_len] != '@')
                                continue;

-                       if (ret >= 0) {
+                       if (ret >= 0 && last_bind != -1) {
                                /* handle multiple matches */
                                if (last_bind != STB_WEAK && curr_bind != STB_WEAK) {
                                        /* Only accept one non-weak bind. */
@@ -11150,8 +11189,11 @@ static long elf_find_func_offset(const char *binary_path, const char *name)
                        }
                        ret = sym.st_value;
                        last_bind = curr_bind;
+                       sym_ndx = idx;
                }
                /* For binaries that are not shared libraries, we need relative offset */
+               if (ret == 0 && sh_types[i] == SHT_DYNSYM)
+                       ret = elf_find_plt_offset(elf, sym_ndx);
                if (ret > 0 && !is_shared_lib)
                        ret = elf_find_relative_offset(binary_path, elf, ret);
                if (ret > 0)
```
