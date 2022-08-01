<h1 style="font-weight:bold"> Extend Berkeley Packet Filter </h1>

 eBPF is used extensively to drive a wide variety of use cases: <br>
 * Providing high-performance networking and load-balancing in modern data centers and cloud native environments.
 * extracting fine-grained security observability data at low overhead.
 * [helping application developers trace applications](#code_tracing).
 * providing insights for performance troubleshooting.
 * preventive application and container runtime security enforcement.<br>
see [epbf.io](https://ebpf.io/) for more information.<br>

<h2 style="font-weight:bold"> Code Tracing </h2>

Before understand how ebpf work at kernel code tracing, that's a samples linux provide is necessary to take a look.<br>
Show packet information when receive packet from `lo` interface. <br>
```c
samples/bpf/tracex1_user.c
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"

int main(int ac, char **argv)
{
        struct bpf_link *link = NULL;
        struct bpf_program *prog;
        struct bpf_object *obj;
        char filename[256];
        FILE *f;

        snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
        obj = bpf_object__open_file(filename, NULL);
        if (libbpf_get_error(obj)) {
                fprintf(stderr, "ERROR: opening BPF object file failed\n");
                return 0;
        }

        prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
        if (!prog) {
                fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
                goto cleanup;
        }

        /* load BPF program */
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

        f = popen("taskset 1 ping -c5 localhost", "r");
        (void) f;

        read_trace_pipe();

cleanup:
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 0;
}
```
As the source code, we can know the BPF program name `bpf_prog1` was extract from `tracex1_kern.o`.<br>
The BPF process divided to<br>
* [Create `struct bpf_object` instance from ELF file.](#create_bpf_object_instance)
* bpf_object__load (TODO)
* bpf_program__attach(TODO)

<h3 style="font-weight:bold" id="create_bpf_object_instance"> Create bpf_object instance from ELF file. </h3>

`bpf_object__open_file()` -> `bpf_object_open()`
```c
static struct bpf_object *bpf_object_open(const char *path, const void *obj_buf, size_t obj_buf_sz,
        const struct bpf_object_open_opts *opts) {
            ...
        err = bpf_object__elf_init(obj);
        err = err ? : bpf_object__check_endianness(obj);
        err = err ? : bpf_object__elf_collect(obj);
        err = err ? : bpf_object__collect_externs(obj);
        err = err ? : bpf_object__finalize_btf(obj);
        err = err ? : bpf_object__init_maps(obj, opts);
        err = err ? : bpf_object_init_progs(obj, opts);
        err = err ? : bpf_object__collect_relos(obj);
        if (err)
            goto out;
        bpf_object__elf_finsih(obj);

        return obj;
}
```

```c
static int bpf_object__elf_collect(struct bpf_object *obj) {
    obj->efile.sec_cnt = obj->efile.ehdr->e_shnum;
    obj->efile.secs = calloc(obj->efile.sec_cnt, sizeof(*obj->efile.secs));

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        sh = elf_sec_hdr(obj, scn);
        if (!sh)
            return -LIBBPF_ERRNO__FORMAT;

        if (sh->sh_type == SHT_SYMTAB) {
            if (obj->efile.symbols) {
                pr_warn("elf: multiple symbol tables in %s\n", obj->path);
                return -LIBBPF_ERRNO__FORMAT;
            }

            data = elf_sec_data(obj, scn);
            if (!data)
                return -LIBBPF_ERRNO__FORMAT;

            idx = elf_ndxscn(scn);

            obj->efile.symbols = data;
            obj->efile.symbols_shndx = idx;
            obj->efile.strtabidx = sh->sh_link;
        }
    }
            ...
    while((scn = elf_nextscn(elf, scn)) != NULL) {
        idx = elf_ndxscn(scn);
        sec_desc = &obj->efile.secs[idx];

        sh = elf_sec_hdr(obj, scn);
        data = elf_sec_data(obj, scn);

        if (strcmp(name, "license") == 0) {
            err = bpf_object__init_license(obj, data->d_buf, data->d_size);
            if (err)
                return err;
        }
                ...
        else if (sh->sh_type == SHT_PROGBITS && data->d_size > 0) {
            if (sh->sh_flags & SHF_EXECINSTR) {
                if (strcmp(name, ".text") == 0)
                    obj->efile.text_shndx = idx;
                err = bpf_object__add_programs(obj, data, name, idx);
                if (err)
                    return err;
            }
                    ...
        }
                ...
    }
}
```
First `libbpf` will extract symbol table from ELF file, and restore as `obj->efile.symbols`.
```
➜  bpf git:(master) ✗ readelf -s tracex1_kern.o
Symbol table '.symtab' contains 3705 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS tracex1_kern.c
            ...
  3697: 0000000000000000     0 SECTION LOCAL  DEFAULT    8
  3698: 0000000000000000     0 SECTION LOCAL  DEFAULT    9
  3699: 0000000000000000     0 SECTION LOCAL  DEFAULT   12
  3700: 0000000000000000     0 SECTION LOCAL  DEFAULT   17
  3701: 0000000000000000     0 SECTION LOCAL  DEFAULT   19
  3702: 0000000000000000     4 OBJECT  GLOBAL DEFAULT    5 _license
  3703: 0000000000000000     4 OBJECT  GLOBAL DEFAULT    6 _version
  3704: 0000000000000000   384 FUNC    GLOBAL DEFAULT    3 bpf_prog1
```
Then foreach all section at ELF file to establish `struct bpf_object`.<br>
* SHF_EXECINSTR<br>
This section is used to hold executable instructions of program.<br>
The flag `SHF_EXECINSTR` means that `The section contains executable machine instructions` will present as `X` at `Flg` item by `readelf`.
    ```
    ➜  bpf git:(master) ✗ readelf -SW tracex1_kern.o
        There are 22 section headers, starting at offset 0x44f60:

        Section Headers:
        [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
        [ 1] .strtab           STRTAB          0000000000000000 044e68 0000f1 00      0   0  1
        [ 2] .text             PROGBITS        0000000000000000 000040 000000 00  AX  0   0  4
        [ 3] kprobe/__netif_receive_skb_core PROGBITS        0000000000000000 000040 000180 00  AX  0   0  8
                    ...
    ```
    As the result of `readelf`, programs is restored at `kprobe/__netif_receive_skb_core` instead of `.text`, <br>
    that's because source file define :<br>
    ```c
    samples/bpf/tracex1_kern.c
    SEC("kprobe/__netif_receive_skb_core")
    int bpf_prog1(struct pt_regs *ctx)
    {
            ...
    }
    ```
    Filling `struct bpf_program programs` of `bpf_object` with those programs be extracted from `SHF_EXECINSTR` section by calling `bpf_object__add_programs`.<br> 
    The instructions of function (offset and size define at symbol table) will be copy to the `bpf_object.programs[$index].insns`.<br>
    We can know how many functions have by read the `bpf_object.nr_programs`.<br>
    ```c
    static int bpf_object__add_programs(struct bpf_object *obj, Elf_Data *sec_data,
            const char *sec_name, int sec_idx) {
                    ...
            for (i = 0; i < nr_syms; i++) {
                    sym = elf_sym_by_idx(obj, i);

                    if (sym->st_shndx != sec_idx)
                            continue;
                    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
                            continue;

                    prog_sz = sym->st_size;
                    sec_off = sym->st_value;

                    name = elf_sym_str(obj, sym->st_name);
                            ...
                    progs = libbpf_reallocarray(progs, nr_progs + 1, sizeof(*progs));

                    obj->programs = progs;

                    prog = &progs[nr_progs];

                    err = bpf_object__init_prog(obj, prog, name, sec_idx, sec_name,
                                                sec_off, data + sec_off, prog_sz);
                            ...
                    nr_progs++;
                    obj->nr_programs = nr_progs;
            }

            return 0;
    }
    ```
    The reason of using non-standard section name (.text) is because `libbpf` need function name we want to influenced to select corresponding attach handler.
    ```c
    static int bpf_object_init_progs(struct bpf_object *obj, const struct bpf_object_open_opts *opts)
    {
            struct bpf_program *prog;
            int err;

            bpf_object__for_each_program(prog, obj) {
                    prog->sec_def = find_sec_def(prog->sec_name);
                    if (!prog->sec_def) {
                            /* couldn't guess, but user might manually specify */
                            pr_debug("prog '%s': unrecognized ELF section name '%s'\n",
                                    prog->name, prog->sec_name);
                            continue;
                    }

                    bpf_program__set_type(prog, prog->sec_def->prog_type);
                    bpf_program__set_expected_attach_type(prog, prog->sec_def->expected_attach_type);
                        ...

            return 0;
    }

    static const struct bpf_sec_def *find_sec_def(const char *sec_name)
    {
            const struct bpf_sec_def *sec_def;
            int i, n;
            bool strict = libbpf_mode & LIBBPF_STRICT_SEC_NAME, allow_sloppy;

            n = custom_sec_def_cnt;
            for (i = 0; i < n; i++) {
                    sec_def = &custom_sec_defs[i];
                    if (sec_def_matches(sec_def, sec_name, false))
                            return sec_def;
            }

            n = ARRAY_SIZE(section_defs);
            for (i = 0; i < n; i++) {
                    sec_def = &section_defs[i];
                    allow_sloppy = (sec_def->cookie & SEC_SLOPPY_PFX) && !strict;
                    if (sec_def_matches(sec_def, sec_name, allow_sloppy))
                            return sec_def;
            }

            if (has_custom_fallback_def)
                    return &custom_fallback_def;

            return NULL;
    }
    ```
    * custom_sec_defs :<br>
        User define section, calling `libbpf_register_prog_handler()` to register custom handler.<br>
    * section_defs :<br>
        `libbpf` defined, common using.<br>
        ```
        static const struct bpf_sec_def section_defs[] = {
                SEC_DEF("socket",               SOCKET_FILTER, 0, SEC_NONE | SEC_SLOPPY_PFX),
                SEC_DEF("sk_reuseport/migrate", SK_REUSEPORT, BPF_SK_REUSEPORT_SELECT_OR_MIGRATE, SEC_ATTACHABLE | SEC_SLOPPY_PFX),
                SEC_DEF("sk_reuseport",         SK_REUSEPORT, BPF_SK_REUSEPORT_SELECT, SEC_ATTACHABLE | SEC_SLOPPY_PFX),
                SEC_DEF("kprobe/",              KPROBE, 0, SEC_NONE, attach_kprobe),
                SEC_DEF("uprobe/",              KPROBE, 0, SEC_NONE),
                            ...
                SEC_DEF("struct_ops+",          STRUCT_OPS, 0, SEC_NONE),
                SEC_DEF("sk_lookup",            SK_LOOKUP, BPF_SK_LOOKUP, SEC_ATTACHABLE | SEC_SLOPPY_PFX),
        };
        ```
* `.BTF`<br>
    BTF is the metadata of bpf program,  the member `struct btf *btf` and `struct btf_ext *btf_ext` of `struct bpf_object` will be filled by those data by calling `bpf_object__init_btf`.<br>
    ```c
    static int bpf_object__init_btf(struct bpf_object *obj, Elf_Data)
    {
            int err = -ENOENT;

            if (btf_data) {
                    obj->btf = btf__new(btf_data->d_buf, btf_data->d_size);
                    err = libbpf_get_error(obj->btf);
                    if (err) {
                            obj->btf = NULL;
                            pr_warn("Error loading ELF section %s: %d.\n", BTF_ELF_SEC, err);
                            goto out;
                    }
                    /* enforce 8-byte pointers for BPF-targeted BTFs */
                    btf__set_pointer_size(obj->btf, 8);
            }
            if (btf_ext_data) {
                    if (!obj->btf) {
                            pr_debug("Ignore ELF section %s because its depending ELF section %s is not found.\n",
                                    BTF_EXT_ELF_SEC, BTF_ELF_SEC);
                            goto out;
                    }
                    obj->btf_ext = btf_ext__new(btf_ext_data->d_buf, btf_ext_data->d_size);
                    err = libbpf_get_error(obj->btf_ext);
                    if (err) {
                            pr_warn("Error loading ELF section %s: %d. Ignored and continue.\n",
                                    BTF_EXT_ELF_SEC, err);
                            obj->btf_ext = NULL;
                            goto out;
                    }
            }
    out:
            if (err && libbpf_needs_btf(obj)) {
                    pr_warn("BTF is required, but is missing or corrupted.\n");
                    return err;
            }
            return 0;
    }
    ```
    The size of `BTF` header is 24 Bytes<br>
    ```c
    struct btf_header {
        __u16 magic;
        __u8 version;
        __u8 flags;
        __u32 hdr_len;
        __u32 type_off;
        __u32 type_len;
        __u32 str_off;
        __u32 str_len;
    }
    ```
    We can know the BTF information by dump the raw date of BTF header.<br>
    ```
    ➜  bpf git:(master) ✗ hexdump -s 114103 -n 24 tracex1_kern.o
    001bdb7 eb9f 0001 0018 0000 0000 0000 0204 0000
    001bdc7 0204 0000 0252 0000
    001bdcf
    ```
    * Magic : eb9f
    * Version : 0
    * Flags : 0x01
    * Header Len: 24
    * Type offset : 0
    * Type Len : 516
        ```
        ➜  bpf git:(master) ✗ hexdump -s 114127 -n 516 tracex1_kern.o
        001bdcf 0000 0000 0000 0200 0002 0000 0001 0000
        001bddf 0015 0400 00a8 0000 0009 0000 0003 0000
        001bdef 0000 0000 000d 0000 0003 0000 0040 0000
        001bdff 0011 0000 0003 0000 0080 0000 0015 0000
        001be0f 0003 0000 00c0 0000 0019 0000 0003 0000
        001be1f 0100 0000 001c 0000 0003 0000 0140 0000
        001be2f 001f 0000 0003 0000 0180 0000 0023 0000
        001be3f 0003 0000 01c0 0000 0027 0000 0003 0000
        001be4f 0200 0000 002a 0000 0003 0000 0240 0000
        001be5f 002d 0000 0003 0000 0280 0000 0030 0000
        001be6f 0003 0000 02c0 0000 0033 0000 0003 0000
        001be7f 0300 0000 0036 0000 0003 0000 0340 0000
        001be8f 0039 0000 0003 0000 0380 0000 003c 0000
        001be9f 0003 0000 03c0 0000 0044 0000 0003 0000
        001beaf 0400 0000 0047 0000 0003 0000 0440 0000
        001bebf 004a 0000 0003 0000 0480 0000 0050 0000
        001becf 0003 0000 04c0 0000 0053 0000 0003 0000
        001bedf 0500 0000 0056 0000 0000 0100 0008 0000
        001beef 0040 0000 0000 0000 0001 0d00 0005 0000
        001beff 0068 0000 0001 0000 006c 0000 0000 0100
        001bf0f 0004 0000 0020 0100 0070 0000 0001 0c00
        001bf1f 0004 0000 0200 0000 0000 0100 0001 0000
        001bf2f 0008 0100 0000 0000 0000 0300 0000 0000
        001bf3f 0007 0000 0009 0000 0004 0000 0205 0000
        001bf4f 0000 0100 0004 0000 0020 0000 0219 0000
        001bf5f 0000 0e00 0008 0000 0001 0000 0222 0000
        001bf6f 0000 0800 000c 0000 0226 0000 0000 0800
        001bf7f 000d 0000 022c 0000 0000 0100 0004 0000
        001bf8f 0020 0000 0239 0000 0000 0e00 000b 0000
        001bf9f 0001 0000 0242 0000 0001 0f00 0000 0000
        001bfaf 000a 0000 0000 0000 0004 0000 024a 0000
        001bfbf 0001 0f00 0000 0000 000e 0000 0000 0000
        001bfcf 0004 0000
        001bfd3
        ```
    * String offset : 516
    * String Len : 594
        ```
        ➜  bpf git:(master) ✗ hexdump -C -s 114643 -n 594 tracex1_kern.o
        0001bfd3  00 70 74 5f 72 65 67 73  00 72 31 35 00 72 31 34  |.pt_regs.r15.r14|
        0001bfe3  00 72 31 33 00 72 31 32  00 62 70 00 62 78 00 72  |.r13.r12.bp.bx.r|
        0001bff3  31 31 00 72 31 30 00 72  39 00 72 38 00 61 78 00  |11.r10.r9.r8.ax.|
        0001c003  63 78 00 64 78 00 73 69  00 64 69 00 6f 72 69 67  |cx.dx.si.di.orig|
        0001c013  5f 61 78 00 69 70 00 63  73 00 66 6c 61 67 73 00  |_ax.ip.cs.flags.|
        0001c023  73 70 00 73 73 00 6c 6f  6e 67 20 75 6e 73 69 67  |sp.ss.long unsig|
        0001c033  6e 65 64 20 69 6e 74 00  63 74 78 00 69 6e 74 00  |ned int.ctx.int.|
        0001c043  62 70 66 5f 70 72 6f 67  31 00 6b 70 72 6f 62 65  |bpf_prog1.kprobe|
        0001c053  2f 5f 5f 6e 65 74 69 66  5f 72 65 63 65 69 76 65  |/__netif_receive|
        0001c063  5f 73 6b 62 5f 63 6f 72  65 00 2f 72 6f 6f 74 2f  |_skb_core./root/|
        0001c073  73 6f 75 72 63 65 2f 6c  69 6e 75 78 2f 73 61 6d  |source/linux/sam|
        0001c083  70 6c 65 73 2f 62 70 66  2f 74 72 61 63 65 78 31  |ples/bpf/tracex1|
        0001c093  5f 6b 65 72 6e 2e 63 00  09 62 70 66 5f 70 72 6f  |_kern.c..bpf_pro|
        0001c0a3  62 65 5f 72 65 61 64 5f  6b 65 72 6e 65 6c 28 26  |be_read_kernel(&|
        0001c0b3  73 6b 62 2c 20 73 69 7a  65 6f 66 28 73 6b 62 29  |skb, sizeof(skb)|
        0001c0c3  2c 20 28 76 6f 69 64 20  2a 29 50 54 5f 52 45 47  |, (void *)PT_REG|
        0001c0d3  53 5f 50 41 52 4d 31 28  63 74 78 29 29 3b 00 09  |S_PARM1(ctx));..|
        0001c0e3  64 65 76 20 3d 20 5f 28  73 6b 62 2d 3e 64 65 76  |dev = _(skb->dev|
        0001c0f3  29 3b 00 09 6c 65 6e 20  3d 20 5f 28 73 6b 62 2d  |);..len = _(skb-|
        0001c103  3e 6c 65 6e 29 3b 00 09  62 70 66 5f 70 72 6f 62  |>len);..bpf_prob|
        0001c113  65 5f 72 65 61 64 5f 6b  65 72 6e 65 6c 28 64 65  |e_read_kernel(de|
        0001c123  76 6e 61 6d 65 2c 20 73  69 7a 65 6f 66 28 64 65  |vname, sizeof(de|
        0001c133  76 6e 61 6d 65 29 2c 20  64 65 76 2d 3e 6e 61 6d  |vname), dev->nam|
        0001c143  65 29 3b 00 09 69 66 20  28 64 65 76 6e 61 6d 65  |e);..if (devname|
        0001c153  5b 30 5d 20 3d 3d 20 27  6c 27 20 26 26 20 64 65  |[0] == 'l' && de|
        0001c163  76 6e 61 6d 65 5b 31 5d  20 3d 3d 20 27 6f 27 29  |vname[1] == 'o')|
        0001c173  20 7b 00 09 09 63 68 61  72 20 66 6d 74 5b 5d 20  | {...char fmt[] |
        0001c183  3d 20 22 73 6b 62 20 25  70 20 6c 65 6e 20 25 64  |= "skb %p len %d|
        0001c193  5c 6e 22 3b 00 09 09 62  70 66 5f 74 72 61 63 65  |\n";...bpf_trace|
        0001c1a3  5f 70 72 69 6e 74 6b 28  66 6d 74 2c 20 73 69 7a  |_printk(fmt, siz|
        0001c1b3  65 6f 66 28 66 6d 74 29  2c 20 73 6b 62 2c 20 6c  |eof(fmt), skb, l|
        0001c1c3  65 6e 29 3b 00 09 72 65  74 75 72 6e 20 30 3b 00  |en);..return 0;.|
        0001c1d3  63 68 61 72 00 5f 5f 41  52 52 41 59 5f 53 49 5a  |char.__ARRAY_SIZ|
        0001c1e3  45 5f 54 59 50 45 5f 5f  00 5f 6c 69 63 65 6e 73  |E_TYPE__._licens|
        0001c1f3  65 00 75 33 32 00 5f 5f  75 33 32 00 75 6e 73 69  |e.u32.__u32.unsi|
        0001c203  67 6e 65 64 20 69 6e 74  00 5f 76 65 72 73 69 6f  |gned int._versio|
        0001c213  6e 00 6c 69 63 65 6e 73  65 00 76 65 72 73 69 6f  |n.license.versio|
        *
        0001c225
        ```
    Or print human readable information of BTF section directly by `bpftool`.<br>
    ```
    ➜  bpftool git:(master) ✗ ./bpftool btf dump file ../tracex1_kern.o
    [1] PTR '(anon)' type_id=2
    [2] STRUCT 'pt_regs' size=168 vlen=21
            'r15' type_id=3 bits_offset=0
            'r14' type_id=3 bits_offset=64
            'r13' type_id=3 bits_offset=128
            'r12' type_id=3 bits_offset=192
            'bp' type_id=3 bits_offset=256
            'bx' type_id=3 bits_offset=320
            'r11' type_id=3 bits_offset=384
            'r10' type_id=3 bits_offset=448
            'r9' type_id=3 bits_offset=512
            'r8' type_id=3 bits_offset=576
            'ax' type_id=3 bits_offset=640
            'cx' type_id=3 bits_offset=704
            'dx' type_id=3 bits_offset=768
            'si' type_id=3 bits_offset=832
            'di' type_id=3 bits_offset=896
            'orig_ax' type_id=3 bits_offset=960
            'ip' type_id=3 bits_offset=1024
            'cs' type_id=3 bits_offset=1088
            'flags' type_id=3 bits_offset=1152
            'sp' type_id=3 bits_offset=1216
            'ss' type_id=3 bits_offset=1280
    [3] INT 'long unsigned int' size=8 bits_offset=0 nr_bits=64 encoding=(none)
    [4] FUNC_PROTO '(anon)' ret_type_id=5 vlen=1
            'ctx' type_id=1
    [5] INT 'int' size=4 bits_offset=0 nr_bits=32 encoding=SIGNED
    [6] FUNC 'bpf_prog1' type_id=4 linkage=global
    [7] INT 'char' size=1 bits_offset=0 nr_bits=8 encoding=SIGNED
    [8] ARRAY '(anon)' type_id=7 index_type_id=9 nr_elems=4
    [9] INT '__ARRAY_SIZE_TYPE__' size=4 bits_offset=0 nr_bits=32 encoding=(none)
    [10] VAR '_license' type_id=8, linkage=global
    [11] TYPEDEF 'u32' type_id=12
    [12] TYPEDEF '__u32' type_id=13
    [13] INT 'unsigned int' size=4 bits_offset=0 nr_bits=32 encoding=(none)
    [14] VAR '_version' type_id=11, linkage=global
    [15] DATASEC 'license' size=0 vlen=1
            type_id=10 offset=0 size=4 (VAR '_license')
    [16] DATASEC 'version' size=0 vlen=1
            type_id=14 offset=0 size=4 (VAR '_version')
    ```
    print human readable information of BTF section directly by `llvm-objdump`.
    ```
    ➜  bpf git:(master) ✗ llvm-objdump-6.0 -d  tracex1_kern.o

        tracex1_kern.o: file format elf64-bpf

        Disassembly of section kprobe/__netif_receive_skb_core:

        0000000000000000 <bpf_prog1>:
        0:       79 13 70 00 00 00 00 00 r3 = *(u64 *)(r1 + 112)
        1:       bf a1 00 00 00 00 00 00 r1 = r10
        2:       07 01 00 00 e8 ff ff ff r1 += -24
        3:       b7 02 00 00 08 00 00 00 r2 = 8
        4:       85 00 00 00 71 00 00 00 call 113
        5:       b7 06 00 00 00 00 00 00 r6 = 0
        6:       7b 6a f0 ff 00 00 00 00 *(u64 *)(r10 - 16) = r6
        7:       79 a3 e8 ff 00 00 00 00 r3 = *(u64 *)(r10 - 24)
        8:       07 03 00 00 10 00 00 00 r3 += 16
        9:       bf a1 00 00 00 00 00 00 r1 = r10
        10:       07 01 00 00 f0 ff ff ff r1 += -16
        11:       b7 02 00 00 08 00 00 00 r2 = 8
        12:       85 00 00 00 71 00 00 00 call 113
        13:       79 a7 f0 ff 00 00 00 00 r7 = *(u64 *)(r10 - 16)
        14:       63 6a f0 ff 00 00 00 00 *(u32 *)(r10 - 16) = r6
        15:       79 a3 e8 ff 00 00 00 00 r3 = *(u64 *)(r10 - 24)
        16:       07 03 00 00 70 00 00 00 r3 += 112
        17:       bf a1 00 00 00 00 00 00 r1 = r10
        18:       07 01 00 00 f0 ff ff ff r1 += -16
        19:       b7 02 00 00 04 00 00 00 r2 = 4
        20:       85 00 00 00 71 00 00 00 call 113
        21:       61 a6 f0 ff 00 00 00 00 r6 = *(u32 *)(r10 - 16)
        22:       bf a1 00 00 00 00 00 00 r1 = r10
        23:       07 01 00 00 f0 ff ff ff r1 += -16
        24:       b7 02 00 00 10 00 00 00 r2 = 16
        25:       bf 73 00 00 00 00 00 00 r3 = r7
        26:       85 00 00 00 71 00 00 00 call 113
        27:       71 a1 f0 ff 00 00 00 00 r1 = *(u8 *)(r10 - 16)
        28:       55 01 11 00 6c 00 00 00 if r1 != 108 goto +17 <LBB0_3>
        29:       71 a1 f1 ff 00 00 00 00 r1 = *(u8 *)(r10 - 15)
        30:       55 01 0f 00 6f 00 00 00 if r1 != 111 goto +15 <LBB0_3>
        31:       b7 01 00 00 00 00 00 00 r1 = 0
        32:       73 1a e6 ff 00 00 00 00 *(u8 *)(r10 - 26) = r1
        33:       b7 01 00 00 64 0a 00 00 r1 = 2660
        34:       6b 1a e4 ff 00 00 00 00 *(u16 *)(r10 - 28) = r1
        35:       b7 01 00 00 65 6e 20 25 r1 = 622882405
        36:       63 1a e0 ff 00 00 00 00 *(u32 *)(r10 - 32) = r1
        37:       18 01 00 00 73 6b 62 20 00 00 00 00 25 70 20 6c r1 = 7791350660110379891 ll
        39:       7b 1a d8 ff 00 00 00 00 *(u64 *)(r10 - 40) = r1
        40:       79 a3 e8 ff 00 00 00 00 r3 = *(u64 *)(r10 - 24)
        41:       bf a1 00 00 00 00 00 00 r1 = r10
        42:       07 01 00 00 d8 ff ff ff r1 += -40
        43:       b7 02 00 00 0f 00 00 00 r2 = 15
        44:       bf 64 00 00 00 00 00 00 r4 = r6
        45:       85 00 00 00 06 00 00 00 call 6

        0000000000000170 <LBB0_3>:
        46:       b7 00 00 00 00 00 00 00 r0 = 0
        47:       95 00 00 00 00 00 00 00 exit
    ```
    * SHT_REL<br>
        <font color="red">TODO</font>

<h3 style="font-weight:bold" id="load_bpf_prog_to_kernel"> Load BPF program to Kernel. </h3>

#### User Space
`bpf_object__load()` -> `bpf_object_load()` -> `bpf_object__load_progs()` -> `bpf_object_load_prog()`
```c
static int bpf_object_load_prog(struct bpf_object *obj, struct bpf_program *prog, const char *license, __u32 kern_ver) {
                ...
        for (i = 0; i < prog->instances.nr; i++) {
                struct bpf_prog_prep_result result;
                bpf_program_prep_t preprocessor = prog->preprocessor;

                preprocessor(prog, i, prog->insns, prog->insns_cnt, &result);

                bpf_object_load_prog_instance(obj, prog, result.new_insn_ptr,
                                result.new_insn_cnt, license, kern_ver, &fd);
                prog->instances.fds[i] = fd;
        }
        return libbpf_err(err);
}

```
`bpf_object_load_prog_instance()` -> `bpf_prog_load()` -> `bpf_prog_load()` -> `bpf_load_program()` -> `bpf_load_program_xattr2()` -><br>
`bpf_prog_load_v0_6_0()` -> `sys_bpf_prog_load()` -> ... -> `__sys_bpf`.<br>
After BPF program loading success, the file descriptor of program will return and store at the `prog->instances.fds` field.<br>
#### Kernel Space
```c
kernel/bpf/syscall.c
static int __sys_bpf(int cmd, bpfptr_t uattr, unsigned int size) {
                ...
        switch(cmd) {
                        ...
        case BPF_PROG_LOAD:
                err = bpf_prog_load(&attr, uattr);
                break;
                        ...
        }
}
static int bpf_prog_load(union bpf_attr *attr, bpfptr_t uattr) {
        struct bpf_prog *prog, *dst_prog = NULL;
                ...
        prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt), GFP_USER);
                ...
        find_prog_type(type, prog);
                ...
        bpf_check(&prog, attr, uattr);
        
        bpf_prog_select_runtime(prog, &err);
        
        bpf_prog_alloc_id(prog);
}

static int find_prog_type(enum bpf_prog_type type, struct bpf_prog *prog) {
        const struct bpf_prog_ops *ops;

        if (type >= ARRAY_SIZE(bpf_prog_types))
                return -EINVAL;
        type = array_index_nospec(type, ARRAY_SIZE(bpf_prog_types));
        ops = bpf_prog_types[type];
        if (!ops)
                return -EINVAL;
        if (!bpf_prog_is_dev_bound(prog->aux))
                prog->aux->ops = ops;
        else
                peog->aux->ops = *bpf_offload_porg_ops;
        prog->type = type;
        return 0;
}

struct bpf_prog *bpf_prog_select_runtime(struct bpf_prog *fp, int *err) {
                ...
        bpf_prog_select_func(fp);

        if (!bpf_prog_is_dev_bound(fp->aux)) {
                *err = bpf_prog_alloc_jited_linfo(fp);

                fp = bpf_int_jit_compile(fp);
                bpf_prog_jit_attempt_done(fp);
        } else {
                *err = bpf_prog_offload_compile(fp);
        }
finalize:
        bpf_prog_lock_ro(fp);
        *err = bpf_check_tail_call(fp);

        return fp;
}
```

If system not enable option `CONFIG_BPF_JIT_ALWAYS_ON`, the `bpf_func` which called when hook function trigger be assigned to BPF interpreter.<br>
```c
static void bpf_prog_select_func(struct bpf_prog *fp) {
#ifndef CONFIG_BPF_JIT_ALWAYS_ON
        u32 stack_depath = max_t(u32, fp->aux->stack_depath, 1);
        fp->bpf_func = interpreters[(round_up(stack_depth, 32) / 32) - 1];
#else
        fp->bpf_func = __bpf_prog_ret0_warn;
#endif
}
```
The interpreter defined at file `kernel/bpf/core.c`.<br>
```c
#define PROG_NAME(stack) __bpf_prog_run##stack_size
#define DEFINE_BPF_PROG_RUN(stack_size) \
static unsigned int PROG_NAME(stack_size)(const void *ctx, const struct bpf_insn *insn) \
{ \
        u64 stack[stack_size / sizeof(u64)]; \
        u64 regs[MAX_BPF_EXT_REG]; \
\
        FP = (u64)(unsigned long) &stack[ARRAY_SIZE(stack)]; \
        ARG1 = (u64) (unsigned long) ctx; \
        return ___bpf_prog_run(regs, insn); \
}

static unsigned int (*interpreters[])(const void *ctx, const struct bpf_insn *insn) = {
EVAL6(PROG_NAME_LIST, 32, 64, 96, 128, 160, 192)
EVAL6(PROG_NAME_LIST, 224, 256, 288, 320, 352, 384),
EVAL4(PROG_NAME_LIST, 416, 448, 480, 512)
}
```
If the JIT image is built success, that `prog->bpf_func` was replaced by the image with the setup `jited` flag, or falls back to the interpreter above if failed.<br>
```c
arch/x86/net/bpf_jit_comp.c
struct x64_jit_data {
        struct bpf_binary_header *rw_header;
        struct bpf_binary_header *header;
        int *addrs;
        u8 *image;
        int proglen;
        struct jit_context ctx;
};

struct bpf *bpf_int_jit_compile(struct bpf_prog *prog) {
        struct x64_jit_data *jit_data;
        struct jit_context ctx = {};

                        ...
        addrs = jit_data->addrs;
        addrs = kvmalloc_array(prog->len + 1, sizeof(*addrs), GFP_KERNEL);

        /*
                * Before first pass, make a rough estimation of addrs[]
                * echo BPF instruction is translated to less than 64 bytes.
                */
        for (proglen = 0, i = 0; i <= prog->len; i++) {
                proglen += 64;
                addrs[i] = proglen;
        }

        for (pass = 0; pass < MAX_PASSES || image; pass++) {
                proglen = do_jit(prog, addrs, image, rw_image, oldproglen, &ctx, padding);
                        ...
                if (image) {
                if (proglen != oldproglen) {
                        pr_err("bpf_jit: proglen=%d != oldproglen=%d\n",
                                proglen, oldproglen);
                }
                break;
                }
                        ...
        }
        if (bpf_jit_enable > 1)
                bpf_jit_dump(prog->len, proglen, pass + 1, image);
        if (image) {
                if (!prog->is_func || extra_pass) {
                if (WARN_ON(bpf_jit_binary_pack_finalize(prog, header, rw_header))) {
                        header = NULL;
                        goto out_image;
                }
                bpf_tail_call_direct_fixup(prog);
                } else {
                jit_data->addrs = addrs;
                jit_data->ctx = ctx;
                jit_data->proglen = proglen;
                jit_data->image = image;
                jit_data->header = header;
                jit_data->rw_header = rw_header;
                }
                prog->bpf_func = (void *)image;
                prog->jited = 1;
                prog->jited_len = proglen;
        }
                        ...
        return prog;
}
```
<h4 id="bpf_program_manage">bpf program manage</h4>

After success JIT compiled, the bpf program instance was managed by BPF filesystem `prog_idr`.<br>
```c
static int bpf_prog_alloc_id(struct bpf_prog *prog) {
        int id;

        idr_preload(GFP_KERNEL);
        spin_lock_bh(&prog_idr_lock);
        id = idr_alloc_cyclic(&prog_idr, prog, 1, INT_MAX, GFP_ATOMIC);
        if (id > 0)
                prog->aux->id = id;
        spin_unlock_bh(&prog_idr_lock);
        idr_preload_end();

        if (WARN_ON_ONCE(!id))
                return -ENOSPC;
        return id > 0 ? 0 : id;
}
```

<h3 style="font-weight:bold" id="attach_bpf_program"> Attach BPF program. </h3>

```c
tools/lib/bpf/libbpf.c
struct bpf_link *bpf_program__attach(const struct bpf_program *prog) {
        struct bpf_link *link = NULL;
        int err;

        err = prog->sec_def->prog_attach_fn(prog, prog->sec_def->cookie, &link);
        return link;
}
```
`eBPF` support 41 different program type in linux 5.18 and keep increasing.<br>
Some of those eBPF program was prefined, the hook point existed at source code.<br> The other program (e.g. kprobe, uprobe...) need to attach to kernel by system call.<br>
#### Kprobe
According to [Kernel Probes (Kprobes)](https://docs.kernel.org/trace/kprobes.html).<br>
```
Kprobes enables you to dynamically break into any kernel routine and collect debugging and performance information non-disruptively.
You can trap almost any kernel code address, specifying a handler routine to be invoked when the breakpoint is hit.
```
`attach_kprobe()` -> `bpf_program__attach_kprobe_opts()` -> `bpf_program__attach_perf_event_opts()`
```c
tools/lib/bpf/libbpf.c
struct pbf_link *bpf_program__attach_perf_event_opts(const struct bpf_program *prog, int pfd,
                const struct bpf_perf_event_opts *opts) {
        struct bpf_link_perf *link;
        int prog_fd, link_fd = -1, err;
                ...
        prog_fd = bpf_program__fd(prog); // get the first FD of BPF program from bpf_program.instances.fds

        link->link.detach = &bpf_link_perf_detach;
        link->link.dealloc = &bpf_link_perf_dealloc;
        link->perf_event_fd = pfd;

        if (kernel_supports(prog->obj, FEAT_PERF_LINK)) {
                DECLARE_LIBBPF_OPTS(bpf_link_create_opts, link_opts,
                                .perf_event.bpf_cookie = OPTS_GET(opts, bpf_cookie, 0));
                link_fd = bpf_link_create(prog_fd, pfd, BPF_PERF_EVENT, &link_opts);
                link->link.fd = link_fd;
        }
                        ...
        return &link->link;
}
```
`bpf_link_create()` -> `sys_bpf_fd()` -> `sys_bpf(BPF_LINK_CREATE, ...)`
```c
kernel/bpf/syscall.c
static int __sys_bpf(int cmd, bpfptr_t uattr, unsigned int size) {
                ...
        swtich(cmd) {
                        ...
        case BPF_LINK_CREATE:
                err = link_create(&attr, uattr);
                break;
                        ...
        }
                ...
}

static int link_create(union bpf_attr *attr, bpfptr_t uattr) {
        struct bpf_prog *prog;

        prog = bpf_prog_get(attr->link_create.prog_fd);
                ...
        switch(prog->type) {
                        ...
        case BPF_PROG_TYPE_KPROBE:
                if (attr->link_create.attach_type == BPF_PERF_EVENT)
                        ret = bpf_perf_link_attach(attr, prog);
                else
                        ret = bpf_kprobe_multi_link_attach(attr, prog);
                break;
                        ...
        }
        return ret;
}

static int bpf_perf_link_attach(const union bpf_attr *attr, struct bpf_prog *prog) {
        struct file *perf_file;

        perf_file = perf_event_get(attr->link_create.target_fd);
        link = kzalloc(sizeof(*link), GFP_USER);
        bpf_link_init(&link->link, BPF_LINK_TYPE_PERF_EVENT, &bpf_perf_link_lops, prog);
        link->perf_file = perf_file;

        bpf_link_prime(&link->link, &link_primer);
        event = perf_file->private_data;
        perf_event_set_bpf_prog(event, prog, attr->link_create.perf_event.bpf_cookie);
        bpf_prog_inc(prog);
        return bpf_link_settle(&link_primer);
}
```
`perf_event_set_bpf_prog()` -> `perf_event_attach_bpf_prog()`
```c
int perf_event_attach_bpf_prog(struct perf_event *event,
                struct bpf_prog *prog, u64 bpf_cookie) {
        struct bpf_prog_array *old_array;
        struct bpf_prog_array *new_array;
        int ret = -EEXIST;

        old_array = bpf_event_rcu_dereference(event->tp_event->prog_array);
        ret = bpf_prog_array_copy(old_array, NULL, prog, bpf_cookie, &new_array);
        event->prog = prog;
        event->bpf_cookie = bpf_cookie;
        rcu_assign_pointer(event->tp_event->prog_array, new_array);
        return ret;
}
```
`kprobe_int3_handler()` -> `struct kprobe.pre_handler = kprobe_dispatcher()` -> `kprobe_perf_func()` -> `trace_call_bpf()`<br>
```c
unsigned int trace_call_bpf(struct trace_event_call *call, void *ctx) {
                ...
        ret = bpf_prog_run_array(rcu_dereference(call->prog_array), ctx, bpf_prog_run);
}

static __always_inline u32
bpf_prog_run_array(const struct bpf_prog_array *array,
                const void *ctx, bpf_prog_run_fn run_prog) {
                ...
        while((prog = READ_ONCE(item->prog))) {
                run_ctx.bpf_cookie = item->bpf_cookie;
                ret &= run_prog(prog, ctx);
                item++;
        }
                ...
}

static __always_inline u32 bpf_prog_run(const struct bpf_prog *prog, const void *ctx) {
        return __bpf_prog_run(prog, ctx, bpf_dispatcher_nop_func);
}

static __always_inline u32 __bpf_prog_run(const struct bpf_prog *prog,
                                          const void *ctx,
                                          bpf_dispatcher_fn dfunc)
{
        u32 ret;

        cant_migrate();
        if (static_branch_unlikely(&bpf_stats_enabled_key)) {
                struct bpf_prog_stats *stats;
                u64 start = sched_clock();
                unsigned long flags;

                ret = dfunc(ctx, prog->insnsi, prog->bpf_func);
                stats = this_cpu_ptr(prog->stats);
                flags = u64_stats_update_begin_irqsave(&stats->syncp);
                u64_stats_inc(&stats->cnt);
                u64_stats_add(&stats->nsecs, sched_clock() - start);
                u64_stats_update_end_irqrestore(&stats->syncp, flags);
        } else {
                ret = dfunc(ctx, prog->insnsi, prog->bpf_func);
        }
        return ret;
}

static __always_inline __nocfi unsigned int bpf_dispatcher_nop_func(const void *ctx,
                const struct bpf_insn *insnsi,
                unsigned int (*bpf_func)(const void *, const struct bpf_insn *)) {
        return bpf_func(ctx, insnsi);
}
```
The function pointer `prog->bpf_func` point to the BPF program image was compiled by `JIT` compiler.<br>
We can dump this image by `bpftool`
```
➜  bpftool git:(master) ✗ sudo ./bpftool prog
                ...
138: kprobe  name bpf_prog1  tag 1db92c82623b9aec  gpl
        loaded_at 2022-07-31T21:44:25+0800  uid 0
        xlated 384B  jited 218B  memlock 4096B  map_ids 3
        btf_id 208
➜  bpftool git:(master) ✗ sudo ./bpftool prog dump xlated id 138
int bpf_prog1(struct pt_regs * ctx):
; bpf_probe_read_kernel(&skb, sizeof(skb), (void *)PT_REGS_PARM1(ctx));
   0: (79) r3 = *(u64 *)(r1 +112)
   1: (bf) r1 = r10
;
   2: (07) r1 += -24
; bpf_probe_read_kernel(&skb, sizeof(skb), (void *)PT_REGS_PARM1(ctx));
   3: (b7) r2 = 8
   4: (85) call bpf_probe_read_kernel#-66000
   5: (b7) r6 = 0
; dev = _(skb->dev);
   6: (7b) *(u64 *)(r10 -16) = r6
   7: (79) r3 = *(u64 *)(r10 -24)
   8: (07) r3 += 16
   9: (bf) r1 = r10
;
  10: (07) r1 += -16
; dev = _(skb->dev);
  11: (b7) r2 = 8
  12: (85) call bpf_probe_read_kernel#-66000
  13: (79) r7 = *(u64 *)(r10 -16)
; len = _(skb->len);
  14: (63) *(u32 *)(r10 -16) = r6
  15: (79) r3 = *(u64 *)(r10 -24)
  16: (07) r3 += 112
  17: (bf) r1 = r10
;
  18: (07) r1 += -16
; len = _(skb->len);
  19: (b7) r2 = 4
  20: (85) call bpf_probe_read_kernel#-66000
  21: (61) r6 = *(u32 *)(r10 -16)
  22: (bf) r1 = r10
;
  23: (07) r1 += -16
; bpf_probe_read_kernel(devname, sizeof(devname), dev->name);
  24: (b7) r2 = 16
  25: (bf) r3 = r7
  26: (85) call bpf_probe_read_kernel#-66000
; if (devname[0] == 'l' && devname[1] == 'o') {
  27: (71) r1 = *(u8 *)(r10 -16)
; if (devname[0] == 'l' && devname[1] == 'o') {
  28: (55) if r1 != 0x6c goto pc+17
; if (devname[0] == 'l' && devname[1] == 'o') {
  29: (71) r1 = *(u8 *)(r10 -15)
; if (devname[0] == 'l' && devname[1] == 'o') {
  30: (55) if r1 != 0x6f goto pc+15
  31: (b7) r1 = 0
; char fmt[] = "skb %p len %d\n";
  32: (73) *(u8 *)(r10 -26) = r1
  33: (b7) r1 = 2660
  34: (6b) *(u16 *)(r10 -28) = r1
  35: (b7) r1 = 622882405
  36: (63) *(u32 *)(r10 -32) = r1
  37: (18) r1 = 0x6c20702520626b73
  39: (7b) *(u64 *)(r10 -40) = r1
; bpf_trace_printk(fmt, sizeof(fmt), skb, len);
  40: (79) r3 = *(u64 *)(r10 -24)
  41: (bf) r1 = r10
; char fmt[] = "skb %p len %d\n";
  42: (07) r1 += -40
; bpf_trace_printk(fmt, sizeof(fmt), skb, len);
  43: (b7) r2 = 15
  44: (bf) r4 = r6
  45: (85) call bpf_trace_printk#-62640
; return 0;
  46: (b7) r0 = 0
  47: (95) exit
```
