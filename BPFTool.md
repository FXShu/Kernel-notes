# BPFTool

## Prog module
```c
static int do_load(int argc, char **argv) {
    if (use_loader)
        return do_loader(argc, argv);
    return load_with_options(argc, argv, true);
}

static int load_with_options(int argc, char **argv, bool first_prog_only) {
            ...
    obj = bpf_object__open_file(file, &open_opts);
            ...
    bpf_object__load(obj);
    mount_bpffs_for_pin(pinfile);

    if (first_prong_only) {
        prog = bpf_object__next_program(obj, NULL);
        bpf_obj_pin(bpf_program__fd(prog), pinfile);
    } else {
        bpf_object__pin_programs(obj, pinfile);
    }

    if(pinmaps) {
        bpf_object__pin_maps(obj, pinmaps);
    }

    bpf_object__close(obj);
    return 0;
}

```
### BPF program loading
```c
static int bpf_object_load(struct bpf_object *obj, int extra_log_level, const char *target_btf_path) {

}
```

### BPF filesystem (bpffs)
```c
int mount_bpffs_for_pin(const char *name)
{
        char err_str[ERR_MAX_LEN];
        char *file;
        char *dir;
        int err = 0;

        file = malloc(strlen(name) + 1);
        if (!file) {
                p_err("mem alloc failed");
                return -1;
        }

        strcpy(file, name);
        dir = dirname(file);

        if (is_bpffs(dir))
                /* nothing to do if already mounted */
                goto out_free;

        if (block_mount) {
                p_err("no BPF file system found, not mounting it due to --nomount option");
                err = -1;
                goto out_free;
        }

        err = mnt_fs(dir, "bpf", err_str, ERR_MAX_LEN);
        if (err) {
                err_str[ERR_MAX_LEN - 1] = '\0';
                p_err("can't mount BPF file system to pin the object (%s): %s",
                      name, err_str);
        }

out_free:
        free(file);
        return err;
}

static int
mnt_fs(const char *target, const char *type, char *buff, size_t bufflen)
{
        bool bind_done = false;

        while (mount("", target, "none", MS_PRIVATE | MS_REC, NULL)) {
                if (errno != EINVAL || bind_done) {
                        snprintf(buff, bufflen,
                                 "mount --make-private %s failed: %s",
                                 target, strerror(errno));
                        return -1;
                }

                if (mount(target, target, "none", MS_BIND, NULL)) {
                        snprintf(buff, bufflen,
                                 "mount --bind %s %s failed: %s",
                                 target, target, strerror(errno));
                        return -1;
                }

                bind_done = true;
        }

        if (mount(type, target, type, 0, "mode=0700")) {
                snprintf(buff, bufflen, "mount -t %s %s %s failed: %s",
                         type, type, target, strerror(errno));
                return -1;
        }

        return 0;
}

kernel/bpf/inode.c
static struct file_system_type bpf_fs_type = {
    .owner              = THIS_MODULE,
    .name               = "bpf",
    .init_fs_context    = bpf_init_fs_context,
    .parameters         = bpf_fs_parameters,
    .kill_sb            = kill_litter_super,
}

static int __init bpf_init(void) {
    int ret;

    sysfs_create_mount_point(fs_kobj, "bpf");

    register_filesystem(&bpf_fs_type);
}

int bpf_obj_pin(int fd, const char *pathname) {
    union bpf_attr attr;
    int ret;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = ptr_to_u64((void *)pathname);
    attr.bpf_fd = fd;

    ret = sys_bpf(BPF_OBJ_PIN, &attr, sizeof(attr));
    return libbpf_err_errno(ret);
}
```

kernel
`__sys_bpf()` -> `bpf_obj_pin()` -> `bpf_obj_pin_user()` -> `bpf_obj_do_pin()`
```c
int bpf_obj_pin_user(u32 ufd, const char __user *pathname)
{
        enum bpf_type type;
        void *raw;
        int ret;

        raw = bpf_fd_probe_obj(ufd, &type);
        if (IS_ERR(raw))
                return PTR_ERR(raw);

        ret = bpf_obj_do_pin(pathname, raw, type);
        if (ret != 0)
                bpf_any_put(raw, type);

        return ret;
}

static int bpf_obj_do_pin(const char __user *pathname, void *raw,
                          enum bpf_type type)
{
        struct dentry *dentry;
        struct inode *dir;
        struct path path;
        umode_t mode;
        int ret;

        dentry = user_path_create(AT_FDCWD, pathname, &path, 0);
        if (IS_ERR(dentry))
                return PTR_ERR(dentry);

        mode = S_IFREG | ((S_IRUSR | S_IWUSR) & ~current_umask());

        ret = security_path_mknod(&path, dentry, mode, 0);
        if (ret)
                goto out;

        dir = d_inode(path.dentry);
        if (dir->i_op != &bpf_dir_iops) {
                ret = -EPERM;
                goto out;
        }

        switch (type) {
        case BPF_TYPE_PROG:
                ret = vfs_mkobj(dentry, mode, bpf_mkprog, raw);
                break;
        case BPF_TYPE_MAP:
                ret = vfs_mkobj(dentry, mode, bpf_mkmap, raw);
                break;
        case BPF_TYPE_LINK:
                ret = vfs_mkobj(dentry, mode, bpf_mklink, raw);
                break;
        default:
                ret = -EPERM;
        }
out:
        done_path_create(&path, dentry);
        return ret;
}

static int bpf_mkprog(struct dentry *dentry, umode_t mode, void *arg) {
    return bpf_mkobj_ops(dentry, mode, arg, &bpf_prog_iops, &bpffs_obj_fops);
}

static const struct inode_operations bpf_prog_iops = { };
static const struct file_operations bpffs_obj_fops = {
    .open = bpffs_obj_open,
}

static int bpffs_obj_open(struct inode *inode, struct file *file) {
    return -EIO;
}
```
```bash
➜  any_test sudo cat bpf_test/pipe
cat: bpf_test/pipe: Input/output error
➜  any_test
```