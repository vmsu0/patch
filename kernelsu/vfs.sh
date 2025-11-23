#!/bin/bash
# Patches author: backslashxx @Github
# Shell authon: JackA1ltman <cs2dtzq@163.com>
# Tested kernel versions: 5.4, 4.19, 4.14, 4.9
# 20250309

patch_files=(
    fs/exec.c
    fs/open.c
    fs/read_write.c
    fs/stat.c
    fs/namespace.c
    fs/devpts/inode.c
    drivers/input/input.c
    drivers/tty/pty.c
    security/security.c
    security/selinux/hooks.c
)

PATCH_LEVEL="1.5"
KERNEL_VERSION=$(head -n 3 Makefile | grep -E 'VERSION|PATCHLEVEL' | awk '{print $3}' | paste -sd '.')
FIRST_VERSION=$(echo "$KERNEL_VERSION" | awk -F '.' '{print $1}')
SECOND_VERSION=$(echo "$KERNEL_VERSION" | awk -F '.' '{print $2}')

echo "Current patch version:$PATCH_LEVEL"

for i in "${patch_files[@]}"; do

    if grep -q "ksu" "$i"; then
        echo "Warning: $i contains KernelSU"
        continue
    fi

    case $i in

    # fs/ changes
    # exec.c
    fs/exec.c)
        sed -i '/int do_execve(struct filename \*filename,/i\#ifdef CONFIG_KSU\nextern bool ksu_execveat_hook __read_mostly;\nextern int ksu_handle_execveat(int *fd, struct filename **filename_ptr, void *argv,\n\t\t\tvoid *envp, int *flags);\nextern int ksu_handle_execveat_sucompat(int *fd, struct filename **filename_ptr,\n\t\t\t\tvoid *argv, void *envp, int *flags);\n#endif' fs/exec.c
        sed -i '/do_execve *(/,/^}/ {
/struct user_arg_ptr envp = { .ptr.native = __envp };/a\
#ifdef CONFIG_KSU\
\tif (unlikely(ksu_execveat_hook))\
\t\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\
\telse\
\t\tksu_handle_execveat_sucompat((int *)AT_FDCWD, &filename, NULL, NULL, NULL);\
#endif
}' fs/exec.c

        sed -i ':a;N;$!ba;s/\(return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);\)/\n#ifdef CONFIG_KSU\n\tif (!ksu_execveat_hook)\n\t\tksu_handle_execveat_sucompat((int *)AT_FDCWD, \&filename, NULL, NULL, NULL); \/* 32-bit su *\/\n#endif\n\1/2' fs/exec.c
        ;;

    # open.c
    fs/open.c)
        if grep -q "return do_faccessat(dfd, filename, mode);" fs/open.c; then
            sed -i '/return do_faccessat(dfd, filename, mode);/i\#ifdef CONFIG_KSU\nextern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,\n\tint *flags);\n#endif' fs/open.c
        else
            sed -i ':a;N;$!ba;s/\(unsigned int lookup_flags = LOOKUP_FOLLOW;\)/\1\n#ifdef CONFIG_KSU\n\tksu_handle_faccessat(\&dfd, \&filename, \&mode, NULL);\n#endif/2' fs/open.c

        fi
        sed -i '0,/SYSCALL_DEFINE3(faccessat, int, dfd, const char __user \*, filename, int, mode)/s//#ifdef CONFIG_KSU\nextern int ksu_handle_faccessat(int *dfd, const char __user **filename_user, int *mode,\n\t\t\t                    int *flags);\n#endif\n&/' fs/open.c
        ;;

    # read_write.c
    fs/read_write.c)
        if grep -q "return ksys_read(fd, buf, count);" fs/read_write.c; then
            sed -i '/return ksys_read(fd, buf, count);/i\#ifdef CONFIG_KSU\n\tif (unlikely(ksu_vfs_read_hook))\n\t\tksu_handle_sys_read(fd, &buf, &count);\n#endif' fs/read_write.c
        else
            sed -i '0,/if (f.file) {/s//if (f.file) {\nloff_t pos;\n#ifdef CONFIG_KSU\n\tif (unlikely(ksu_vfs_read_hook))\n\t\tksu_handle_sys_read(fd, \&buf, \&count);\n#endif/' fs/read_write.c
	    sed -i '0,/loff_t pos = file_pos_read(f.file);/s/loff_t pos = file_pos_read(f.file);/pos = file_pos_read(f.file);/' fs/read_write.c
        fi
        sed -i '/SYSCALL_DEFINE3(read, unsigned int, fd, char __user \*, buf, size_t, count)/i\#ifdef CONFIG_KSU\nextern bool ksu_vfs_read_hook __read_mostly;\nextern int ksu_handle_sys_read(unsigned int fd, char __user **buf_ptr,\n\t\t\tsize_t *count_ptr);\n#endif' fs/read_write.c
        ;;

    # stat.c
    fs/stat.c)
        sed -i '/#if !defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_SYS_NEWFSTATAT)/i\#ifdef CONFIG_KSU\nextern int ksu_handle_stat(int *dfd, const char __user **filename_user, int *flags);\n#endif' fs/stat.c
        sed -i '0,/\terror = vfs_fstatat(dfd, filename, &stat, flag);/s//#ifdef CONFIG_KSU\n\tksu_handle_stat(\&dfd, \&filename, \&flag);\n#endif\n&/' fs/stat.c
        sed -i ':a;N;$!ba;s/\(\terror = vfs_fstatat(dfd, filename, &stat, flag);\)/#ifdef CONFIG_KSU\n\tksu_handle_stat(\&dfd, \&filename, \&flag);\n#endif\n\1/2' fs/stat.c
        ;;

    # drivers/input changes
    ## input.c
    drivers/input/input.c)
        sed -i '0,/void input_event(struct input_dev \*dev,/s//#ifdef CONFIG_KSU\nextern bool ksu_input_hook __read_mostly;\nextern int ksu_handle_input_handle_event(unsigned int \*type, unsigned int \*code, int \*value);\n#endif\n&/' drivers/input/input.c
        sed -i '0,/\tif (is_event_supported(type, dev->evbit, EV_MAX)) {/s//#ifdef CONFIG_KSU\n\tif (unlikely(ksu_input_hook))\n\t\tksu_handle_input_handle_event(\&type, \&code, \&value);\n#endif\n&/' drivers/input/input.c
        ;;

    # drivers/tty changes
    # pty.c
    drivers/tty/pty.c)
        sed -i '0,/static struct tty_struct \*pts_unix98_lookup(struct tty_driver \*driver,/s//#ifdef CONFIG_KSU\nextern int __ksu_handle_devpts(struct inode*);\n#endif\n&/' drivers/tty/pty.c
        sed -i ':a;N;$!ba;s/\(\tmutex_lock(&devpts_mutex);\)/#ifdef CONFIG_KSU\n\t__ksu_handle_devpts((struct inode *)file->f_path.dentry->d_inode);\n#endif\n\1/2' drivers/tty/pty.c
        ;;

    # security/ changes
    # security.c
    security/security.c)
        if [ "$FIRST_VERSION" -lt 4 ] && [ "$SECOND_VERSION" -lt 18 ]; then
            sed -i '/#ifdef CONFIG_BPF_SYSCALL/i \#ifdef CONFIG_KSU\nextern int ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,\n\t\t   unsigned long arg4, unsigned long arg5);\nextern int ksu_handle_rename(struct dentry *old_dentry, struct dentry *new_dentry);\nextern int ksu_handle_setuid(struct cred *new, const struct cred *old);\n#endif' security/security.c
            sed -i '/if (unlikely(IS_PRIVATE(old_dentry->d_inode) ||/i \#ifdef CONFIG_KSU\n\tksu_handle_rename(old_dentry, new_dentry);\n#endif' security/security.c
            sed -i '/return security_ops->task_fix_setuid(new, old, flags);/i \#ifdef CONFIG_KSU\n\tksu_handle_setuid(new, old);\n#endif' security/security.c
            sed -i '/return security_ops->task_prctl(option, arg2, arg3, arg4, arg5);/i \#ifdef CONFIG_KSU\n\tksu_handle_prctl(option, arg2, arg3, arg4, arg5);\n#endif' security/security.c
        fi
        ;;

    # selinux/hooks.c
    security/selinux/hooks.c)
        if [ "$FIRST_VERSION" -lt 4 ] && [ "$SECOND_VERSION" -lt 11 ]; then
            sed -i '/static int selinux_bprm_set_creds(struct linux_binprm \*bprm)/i \#ifdef CONFIG_KSU\nextern bool is_ksu_transition(const struct task_security_struct \*old_tsec,\n\t\t\tconst struct task_security_struct \*new_tsec);\n#endif' security/selinux/hooks.c
            sed -i '/new_tsec->exec_sid = 0;/a \#ifdef CONFIG_KSU\n\t\tif (is_ksu_transition(old_tsec, new_tsec))\n\t\t\treturn 0;\n#endif' security/selinux/hooks.c
        elif [ "$FIRST_VERSION" -lt 5 ] && [ "$SECOND_VERSION" -lt 10 ]; then
            sed -i '/static int check_nnp_nosuid(const struct linux_binprm \*bprm,/i \#ifdef CONFIG_KSU\nextern bool ksu_execveat_hook __read_mostly;\nextern bool is_ksu_transition(const struct task_security_struct \*old_tsec,\n\t\t\t\tconst struct task_security_struct \*new_tsec);\n#endif' security/selinux/hooks.c
            sed -i '/rc = security_bounded_transition(old_tsec->sid, new_tsec->sid);/i \#ifdef CONFIG_KSU\n\tif (is_ksu_transition(old_tsec, new_tsec))\n\t\treturn 0;\n#endif' security/selinux/hooks.c
        fi
        ;;

    # fs/ changes
    fs/namespace.c)
        if [[ $(grep -c "static int can_umount(const struct" fs/namespace.c) == 0 ]]; then
            if grep -q "may_mandlock(void)" fs/namespace.c; then
                umount='may_mandlock(void)/,/^}/ { /^}/ {n;a'
            else
                umount='int ksys_umount(char __user \*name, int flags)/i'
            fi
        sed -i "/${umount} \
#ifdef CONFIG_KSU\n\
static int can_umount(const struct path *path, int flags)\n\
{\n\
    struct mount *mnt = real_mount(path->mnt);\n\
\n\
    if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))\n\
        return -EINVAL;\n\
    if (!may_mount())\n\
        return -EPERM;\n\
    if (path->dentry != path->mnt->mnt_root)\n\
        return -EINVAL;\n\
    if (!check_mnt(mnt))\n\
        return -EINVAL;\n\
    if (mnt->mnt.mnt_flags & MNT_LOCKED) /* Check optimistically */\n\
        return -EINVAL;\n\
    if (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))\n\
        return -EPERM;\n\
    return 0;\n\
}\n\
\n\
int path_umount(struct path *path, int flags)\n\
{\n\
    struct mount *mnt = real_mount(path->mnt);\n\
    int ret;\n\
\n\
    ret = can_umount(path, flags);\n\
    if (!ret)\n\
        ret = do_umount(mnt, flags);\n\
\n\
    /* we must not call path_put() as that would clear mnt_expiry_mark */\n\
    dput(path->dentry);\n\
    mntput_no_expire(mnt);\n\
    return ret;\n\
}\n\
#endif
}}" fs/namespace.c
        fi
        ;;

    # fs/devpts changes
    fs/devpts/inode.c)
        sed -i '/struct dentry \*devpts_pty_new/,/return dentry;/ {
    /return dentry;/ {n; a\
#ifdef CONFIG_KSU\nextern int __ksu_handle_devpts(struct inode*);\n#endif
    }
}
        /if (dentry->d_sb->s_magic != DEVPTS_SUPER_MAGIC)/i\
	#ifdef CONFIG_KSU\n	__ksu_handle_devpts(dentry->d_inode);\n	#endif' fs/devpts/inode.c
        ;;
    esac

    echo "Patch applied successfully to $i"

done
