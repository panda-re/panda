use chumsky::prelude::*;

#[derive(Debug, Clone)]
pub(crate) enum Type {
    Ptr(Box<Type>),
    Ident(String),
    Struct(String),
    Union(String),
    Const(Box<Type>),
    Unsigned(String),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CTypeParseFail;

impl Type {
    pub(crate) fn parse(s: &str) -> Result<Self, CTypeParseFail> {
        parser().parse(s).map_err(|_| CTypeParseFail)
    }
}

fn parser() -> impl Parser<char, Type, Error = Simple<char>> {
    recursive(|c_type| {
        let atom = choice((
            struct_type(),
            union_type(),
            unsigned_ident(),
            ident().map(Type::Ident),
            c_type,
        ));

        let longness =
            kw("long")
                .or_not()
                .then(atom)
                .map(|(qualifier, inner)| match qualifier.is_some() {
                    true => match inner {
                        Type::Ident(inner) => Type::Ident(format!("long {}", inner)),
                        Type::Unsigned(inner) => Type::Unsigned(format!("long {}", inner)),
                        _ => panic!("cannot apply 'long' to {:?}", inner),
                    },
                    false => inner,
                });

        let qualification = kw("const")
            .or_not()
            .then(longness)
            .map(|(qualifier, inner)| match qualifier.is_some() {
                true => Type::Const(Box::new(inner)),
                false => inner,
            });

        let pointer = qualification
            .then(
                kw("const")
                    .or_not()
                    .then(just('*').padded().ignored())
                    .map(|(opt, _)| opt.is_some())
                    .repeated(),
            )
            .foldl(|left, is_const| match is_const {
                true => Type::Ptr(Box::new(Type::Const(Box::new(left)))),
                false => Type::Ptr(Box::new(left)),
            });

        let end_const = pointer
            .then(kw("const").or_not())
            .map(|(inner, maybe_const)| match maybe_const.is_some() {
                true => Type::Const(Box::new(inner)),
                false => inner,
            });

        let ignore_suffix = end_const.then_ignore(kw("f_t").or_not());

        kw("long")
            .padded()
            .then_ignore(end())
            .map(|_| Type::Ident("long".into()))
            .or(ignore_suffix)
    })
    .padded()
    .then_ignore(end())
}

fn kw(k: &str) -> impl Parser<char, (), Error = Simple<char>> + Clone + '_ {
    text::keyword(k).ignored().padded()
}

fn struct_type() -> impl Parser<char, Type, Error = Simple<char>> + Clone {
    kw("struct")
        .then(ident())
        .map(|(_, name)| Type::Struct(name))
}

fn union_type() -> impl Parser<char, Type, Error = Simple<char>> + Clone {
    kw("union").then(ident()).map(|(_, name)| Type::Union(name))
}

fn unsigned_ident() -> impl Parser<char, Type, Error = Simple<char>> + Clone {
    kw("unsigned")
        .then(ident())
        .map(|(_, name)| Type::Unsigned(name))
}

fn ident() -> impl Parser<char, String, Error = Simple<char>> + Clone {
    text::ident().padded().labelled("identifier")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TYPES: &str = r"
        int
        unsigned int
        char *
        size_t
        const char *
        umode_t
        pid_t
        int *
        const char *const *
        time_t *
        unsigned
        old_uid_t
        old_gid_t
        struct __old_kernel_stat *
        oft64 *
        uid_t
        gid_t
        gid_t *
        uid_t *
        unsigned char *
        struct linux_dirent64 *
        const void *
        u32 *
        u32
        struct user_desc *
        aio_context_t *
        aio_context_t
        struct io_event *
        struct iocb * *
        struct iocb *
        u64
        struct epoll_event *
        const clockid_t
        struct sigevent *
        timer_t *
        timer_t
        const struct itimerspec *
        struct itimerspec *
        struct statfs64 *
        struct mq_attr *
        mqd_t
        unsigned int *
        const struct sigevent *
        const struct mq_attr *
        struct kexec_segment *
        struct siginfo *
        key_serial_t
        __s32
        struct robust_list_head *
        struct robust_list_head * *
        size_t *
        unsigned *
        struct getcpu_cache *
        struct perf_event_attr *
        struct mmsghdr *
        __u64
        const struct rlimit64 *
        struct rlimit64 *
        struct file_handle *
        struct sched_attr *
        union bpf_attr *
        struct sockaddr *f_t
        unsigned long
        void *
        long
        struct utimbuf *
        struct tms *
        __sighandler_t
        struct oldold_utsname *
        struct ustat *
        const struct old_sigaction *
        struct old_sigaction *
        old_sigset_t
        old_sigset_t *
        struct rlimit *
        struct rusage *
        struct timeval *
        struct timezone *
        old_gid_t *
        struct sel_arg_struct *
        struct old_linux_dirent *
        struct mmap_arg_struct *
        struct statfs *
        unsigned long *
        struct itimerval *
        struct stat *
        struct old_utsname *
        struct vm86_struct *
        struct sysinfo *
        struct new_utsname *
        struct timex *
        qid_t
        loff_t *
        struct linux_dirent *
        fd_set *
        const struct iovec *
        struct __sysctl_args *
        struct sched_param *
        struct timespec *
        old_uid_t *
        struct pollfd *
        const struct sigaction *
        struct sigaction *
        sigset_t *
        const sigset_t *
        siginfo_t *
        const struct timespec *
        loff_t
        cap_user_header_t
        cap_user_data_t
        const cap_user_data_t
        const stack_t *
        stack_t *
        off_t *
        struct sta
        long unsigned int
    ";

    #[test]
    fn try_parse_all() {
        for type_str in TYPES.trim().split('\n').map(|line| line.trim()) {
            let res = parser().parse(type_str);

            println!("{:?}: {:#?}", type_str, res);
            let _ = res.unwrap();
        }
    }
}
