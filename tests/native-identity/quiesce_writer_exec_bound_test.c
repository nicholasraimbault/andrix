#define QUIESCE_EXEC_TEST
#define main bound_helper_tests
#include "quiesce_writer_exec_bound.c"
#undef main
static void replace_bytes(int fd, const void *data, size_t size) {
    assert(ftruncate(fd, 0) == 0); size_t done = 0;
    while (done < size) { ssize_t n = pwrite(fd, (const char *)data + done, size - done, (off_t)done); assert(n > 0); done += (size_t)n; }
}
int main(void) {
    int original = open("/proc/self/exe", O_RDONLY | O_CLOEXEC); assert(original >= 0);
    struct stat metadata; assert(fstat(original, &metadata) == 0 && metadata.st_size < EXE_LIMIT);
    size_t size = (size_t)metadata.st_size; unsigned char *base = malloc(size), *changed = malloc(size); assert(base && changed && exact_pread(original, base, size, 0)); close(original);
    const char *tmp = getenv("TMPDIR"); assert(tmp && tmp[0] == '/'); char path[PATH_MAX], alias[PATH_MAX];
    assert(snprintf(path, sizeof(path), "%s/elf-XXXXXX", tmp) < (int)sizeof(path));
    int fd = mkstemp(path); assert(fd >= 0 && fchmod(fd, 0700) == 0); replace_bytes(fd, base, size);
    struct stat checked; assert(executable_elf(fd, &checked));
    assert(fchmod(fd, 0755) == 0 && !executable_elf(fd, &checked) && fchmod(fd, 0700) == 0);
    assert(snprintf(alias, sizeof(alias), "%s.link", path) < (int)sizeof(alias));
    assert(link(path, alias) == 0 && !executable_elf(fd, &checked) && unlink(alias) == 0);
    assert(ftruncate(fd, sizeof(Elf64_Ehdr)-1) == 0 && !executable_elf(fd, &checked));
    assert(ftruncate(fd, EXE_LIMIT+1) == 0 && !executable_elf(fd, &checked)); replace_bytes(fd, base, size);
    for (int which = 0; which < 9; ++which) {
        memcpy(changed, base, size); Elf64_Ehdr *header = (Elf64_Ehdr *)changed;
        Elf64_Phdr *program = (Elf64_Phdr *)(changed + header->e_phoff); unsigned interp = 0;
        while (interp < header->e_phnum && program[interp].p_type != PT_INTERP) ++interp;
        assert(interp < header->e_phnum && header->e_phnum > 1);
        if (which == 0) header->e_ident[EI_CLASS] = ELFCLASS32;
        if (which == 1) header->e_machine = EM_ARM;
        if (which == 2) header->e_type = ET_EXEC;
        if (which == 3) program[interp].p_type = PT_NOTE;
        if (which == 4) program[interp ? 0 : 1] = program[interp];
        if (which == 5) changed[program[interp].p_offset] = 'x';
        if (which == 6) ++program[interp].p_filesz;
        if (which == 7) header->e_phoff = UINT64_MAX;
        if (which == 8) header->e_phoff = size-1;
        replace_bytes(fd, changed, size); assert(!executable_elf(fd, &checked));
    }
    replace_bytes(fd, base, size); assert(executable_elf(fd, &checked));
    struct stat same = checked; assert(same_executable(&checked, &same));
    ++same.st_ino; assert(!same_executable(&checked, &same)); same = checked;
    ++same.st_ctim.tv_nsec; assert(!same_executable(&checked, &same)); same = checked;
    ++same.st_atim.tv_sec; assert(same_executable(&checked, &same));
    int channels[2]; assert(pipe(channels) == 0 && !executable_elf(channels[0], &checked));close(channels[0]);close(channels[1]);
    close(fd); assert(unlink(path) == 0); free(base);free(changed);
    /* Actual parent-death behavior, not a stop-service model. */
    assert(prctl(PR_SET_CHILD_SUBREAPER, 1) == 0); int announce[2]; assert(pipe2(announce,O_CLOEXEC)==0);
    pid_t parent = fork(); assert(parent >= 0);
    if (!parent) {
        close(announce[0]);pid_t self=getpid(), child=fork();if(child<0)_exit(120);
        if(!child){child_parent_guard(self);pid_t mine=getpid();if(write(announce[1],&mine,sizeof(mine))!=(ssize_t)sizeof(mine))_exit(121);for(;;)pause();}
        close(announce[1]);for(;;)pause();
    }
    close(announce[1]);pid_t grandchild=0;assert(read(announce[0],&grandchild,sizeof(grandchild))==(ssize_t)sizeof(grandchild));close(announce[0]);
    int pfd=pid_descriptor(parent), cfd=pid_descriptor(grandchild);assert(pfd>=0&&cfd>=0&&descriptor_exited(cfd,0)==0);
    assert(syscall(SYS_pidfd_send_signal,pfd,SIGKILL,NULL,0)==0);int status;assert(waitpid(parent,&status,0)==parent&&WIFSIGNALED(status));
    assert(descriptor_exited(cfd,2000)==1&&waitpid(grandchild,&status,0)==grandchild&&WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL);close(pfd);close(cfd);
    puts("ELF descriptor refusals, metadata bookends and actual PDEATHSIG child exit passed; no Android stop claim"); return 0;
}
