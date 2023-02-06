#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <syscall-nr.h>

struct lock file_sys_lock; /* Lock for file system */

static void syscall_handler(struct intr_frame *);
static int load_mem(void *esp, void *dest, unsigned size);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
bool create(const char *file_name, unsigned initial_size);
bool remove(const char *file_name);
unsigned tell(int fd);
struct FCB *get_fcb(int fd);

void syscall_init(void) {
    lock_init(&file_sys_lock);
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED) {

    int systemcall_number;

    if (!load_mem(f->esp, &systemcall_number, sizeof(int))) {
        exit(-1);
    }

    // printf("System call number: %d\n", systemcall_number);

    switch (systemcall_number) {
    case SYS_EXIT: {
        int exit_number;

        if (!load_mem(f->esp + 4, &exit_number, sizeof(int))) {
            exit(-1);
        }

        exit(exit_number);
        break;
    }

    case SYS_WAIT: {
        int pid;

        if (!load_mem(f->esp + 4, &pid, sizeof(int))) {
            exit(-1);
        }

        f->eax = wait(pid);
        break;
    }

    case SYS_HALT: {
        shutdown_power_off();
        break;
    }

    case SYS_OPEN: {
        const char *file_name;

        if (!load_mem(f->esp + 4, &file_name, sizeof(char *))) {
            exit(-1);
        }

        f->eax = open(file_name);
        break;
    }

    case SYS_WRITE: {
        int fd;
        const void *buffer;
        unsigned size;

        if (!load_mem(f->esp + 4, &fd, sizeof(int)) ||
            !load_mem(f->esp + 8, &buffer, sizeof(void *)) ||
            !load_mem(f->esp + 12, &size, sizeof(unsigned))) {
            exit(-1);
        }

        f->eax = write(fd, buffer, size);
        break;
    }

    case SYS_READ: {
        int fd;
        void *buffer;
        unsigned size;

        if (!load_mem(f->esp + 4, &fd, sizeof(int)) ||
            !load_mem(f->esp + 8, &buffer, sizeof(void *)) ||
            !load_mem(f->esp + 12, &size, sizeof(unsigned))) {
            exit(-1);
        }

        f->eax = read(fd, buffer, size);
        break;
    }

    case SYS_REMOVE: {

        const char *file_name;

        if (!load_mem(f->esp + 4, &file_name, sizeof(char *))) {
            exit(-1);
        }

        f->eax = remove(file_name);
        break;
    }

    case SYS_CREATE: {
        const char *file_name;
        unsigned initial_size;

        if (!load_mem(f->esp + 4, &file_name, sizeof(char *)) ||
            !load_mem(f->esp + 8, &initial_size, sizeof(unsigned))) {
            exit(-1);
        }

        f->eax = create(file_name, initial_size);
        break;
    }

    case SYS_FILESIZE: {
        int fd;

        if (!load_mem(f->esp + 4, &fd, sizeof(int))) {
            exit(-1);
        }

        f->eax = filesize(fd);
        break;
    }

    case SYS_SEEK: {
        int fd;
        unsigned position;

        if (!load_mem(f->esp + 4, &fd, sizeof(int)) ||
            !load_mem(f->esp + 8, &position, sizeof(unsigned))) {
            exit(-1);
        }

        seek(fd, position);
        break;
    }

    case SYS_TELL: {
        int fd;

        if (!load_mem(f->esp + 4, &fd, sizeof(int))) {
            exit(-1);
        }

        f->eax = tell(fd);
        break;
    }

    case SYS_CLOSE: {
        int fd;

        if (!load_mem(f->esp + 4, &fd, sizeof(int))) {
            exit(-1);
        }

        close(fd);
        break;
    }

    default: {
        printf("Unimplemented system call: %d\n", systemcall_number);
        break;
    }
    }
}

int exit(int status) {
    struct thread *current_thread = thread_current();

    printf("%s: exit(%d)\n", current_thread->name, status);

    thread_exit();
}

int wait(int pid) {
    return process_wait(pid);
}

int write(int fd, const void *buffer, unsigned size) {
    if (fd < 0 || !is_user_vaddr(buffer) || !is_user_vaddr(buffer + size)) {
        return -1;
    }

    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }

    struct FCB *fcb = get_fcb(fd);
    if (fcb == NULL) {
        return -1;
    }

    struct file *file = fcb->file;
    lock_acquire(&file_sys_lock);
    int bytes_written = file_write(file, buffer, size);
    lock_release(&file_sys_lock);
    return bytes_written;
}

int read(int fd, void *buffer, unsigned size) {
    if (fd < 0 || !is_user_vaddr(buffer) || !is_user_vaddr(buffer + size)) {
        exit(-1);
    }

    if (fd == 0) {
        unsigned i;
        for (i = 0; i < size; i++) {
            ((char *)buffer)[i] = input_getc();
        }
        return size;
    }

    struct FCB *fcb = get_fcb(fd);
    if (fcb == NULL || buffer == NULL || get_user(buffer) == -1 || !is_user_vaddr(buffer + size) || get_user(buffer + size) == -1) {
        exit(-1);
    }

    struct file *file = fcb->file;
    lock_acquire(&file_sys_lock);
    int bytes_read = file_read(file, buffer, size);
    lock_release(&file_sys_lock);
    return bytes_read;
}

int open(const char *file_name) {
    // printf("open: %s\n", file_name);
    //
    if (file_name == NULL || !is_user_vaddr(file_name)) {
        return -1;
    }

    lock_acquire(&file_sys_lock);
    struct file *file = filesys_open(file_name);
    lock_release(&file_sys_lock);
    struct thread *current_thread = thread_current();
    if (file == NULL) {
        return -1;
    }
    current_thread->open_file_count++;
    struct FCB *fcb = malloc(sizeof(struct FCB));
    fcb->fd = current_thread->open_file_count;
    // printf("here\n");
    fcb->file = file;
    list_push_back(&current_thread->open_file_list, &fcb->elem);
    return current_thread->open_file_count;
}

static int load_mem(void *esp, void *dest, unsigned size) {
    unsigned i = 0;
    while (i < size && is_user_vaddr(esp + i)) {
        int byte = get_user(esp + i);
        if (byte == -1) {
            break;
        }
        *(char *)(dest + i) = (uint8_t)byte;
        i++;
    }

    return i == size;
}

bool remove(const char *file_name) {
    if (file_name == NULL || !is_user_vaddr(file_name)) {
        return false;
    }

    lock_acquire(&file_sys_lock);
    bool success = filesys_remove(file_name);
    lock_release(&file_sys_lock);

    return success;
}

bool create(const char *file_name, unsigned initial_size) {
    if (file_name == NULL || !is_user_vaddr(file_name)) {
        exit(-1);
    }

    lock_acquire(&file_sys_lock);
    bool success = filesys_create(file_name, initial_size);
    lock_release(&file_sys_lock);

    return success;
}
// not sure if this is correct
int filesize(int fd) {
    struct thread *current_thread = thread_current();
    struct list_elem *e;
    for (e = list_begin(&current_thread->open_file_list);
         e != list_end(&current_thread->open_file_list); e = list_next(e)) {
        struct FCB *fcb = list_entry(e, struct FCB, elem);
        if (fcb->fd == fd) {
            return file_length(fcb->file);
        }
    }

    return -1;
}
// not sure if this is correct
void seek(int fd, unsigned position) {
    struct thread *current_thread = thread_current();
    struct list_elem *e;
    for (e = list_begin(&current_thread->open_file_list);
         e != list_end(&current_thread->open_file_list); e = list_next(e)) {
        struct FCB *fcb = list_entry(e, struct FCB, elem);
        if (fcb->fd == fd) {
            file_seek(fcb->file, position);
            return;
        }
    }
}

// not sure if this is correct
unsigned tell(int fd) {
    struct thread *current_thread = thread_current();
    struct list_elem *e;
    for (e = list_begin(&current_thread->open_file_list);
         e != list_end(&current_thread->open_file_list); e = list_next(e)) {
        struct FCB *fcb = list_entry(e, struct FCB, elem);
        if (fcb->fd == fd) {
            return file_tell(fcb->file);
        }
    }

    return -1;
}

// not sure if this is correct
void close(int fd) {
    struct thread *current_thread = thread_current();
    struct list_elem *e;
    for (e = list_begin(&current_thread->open_file_list);
         e != list_end(&current_thread->open_file_list); e = list_next(e)) {
        struct FCB *fcb = list_entry(e, struct FCB, elem);
        if (fcb->fd == fd) {
            lock_acquire(&file_sys_lock);
            file_close(fcb->file);
            lock_release(&file_sys_lock);
            list_remove(&fcb->elem);
            free(fcb);
            return;
        }
    }
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user(const uint8_t *uaddr) {
    int result;
    asm("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a"(result)
        : "m"(*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte) {
    int error_code;
    asm("movl $1f, %0; movb %b2, %1; 1:"
        : "=&a"(error_code), "=m"(*udst)
        : "q"(byte));
    return error_code != -1;
}

struct FCB *get_fcb(int fd) {
    struct thread *current_thread = thread_current();
    struct list_elem *e;
    for (e = list_begin(&current_thread->open_file_list);
         e != list_end(&current_thread->open_file_list); e = list_next(e)) {
        struct FCB *fcb = list_entry(e, struct FCB, elem);
        if (fcb->fd == fd) {
            return fcb;
        }
    }

    return NULL;
}