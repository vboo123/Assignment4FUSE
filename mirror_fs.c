/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    gcc -Wall `pkg-config fuse --cflags --libs` mirror_fs.c -o mirror_fs -lcrypto
*/

#define FUSE_USE_VERSION 26

#define PATH_MAX 4096
static char mirror_dir[PATH_MAX]; // stores path to actual mirrored source dir

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define KEY_LEN 32
#define IV_LEN 16
static unsigned char key[KEY_LEN];

// this helper function redirects paths to the actual source directory
static void full_path(char fpath[PATH_MAX], const char *path) {
    snprintf(fpath, PATH_MAX, "%s%s", mirror_dir, path);
}

// helper function to securely read a passphrase
static void get_passphrase(char *buf, size_t size) {
    struct termios oldt, newt;
    printf("Enter encryption passphrase: ");
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    fgets(buf, size, stdin);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
    buf[strcspn(buf, "\n")] = 0; // remove newline
}

// derive AES-256 key from passphrase using PBKDF2
static void derive_key(const char *passphrase) {
    unsigned char salt[8] = {0};
    PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), salt, sizeof(salt), 10000, KEY_LEN, key);
}

// encrypt buffer using AES-256-CBC
int encrypt_data(const char *in, size_t in_len, unsigned char *out, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len1, out_len2;
    RAND_bytes(iv, IV_LEN);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, out, &out_len1, (unsigned char *)in, in_len);
    EVP_EncryptFinal_ex(ctx, out + out_len1, &out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return out_len1 + out_len2;
}

// decrypt buffer using AES-256-CBC
int decrypt_data(const unsigned char *in, size_t in_len, char *out, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len1, out_len2;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, (unsigned char *)out, &out_len1, in, in_len);
    EVP_DecryptFinal_ex(ctx, (unsigned char *)out + out_len1, &out_len2);
    EVP_CIPHER_CTX_free(ctx);
    return out_len1 + out_len2;
}

// FUSE operation implementations follow
static int xmp_getattr(const char *path, struct stat *stbuf) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = lstat(fpath, stbuf);
    return res == -1 ? -errno : 0;
}

static int xmp_access(const char *path, int mask) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = access(fpath, mask);
    return res == -1 ? -errno : 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = readlink(fpath, buf, size - 1);
    if (res == -1) return -errno;
    buf[res] = '\0';
    return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    DIR *dp = opendir(fpath);
    if (!dp) return -errno;
    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0)) break;
    }
    closedir(dp);
    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res;
    if (S_ISREG(mode)) {
        res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0) res = close(res);
    } else if (S_ISFIFO(mode)) {
        res = mkfifo(fpath, mode);
    } else {
        res = mknod(fpath, mode, rdev);
    }
    return res == -1 ? -errno : 0;
}

static int xmp_mkdir(const char *path, mode_t mode) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = mkdir(fpath, mode);
    return res == -1 ? -errno : 0;
}

static int xmp_unlink(const char *path) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = unlink(fpath);
    return res == -1 ? -errno : 0;
}

static int xmp_rmdir(const char *path) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = rmdir(fpath);
    return res == -1 ? -errno : 0;
}

static int xmp_symlink(const char *from, const char *to) {
    char ffrom[PATH_MAX], fto[PATH_MAX];
    full_path(ffrom, from);
    full_path(fto, to);
    int res = symlink(ffrom, fto);
    return res == -1 ? -errno : 0;
}

static int xmp_rename(const char *from, const char *to) {
    char ffrom[PATH_MAX], fto[PATH_MAX];
    full_path(ffrom, from);
    full_path(fto, to);
    int res = rename(ffrom, fto);
    return res == -1 ? -errno : 0;
}

static int xmp_link(const char *from, const char *to) {
    char ffrom[PATH_MAX], fto[PATH_MAX];
    full_path(ffrom, from);
    full_path(fto, to);
    int res = link(ffrom, fto);
    return res == -1 ? -errno : 0;
}

static int xmp_chmod(const char *path, mode_t mode) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = chmod(fpath, mode);
    return res == -1 ? -errno : 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = lchown(fpath, uid, gid);
    return res == -1 ? -errno : 0;
}

static int xmp_truncate(const char *path, off_t size) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = truncate(fpath, size);
    return res == -1 ? -errno : 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2]) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    struct timeval tv[2];
    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;
    int res = utimes(fpath, tv);
    return res == -1 ? -errno : 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = open(fpath, fi->flags);
    if (res == -1) return -errno;
    close(res);
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int fd = open(fpath, O_RDONLY);
    if (fd == -1) return -errno;
    unsigned char enc_buf[8192];
    int read_bytes = pread(fd, enc_buf, sizeof(enc_buf), 0);
    close(fd);
    if (read_bytes <= IV_LEN) return 0;
    unsigned char *iv = enc_buf;
    unsigned char *enc_data = enc_buf + IV_LEN;
    int dec_len = decrypt_data(enc_data, read_bytes - IV_LEN, buf, iv);
    return dec_len;
}

static int xmp_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    unsigned char iv[IV_LEN];
    unsigned char enc_buf[8192];
    int enc_len = encrypt_data(buf, size, enc_buf + IV_LEN, iv);
    memcpy(enc_buf, iv, IV_LEN);
    int fd = open(fpath, O_WRONLY | O_CREAT, 0644);
    if (fd == -1) return -errno;
    int res = pwrite(fd, enc_buf, enc_len + IV_LEN, offset);
    if (res == -1) res = -errno;
    close(fd);
    return res - IV_LEN;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = statvfs(fpath, stbuf);
    return res == -1 ? -errno : 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi) {
    (void) path;
    (void) fi;
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync, struct fuse_file_info *fi) {
    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value, size_t size, int flags) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = lsetxattr(fpath, name, value, size, flags);
    return res == -1 ? -errno : 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value, size_t size) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = lgetxattr(fpath, name, value, size);
    return res == -1 ? -errno : res;
}

static int xmp_listxattr(const char *path, char *list, size_t size) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = llistxattr(fpath, list, size);
    return res == -1 ? -errno : res;
}

static int xmp_removexattr(const char *path, const char *name) {
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = lremovexattr(fpath, name);
    return res == -1 ? -errno : 0;
}
#endif

// This struct tells FUSE which function to call 
// This is how file system responds to user commands like 
// ls, cat, touch, rm, etc..
static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,
    .access     = xmp_access,
    .readlink   = xmp_readlink,
    .readdir    = xmp_readdir,
    .mknod      = xmp_mknod,
    .mkdir      = xmp_mkdir,
    .symlink    = xmp_symlink,
    .unlink     = xmp_unlink,
    .rmdir      = xmp_rmdir,
    .rename     = xmp_rename,
    .link       = xmp_link,
    .chmod      = xmp_chmod,
    .chown      = xmp_chown,
    .truncate   = xmp_truncate,
    .utimens    = xmp_utimens,
    .open       = xmp_open,
    .read       = xmp_read,
    .write      = xmp_write,
    .statfs     = xmp_statfs,
    .release    = xmp_release,
    .fsync      = xmp_fsync,
#ifdef HAVE_SETXATTR
    .setxattr   = xmp_setxattr,
    .getxattr   = xmp_getxattr,
    .listxattr  = xmp_listxattr,
    .removexattr= xmp_removexattr,
#endif
};

// main accepts a mirror_dir and mountpoint, sets up the mirror_dir path
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <mountpoint> <mirror_dir>\n", argv[0]);
        exit(1);
    }

    char passphrase[256];
    get_passphrase(passphrase, sizeof(passphrase));
    derive_key(passphrase);

    realpath(argv[argc - 1], mirror_dir);  // save full mirror path
    argv[argc - 1] = NULL; // remove mirror_dir from FUSE args
    argc--;

    // this ensures that all files created by file system retain permissions 
    // that are set by user
    umask(0);

    // starts fuse main loop, which mounts file system, intercepts sys calls,
    // and routes them to xmp_oper
    return fuse_main(argc, argv, &xmp_oper, NULL);
}