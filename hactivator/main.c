#include <CoreFoundation/CoreFoundation.h>
#include <sys/sysctl.h>
#include <stdbool.h>
#include <strings.h>
#include <syslog.h>
#include <dlfcn.h>

#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
            __attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

/* XXX doesn't seem to go anywhere */
#define LOG(__fmt, ...) \
    // syslog(0, __fmt, ##__VA_ARGS__);

static
bool hactivation_enabled = false;

__attribute__((constructor))
void start(void) {
    char boot_args[512] = { 0 };
    size_t boot_args_len = sizeof(boot_args) - 1;

    int ret = sysctlbyname("kern.bootargs", boot_args, &boot_args_len, NULL, 0);
    if (ret != 0) {
        LOG("failed to query boot-args, not Hactivating!");
        return;
    }

    hactivation_enabled = strstr(boot_args, "-hactivate") != NULL;
    if (!hactivation_enabled) {
        LOG("NOT doing Hactivation");
        return;
    }

    LOG("doing Hactivation!");
}

extern
CFTypeRef MGCopyAnswer(CFStringRef question, CFDictionaryRef options);

CFTypeRef OUR_MGCopyAnswer(CFStringRef question, CFDictionaryRef options) {
    if (!hactivation_enabled) {
        goto orig;
    }

    if (CFStringCompare(question, CFSTR("ShouldHactivate"), 0) != kCFCompareEqualTo) {
        goto orig;
    }

    LOG("hit Hactivation hook!")

    return kCFBooleanTrue;

orig:
    return MGCopyAnswer(question, options);
}

DYLD_INTERPOSE(OUR_MGCopyAnswer, MGCopyAnswer)
