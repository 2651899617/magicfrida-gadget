#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <android/log.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include "zygisk.hpp"
#include "policy.hpp"
#include "sha256.hpp"
#include "payload.hpp"

struct LoadContext {
    int fd;
    NianchuTarget target;
};

static void status(const char *message)
{
    __android_log_write(ANDROID_LOG_INFO, "nianchu-gadget", message);
}

static bool verify_payload(int fd)
{
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) ||
        uint64_t(info.st_size) != NIANCHU_PAYLOAD_SIZE) return false;
    NianchuSha256 hash;
    unsigned char buffer[32768];
    off_t offset = 0;
    while (offset < info.st_size) {
        ssize_t n = pread(fd, buffer, sizeof(buffer), offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        hash.update(buffer, size_t(n));
        offset += n;
    }
    unsigned char digest[32];
    hash.finish(digest);
    return !memcmp(digest, NIANCHU_PAYLOAD_SHA256, sizeof(digest));
}

static void *load_gadget(void *opaque)
{
    LoadContext *context = static_cast<LoadContext *>(opaque);
    NianchuTarget target = context->target;
    int fd = context->fd;
    free(context);
    pthread_setname_np(pthread_self(), "nianchu-load");
    struct timespec remaining = {time_t(target.delay_ms / 1000), long(target.delay_ms % 1000) * 1000000};
    while (nanosleep(&remaining, &remaining) && errno == EINTR) {}
    if (!verify_payload(fd)) {
        close(fd);
        status("payload size/hash verification failed; no load");
        return nullptr;
    }
    android_dlextinfo info = {};
    info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    info.library_fd = fd;
    void *handle = android_dlopen_ext("libnianchu-gadget.so", RTLD_NOW | RTLD_LOCAL, &info);
    close(fd);
    if (!handle) {
        status("Gadget mapping failed; host left running");
        return nullptr;
    }
    using Init = void (*)(const char *, int *);
    Init init = reinterpret_cast<Init>(dlsym(handle, "nianchu_gadget_init"));
    if (!init) {
        status("explicit initialization entry missing; incompatible payload retained, not initialized");
        return nullptr;
    }
    char config[256];
    snprintf(config, sizeof(config),
             "{\"interaction\":{\"type\":\"listen\",\"address\":\"127.0.0.1\","
             "\"port\":%u,\"on_port_conflict\":\"fail\",\"on_load\":\"%s\"}}",
             target.port, target.wait ? "wait" : "resume");
    int result = -1;
    /* No Zygisk API/JNIEnv calls in the worker. The module stays mapped. */
    init(config, &result);
    status(result >= 0 ? "Gadget initialization returned; client/app validation still required" :
                        "Gadget initialization reported failure; no unload of potentially active code");
    return nullptr;
}

class NianchuModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *value, JNIEnv *jni) override { api = value; env = jni; }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override
    {
        if (!args || !args->nice_name || args->uid < 10000 ||
            (args->is_child_zygote && *args->is_child_zygote)) { decline(); return; }
        const char *name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!name) { decline(); return; }
        int directory = api->getModuleDir();
        NianchuTarget target = {};
        bool found = false;
        bool valid = false;
        if (directory >= 0) {
            int config = openat(directory, "targets.conf", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (config >= 0) {
                struct stat info;
                if (!fstat(config, &info) && S_ISREG(info.st_mode) && info.st_size <= 16384 && info.st_size >= 0) {
                    char text[16385];
                    size_t used = 0;
                    while (used < size_t(info.st_size)) {
                        ssize_t n = read(config, text + used, size_t(info.st_size) - used);
                        if (n < 0 && errno == EINTR) continue;
                        if (n <= 0) break;
                        used += size_t(n);
                    }
                    char extra;
                    ssize_t tail;
                    do { tail = read(config, &extra, 1); } while (tail < 0 && errno == EINTR);
                    if (used == size_t(info.st_size) && tail == 0)
                        valid = nianchu_select(text, used, unsigned(args->uid), name, &target, &found);
                }
                close(config);
            }
        }
        env->ReleaseStringUTFChars(args->nice_name, name);
        if (valid && found) {
            int fd = openat(directory, "gadget/libnianchu-gadget.so", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd >= 0) {
                pending = static_cast<LoadContext *>(calloc(1, sizeof(LoadContext)));
                if (pending && api->exemptFd(fd)) {
                    pending->fd = fd;
                    pending->target = target;
                } else {
                    close(fd);
                    free(pending);
                    pending = nullptr;
                }
            }
        }
        if (directory >= 0) close(directory);
        if (!pending) decline();
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *) override
    {
        if (!pending) return;
        LoadContext *context = pending;
        pending = nullptr;
        pthread_attr_t attributes;
        int rc = pthread_attr_init(&attributes);
        if (!rc) {
            rc = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
            if (!rc) {
                pthread_t thread;
                rc = pthread_create(&thread, &attributes, load_gadget, context);
            }
            pthread_attr_destroy(&attributes);
        }
        if (rc) {
            close(context->fd);
            free(context);
            status("loader thread creation failed; no synchronous fallback");
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *) override { decline(); }

private:
    void decline() { api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY); }
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    LoadContext *pending = nullptr;
};

REGISTER_ZYGISK_MODULE(NianchuModule)
