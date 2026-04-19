#include "wrappers.hpp"

extern "C" void PostNativeInit(const char* loadedLibrary, void*) {
    if (loadedLibrary == nullptr ||
        std::strstr(loadedLibrary, fusefixer::kTargetLibrary) == nullptr) {
        return;
    }
    fusefixer::InstallFuseHooks();
}

extern "C" {

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    fusefixer::gJavaVm = vm;
    return JNI_VERSION_1_6;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_rmdir(JNIEnv* env, jclass clazz,
                                                                         jstring path) {
    (void)clazz;
    const char* c_path = env->GetStringUTFChars(path, nullptr);

    jint ret = rmdir(c_path);
    if (ret != 0)
        ret = errno;
    else
        ret = 0;
    env->ReleaseStringUTFChars(path, c_path);
    return ret;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_unlink(JNIEnv* env, jclass clazz,
                                                                          jstring path) {
    (void)clazz;
    const char* c_path = env->GetStringUTFChars(path, nullptr);

    jint ret = unlink(c_path);
    if (ret != 0)
        ret = errno;
    else
        ret = 0;
    env->ReleaseStringUTFChars(path, c_path);
    return ret;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_mkdir(JNIEnv* env, jclass clazz,
                                                                         jstring path) {
    (void)clazz;
    const char* c_path = env->GetStringUTFChars(path, nullptr);

    jint ret = mkdir(c_path, 0777);
    if (ret != 0)
        ret = errno;
    else
        ret = 0;
    env->ReleaseStringUTFChars(path, c_path);
    return ret;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_rename(JNIEnv* env, jclass clazz,
                                                                          jstring old_path,
                                                                          jstring new_path) {
    (void)clazz;
    const char* c_old_path = env->GetStringUTFChars(old_path, nullptr);
    const char* c_new_path = env->GetStringUTFChars(new_path, nullptr);

    jint ret = rename(c_old_path, c_new_path);
    if (ret != 0)
        ret = errno;
    else
        ret = 0;
    env->ReleaseStringUTFChars(old_path, c_old_path);
    env->ReleaseStringUTFChars(new_path, c_new_path);
    return ret;
}

JNIEXPORT jint JNICALL Java_io_github_xiaotong6666_fusefixer_Utils_create(JNIEnv* env, jclass clazz,
                                                                          jstring path) {
    (void)clazz;
    const char* c_path = env->GetStringUTFChars(path, nullptr);

    const int fd = open(c_path, O_CREAT | O_EXCL | O_CLOEXEC | O_RDWR, 0666);
    jint ret = 0;
    if (fd < 0) {
        ret = errno;
    } else {
        close(fd);
    }
    env->ReleaseStringUTFChars(path, c_path);
    return ret;
}

}  // extern "C"

extern "C" __attribute__((visibility("default"))) void* native_init(void* api) {
    __android_log_print(4, fusefixer::kLogTag, "Loaded");
    if (api != nullptr) {
        fusefixer::gHookInstaller =
            reinterpret_cast<const fusefixer::NativeApiEntries*>(api)->hookFunc;
    }
    return reinterpret_cast<void*>(+PostNativeInit);
}
