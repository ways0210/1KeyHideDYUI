// 作者：pxx917144686
// 日期：2025-04-15
// 绕过网络授权弹窗、服务器验证和闪退机制

#include <Foundation/Foundation.h>
#include <UIKit/UIKit.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <Security/Security.h>
#include <sys/syscall.h>
#include <pthread.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// 函数指针 - 覆盖更多关键验证函数
static struct {
    void *sub_5A8D1C;  // 路径解析函数
    void *sub_10B934;  // 校验函数
    void *sub_10C7BC;  // 校验函数
    void *sub_10B65C;  // 校验函数
    void *sub_55AC80;  // 状态管理函数
    void *sub_59E770;  // 状态管理函数
    void *sub_10E69C;  // 动态校验函数
    void *sub_10F07C;  // 路径验证函数
    void *sub_10C930;  // 网络解析函数
    void *sub_10EE44;  // 内存校验函数
    void *sub_10E8B8;  // 信号生成函数
    void *stat;        // 文件状态查询
    void *socket;      // 网络套接字创建
    void *send;        // 网络数据发送
    void *recv;        // 网络数据接收
    void *connect;     // 网络连接
    void *getaddrinfo; // DNS解析
    void *vm_protect;  // 内存保护
    void *exit;        // 程序退出
    void *abort;       // 程序中止
    void *objc_msgSend;// Objective-C消息发送
    void *ssl_handshake;// SSL握手
    void *ssl_copy_alpn;// SSL协议协商
    void *ssl_get_cipher;// SSL密码套件
    void *sec_trust_evaluate;// 证书信任评估
    void *sec_trust_copy_key;// 证书公钥获取
    void *cc_sha256;   // SHA256哈希
    void *dispatch_async;// 异步任务调度
    void *dispatch_after;// 延迟任务调度
    void *dispatch_source_create;// 定时器源创建
    void *dispatch_queue_create;// 队列创建
    void *dispatch_source_set_timer;// 定时器设置
    void *pthread_create;// 线程创建
    void *kill;        // 进程终止信号
    void *raise;       // 信号触发
    void *pthread_kill;// 线程终止信号
    void *syscall;     // 系统调用
    void *mach_task_self;// 任务端口获取
} cached_addrs = {0};

// 原始函数指针
static void (*orig_showAlert)(id, SEL, NSString *, NSString *, id) = NULL;
static void (*orig_presentViewController)(id, SEL, id, BOOL, id) = NULL;
static void (*orig_initPresentation)(id, SEL, id, id) = NULL;
static void (*orig_showNotification)(id, SEL, NSString *, NSString *, id, id) = NULL;
static void (*orig_dismissTimerFired)(id, SEL, id) = NULL;
static id (*orig_post)(id, SEL, NSString *, id, id, id, id) = NULL;
static id (*orig_get)(id, SEL, NSString *, id, id, id, id) = NULL;
static BOOL (*orig_evaluateServerTrust)(id, SEL, void *, NSString *) = NULL;
static BOOL (*orig_isReachable)(id, SEL) = NULL;
static void (*orig_sessionDidBecomeInvalid)(id, SEL, id, id) = NULL;
static void (*orig_validateSession)(id, SEL, id) = NULL;
static void (*orig_checkLicense)(id, SEL, NSString *) = NULL;
static void (*orig_popupViewShow)(id, SEL) = NULL;
static void (*orig_popupViewPresent)(id, SEL, id, BOOL, id) = NULL;
static void (*orig_popupViewDisplay)(id, SEL, id) = NULL;
static void (*orig_addSubview)(id, SEL, id) = NULL;
static void (*orig_validateData)(id, SEL, id, id) = NULL;
static BOOL (*orig_checkAuthStatus)(id, SEL, NSString *) = NULL;
static int64_t (*orig_sub_5A8D1C)(void *, void *, void *) = NULL;
static int64_t (*orig_sub_10B934)(void *, void *) = NULL;
static int64_t (*orig_sub_10C7BC)(void *, void *) = NULL;
static int64_t (*orig_sub_10B65C)(void *, void *) = NULL;
static int64_t (*orig_sub_55AC80)(void *, void *) = NULL;
static int64_t (*orig_sub_59E770)(void *, void *) = NULL;
static int64_t (*orig_sub_10E69C)(void *, void *) = NULL;  // 动态校验函数
static int64_t (*orig_sub_10F07C)(void *, void *) = NULL;  // 路径验证函数
static int64_t (*orig_sub_10C930)(void *, void *) = NULL;  // 网络解析函数
static int64_t (*orig_sub_10EE44)(void *, void *) = NULL;  // 内存校验函数
static int64_t (*orig_sub_10E8B8)(void *, void *) = NULL;  // 信号生成函数
static int (*orig_stat)(const char *, struct stat *) = NULL;
static int (*orig_socket)(int, int, int) = NULL;
static ssize_t (*orig_send)(int, const void *, size_t, int) = NULL;
static ssize_t (*orig_recv)(int, void *, size_t, int) = NULL;
static int (*orig_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*orig_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = NULL;
static kern_return_t (*orig_vm_protect)(vm_map_t, vm_address_t, vm_size_t, boolean_t, vm_prot_t) = NULL;
static void (*orig_exit)(int) = NULL;
static void (*orig_abort)(void) = NULL;
static void *(*orig_objc_msgSend)(id, SEL, ...) = NULL;
static OSStatus (*orig_SSLHandshake)(void *) = NULL;
static OSStatus (*orig_SSLCopyALPNProtocols)(void *, CFArrayRef *) = NULL;
static OSStatus (*orig_SSLGetNegotiatedCipher)(void *, SSLCipherSuite *) = NULL;
static OSStatus (*orig_SecTrustEvaluateWithError)(SecTrustRef, CFErrorRef *) = NULL;
static SecKeyRef (*orig_SecTrustCopyPublicKey)(SecTrustRef) = NULL;
static void (*orig_cc_sha256)(const void *, CC_LONG, unsigned char *) = NULL;
static void (*orig_dispatch_async)(dispatch_queue_t, void (^)(void)) = NULL;
static void (*orig_dispatch_after)(dispatch_time_t, dispatch_queue_t, void (^)(void)) = NULL;
static dispatch_source_t (*orig_dispatch_source_create)(dispatch_source_type_t, uintptr_t, unsigned long, dispatch_queue_t) = NULL;
static dispatch_queue_t (*orig_dispatch_queue_create)(const char *, dispatch_queue_attr_t) = NULL;
static void (*orig_dispatch_source_set_timer)(dispatch_source_t, dispatch_time_t, uint64_t, uint64_t) = NULL;
static int (*orig_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = NULL;
static int (*orig_kill)(pid_t, int) = NULL;
static int (*orig_raise)(int) = NULL;
static int (*orig_pthread_kill)(pthread_t, int) = NULL;
static int (*orig_syscall)(int, ...) = NULL;
static mach_port_t (*orig_mach_task_self)(void) = NULL;

// 验证状态标志 - 用于标记授权验证是否已通过
static volatile bool validation_passed = false;

// 获取ASLR偏移量 - 用于计算运行时的实际内存地址
static uintptr_t get_aslr_slide(void) {
    return _dyld_get_image_vmaddr_slide(0);
}

// 获取指定段的内存范围 - 用于定位特定代码段
static bool get_section(const char *segname, uintptr_t *start, size_t *size) {
    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!header) return false;

    struct load_command *cmd = (struct load_command *)((uintptr_t)header + sizeof(struct mach_header_64));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)cmd;
            if (strncmp(seg->segname, segname, 16) == 0) {
                *start = seg->vmaddr + get_aslr_slide();
                *size = seg->vmsize;
                return true;
            }
        }
        cmd = (struct load_command *)((uintptr_t)cmd + cmd->cmdsize);
    }
    return false;
}

// 修补内存 - 用于直接修改内存中的代码或数据
static bool patch_memory(void *addr, const void *data, size_t len) {
    if (!addr || !data || (uintptr_t)addr % 8 != 0) return false;
    void *page = (void *)((uintptr_t)addr & ~0xFFF);
    if (mprotect(page, 0x1000, PROT_READ | PROT_WRITE) != 0) return false;
    memcpy(addr, data, len);
    if (mprotect(page, 0x1000, PROT_READ | PROT_EXEC) != 0) return false;
    sys_icache_invalidate(addr, len);
    return true;
}

// 修补验证表 - 动态扫描所有高位哈希，覆盖更多DCB/DCD
static void patch_validation_table(uintptr_t start, size_t size) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256("validation_success_2025", 22, digest);
    uint32_t dynamic_hash = *(uint32_t *)digest;

    // 扩展的DCD值列表 - 覆盖更多动态校验点
    uint32_t dcd_values[] = {
        0x2ad87b69, 0xadb223c6, 0x86ff6bc6, 0xe4c60000, 0xbcc60000, 0xba90c69d, 0xf436610e,
        0x4510, 0x4520, 0x45ac, 0x45d0, 0x4654, 0x46b8, 0x47a0, 0x47cc,
        0x6aff6e, 0x740da8, 0x740f78, 0x740f98, 0x60, 0x740fe0, 0x6aff48, 0x741080,
        0x57928345, 0xfa606938, 0x0fb840d7, 0x86440ead, 0x95c5a710, 0x4715fa8d,
        0xf2f15757, 0x7d077b23, 0x6053c3aa, 0xdd4f9097, 0xf38394fc, 0xabd2f288,
        0x72a61265, 0x65a08dda, 0xb171bef1, 0xd44de1e9,
        0x7CA0A290, 0xE784CEF5, 0xAC2D70FF, 0xF5CA41EB, 0x48714403, 0x2E51C8D2,
        0xB7B80ADE, 0x5978CE9E, 0xEA4BF35A, 0xA320B67C, 0x28DDC703, 0xC1FF2398
    };
    // 扩展的DCB地址 - 覆盖更多动态校验点
    uintptr_t dcb_addrs[] = {
        0x7571ec, 0x75727c, 0x7576fc, 0x757e9c, 0x757eac, 0x7599e8, 0x75a720, 0x75c12c,
        0x75c78c, 0x75c7ac, 0x75c7cc, 0x75c7ec, 0x75c80c, 0x75c84c, 0x75c86c, 0x75c93c,
        0x75c94c, 0x75c95c, 0x75dc44, 0x75dc64, 0x75ed58, 0x75f25c, 0x75f82c, 0x761880,
        0x761f4c, 0x767188, 0x7678ec, 0x767d28, 0x768ca0, 0x7694ec, 0x76c7ac, 0x76ce7c,
        0x77992C, 0x77993C, 0x779964, 0x779C04, 0x779C1C
    };

    // 修补DCB序列 - 替换原始验证数据
    for (size_t i = 0; i < sizeof(dcb_addrs) / sizeof(dcb_addrs[0]); i++) {
        uint8_t new_dcb[8];
        memcpy(new_dcb, digest, sizeof(new_dcb));
        patch_memory((void *)(start + (dcb_addrs[i] - 0x755f30)), new_dcb, sizeof(new_dcb));
    }

    // 修补DCD值 - 替换验证哈希值
    for (size_t i = 0; i < sizeof(dcd_values) / sizeof(dcd_values[0]); i++) {
        for (uintptr_t addr = start; addr < start + size - 4; addr += 4) {
            uint32_t *ptr = (uint32_t *)addr;
            if (*ptr == dcd_values[i] || (*ptr ^ dynamic_hash) == dcd_values[i]) {
                patch_memory(ptr, &dynamic_hash, sizeof(uint32_t));
            }
        }
    }

    // 动态修补高位哈希 - 全面扫描，替换所有潜在校验值
    for (uintptr_t addr = start; addr < start + size - 4; addr += 4) {
        uint32_t *ptr = (uint32_t *)addr;
        if (*ptr > 0x1000000 || (*ptr & 0x80000000)) {
            uint32_t random_hash = arc4random();
            patch_memory(ptr, &random_hash, sizeof(uint32_t));
        }
    }
}

// 修补完整性检查代码 - 扩展栈保护和签名校验
static void patch_integrity_checks(void) {
    uintptr_t data_start, data_size;
    if (get_section("____j_M__c___T__", &data_start, &data_size)) {
        uint32_t fake_guard = 0xDEADBEEF;
        // 扩展栈保护地址 - 覆盖更多潜在校验点
        uintptr_t stack_guard_addrs[] = {
            0x7571ec, 0x75727c, 0x7576fc, 0x757e9c, 0x757eac, 0x7599e8, 0x75a720, 0x75c12c,
            0x75c78c, 0x75c7ac, 0x75c7cc, 0x75c7ec, 0x75c80c, 0x75c84c, 0x75c86c, 0x75c93c,
            0x7f6440, 0x7f6450, 0x7f6460, 0x7f6470, 0x7f6480, 0x7f6490, 0x8c25c8, 0x8c25d8,
            0x77992C, 0x77993C, 0x779964, 0x779C04, 0x779C1C
        };
        for (size_t i = 0; i < sizeof(stack_guard_addrs) / sizeof(stack_guard_addrs[0]); i++) {
            patch_memory((void *)(data_start + (stack_guard_addrs[i] - 0x755f30)), &fake_guard, sizeof(fake_guard));
        }

        // 动态扫描栈保护 - 覆盖更多异常值
        for (uintptr_t addr = data_start; addr < data_start + data_size - 4; addr += 4) {
            uint32_t *ptr = (uint32_t *)addr;
            if (*ptr == 0x0 || (*ptr & 0xFFFF0000) == 0xCAFE0000 || (*ptr & 0xFFFF0000) == 0xDEAD0000) {
                patch_memory((void *)addr, &fake_guard, sizeof(fake_guard));
            }
        }
    }

    uintptr_t linkedit_start, linkedit_size;
    if (get_section("__LINKEDIT_hidden", &linkedit_start, &linkedit_size)) {
        // 扩展签名校验地址 - 覆盖更多潜在签名点
        uintptr_t signature_addrs[] = {
            0x8e8ae0, 0x8e9214, 0x8e42c, 0x8e444, 0x8e460,
            0x8e5000, 0x8e5100, 0x8e5200, 0x8e5300 
        };
        uint32_t fake_signature = 0xDEADBEEF;
        for (size_t i = 0; i < sizeof(signature_addrs) / sizeof(signature_addrs[0]); i++) {
            patch_memory((void *)(linkedit_start + (signature_addrs[i] - 0x8e0000)), &fake_signature, sizeof(fake_signature));
        }
    }
}

// 修补跳转表 - 扩展跳转表覆盖范围，禁用动态跳转
static void patch_jump_tables(void) {
    uintptr_t jump_start, jump_size;
    if (get_section("_a_______d______", &jump_start, &jump_size)) {
        // 扩展跳转表地址 - 覆盖更多潜在跳转点
        uintptr_t jump_table_addrs[] = {
            0x5d9bb4, 0x5d9bbc, 0x5d9bc2, 0x5d9c10, 0x5d9c17, 0x5d9c1d, 0x5d9c4c, 0x5da010,
            0x5da018, 0x5da039, 0x5da0d8, 0x5da0dc, 0x5da0f0, 0x5da100, 0x5da110, 0x5da116,
            0x5da200, 0x5da210, 0x5da220, 0x5da230, 0x5da240, 0x5da250, 0x5da260, 0x5da270
        };
        uint32_t nop = 0xD503201F;
        for (size_t i = 0; i < sizeof(jump_table_addrs) / sizeof(jump_table_addrs[0]); i++) {
            patch_memory((void *)(jump_start + (jump_table_addrs[i] - 0x5d7500)), &nop, sizeof(nop));
        }
    }
}

// 修补退出调用 - 覆盖间接调用和动态终止逻辑
static void patch_exit_calls(uintptr_t start, size_t size) {
    uint32_t bl_exit = 0x94000000;
    uint32_t nop = 0xD503201F;
    for (uintptr_t addr = start; addr < start + size - 4; addr += 4) {
        uint32_t *instr = (uint32_t *)addr;
        // 检查BL指令
        if ((*instr & 0xFC000000) == bl_exit) {
            ptrdiff_t offset = (*instr & 0x3FFFFFF) << 2;
            if (offset & 0x8000000) offset |= ~0xFFFFFFF;
            uintptr_t target = addr + offset;
            if (target == (uintptr_t)cached_addrs.exit ||
                target == (uintptr_t)cached_addrs.abort ||
                target == (uintptr_t)cached_addrs.kill ||
                target == (uintptr_t)cached_addrs.raise ||
                target == (uintptr_t)cached_addrs.pthread_kill ||
                target == (uintptr_t)cached_addrs.syscall) {
                patch_memory((void *)addr, &nop, sizeof(nop));
            }
        }
    }
}

// 生成签名 - 为伪造的服务器响应创建签名
static NSString *generate_signature(NSDictionary *data) {
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:data options:0 error:nil];
    const char *secret = "libroot_server_secret_2025";
    unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, secret, strlen(secret), jsonData.bytes, jsonData.length, hmac);
    NSMutableString *sig = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [sig appendFormat:@"%02x", hmac[i]];
    }
    return sig;
}

// 生成随机字符串 - 用于创建唯一的随机值
static NSString *generate_nonce(void) {
    uint8_t bytes[16];
    arc4random_buf(bytes, 16);
    NSMutableString *nonce = [NSMutableString stringWithCapacity:32];
    for (int i = 0; i < 16; i++) {
        [nonce appendFormat:@"%02x", bytes[i]];
    }
    return nonce;
}

// hook ObjC方法 - 替换目标类的方法实现
static void hook_method(Class cls, SEL selector, IMP new_imp, IMP *orig_imp) {
    if (!cls) return;
    Method method = class_getInstanceMethod(cls, selector);
    if (!method) return;
    *orig_imp = method_getImplementation(method);
    method_setImplementation(method, new_imp);
}

// C函数 - 通过跳转指令替换原始函数
static void patch_c_function(void *orig_addr, void *new_func) {
    if (!orig_addr || !new_func || (uintptr_t)orig_addr % 4 != 0 || (uintptr_t)new_func % 4 != 0) return;
    ptrdiff_t offset = ((ptrdiff_t)new_func - (ptrdiff_t)orig_addr) >> 2;
    if (offset > 0x1FFFFFF || offset < -0x1FFFFFF) return;
    uint32_t jump_instr[2] = {
        0x14000000 | (offset & 0x3FFFFFF),
        0xD503201F
    };
    patch_memory(orig_addr, jump_instr, sizeof(jump_instr));
}

// 弹窗显示函数 - 拦截警告弹窗显示
static void hooked_showAlert(id self, SEL _cmd, NSString *title, NSString *message, id completion) {
    validation_passed = true;
    if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
            ((void (^)(void))completion)();
        });
    }
}

// 视图控制器展示函数 - 拦截授权提示窗口
static void hooked_presentViewController(id self, SEL _cmd, id viewController, BOOL animated, id completion) {
    NSString *className = NSStringFromClass([viewController class]);
    if ([className containsString:@"Alert"] || [className containsString:@"Notification"] ||
        [className containsString:@"Presentation"] || [className containsString:@"IESECPopupView"] ||
        [className containsString:@"CustomAlert"]) {
        validation_passed = true;
        if (completion) {
            dispatch_async(dispatch_get_main_queue(), ^{
                ((void (^)(void))completion)();
            });
        }
        return;
    }
    if (orig_presentViewController) {
        orig_presentViewController(self, _cmd, viewController, animated, completion);
    }
}

// 展示初始化函数 - 拦截弹窗初始化过程
static void hooked_initPresentation(id self, SEL _cmd, id presented, id presenting) {
    validation_passed = true;
    if (orig_initPresentation) {
        orig_initPresentation(self, _cmd, presented, presenting);
    }
}

// 通知显示函数 - 拦截授权通知
static void hooked_showNotification(id self, SEL _cmd, NSString *title, NSString *subtitle, id style, id completion) {
    validation_passed = true;
    if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
            ((void (^)(void))completion)();
        });
    }
}

// 定时器触发函数 - 防止定时弹窗
static void hooked_dismissTimerFired(id self, SEL _cmd, id timer) {
    // 直接忽略定时器触发
}

// 弹窗显示函数 - 拦截自定义弹窗
static void hooked_popupViewShow(id self, SEL _cmd) {
    validation_passed = true;
}

// 弹窗展示函数 - 拦截弹窗展示
static void hooked_popupViewPresent(id self, SEL _cmd, id viewController, BOOL animated, id completion) {
    validation_passed = true;
    if (completion) {
        dispatch_async(dispatch_get_main_queue(), ^{
            ((void (^)(void))completion)();
        });
    }
}

// 弹窗显示函数 - 拦截弹窗显示过程
static void hooked_popupViewDisplay(id self, SEL _cmd, id context) {
    validation_passed = true;
}

// 添加子视图函数 - 拦截授权提示视图
static void hooked_addSubview(id self, SEL _cmd, id subview) {
    NSString *className = NSStringFromClass([subview class]);
    if ([className isEqualToString:@"IESECPopupView"] || [className isEqualToString:@"IESECAlertCustomView"] ||
        [className containsString:@"Alert"]) {
        validation_passed = true;
        return;
    }
    if (orig_addSubview) {
        orig_addSubview(self, _cmd, subview);
    }
}

// 数据验证函数 - 模拟数据验证通过
static void hooked_validateData(id self, SEL _cmd, id data, id context) {
    validation_passed = true;
    // 模拟验证通过
}

// 授权状态检查函数 - 始终返回已授权状态
static BOOL hooked_checkAuthStatus(id self, SEL _cmd, NSString *key) {
    validation_passed = true;
    return YES;
}

// POST请求函数
static id hooked_post(id self, SEL _cmd, NSString *path, id params, id progress, id success, id failure) {
    NSDictionary *result = @{
        @"valid": @YES,
        @"expires_in": @(time(NULL) + 86400 * 30),  // 授权30天
        @"license_key": [NSString stringWithFormat:@"%08x%08x", arc4random(), arc4random()],
        @"timestamp": @(time(NULL)),
        @"nonce": generate_nonce(),
        @"session_id": [[NSUUID UUID] UUIDString],
        @"metadata": @{@"version": @"1.0", @"device": @"iOS"},
        @"server_timestamp": @(time(NULL)),
        @"device_id": [[UIDevice currentDevice] identifierForVendor].UUIDString,
        @"license_version": @"2.1",
        @"challenge": generate_nonce(),
        @"extra_field": @"server_specific_2025",
        @"token": generate_nonce()  // 动态生成token
    };
    NSDictionary *fakeResponse = @{
        @"status": @"success",
        @"result": result,
        @"signature": generate_signature(result)
    };
    validation_passed = true;
    if (success) {
        dispatch_async(dispatch_get_main_queue(), ^{
            ((void (^)(id, id))success)(nil, fakeResponse);
        });
    }
    return nil;
}

// GET请求函数
static id hooked_get(id self, SEL _cmd, NSString *path, id params, id progress, id success, id failure) {
    NSDictionary *result = @{
        @"valid": @YES,
        @"expires_in": @(time(NULL) + 86400 * 30),  // 授权30天
        @"license_key": [NSString stringWithFormat:@"%08x%08x", arc4random(), arc4random()],
        @"timestamp": @(time(NULL)),
        @"nonce": generate_nonce(),
        @"session_id": [[NSUUID UUID] UUIDString],
        @"metadata": @{@"version": @"1.0", @"device": @"iOS"},
        @"server_timestamp": @(time(NULL)),
        @"device_id": [[UIDevice currentDevice] identifierForVendor].UUIDString,
        @"license_version": @"2.1",
        @"challenge": generate_nonce(),
        @"extra_field": @"server_specific_2025",
        @"token": generate_nonce()  // 动态生成token
    };
    NSDictionary *fakeResponse = @{
        @"status": @"success",
        @"result": result,
        @"signature": generate_signature(result)
    };
    validation_passed = true;
    if (success) {
        dispatch_async(dispatch_get_main_queue(), ^{
            ((void (^)(id, id))success)(nil, fakeResponse);
        });
    }
    return nil;
}

// 服务器证书验证函数 - 绕过SSL证书验证
static BOOL hooked_evaluateServerTrust(id self, SEL _cmd, void *trust, NSString *domain) {
    validation_passed = true;
    return YES;
}

// 网络可达性检查函数 - 始终返回网络可用状态
static BOOL hooked_isReachable(id self, SEL _cmd) {
    return YES;
}

// 会话失效处理函数 - 忽略会话失效
static void hooked_sessionDidBecomeInvalid(id self, SEL _cmd, id session, id error) {
    // 忽略会话失效
}

// 会话验证函数 - 模拟验证通过
static void hooked_validateSession(id self, SEL _cmd, id session) {
    validation_passed = true;
}

// 许可证检查函数 - 模拟许可证有效
static void hooked_checkLicense(id self, SEL _cmd, NSString *license) {
    validation_passed = true;
}

// 内部验证函数 - 返回成功状态
static int64_t hooked_sub_5A8D1C(void *arg0, void *arg1, void *arg2) {
    validation_passed = true;
    return 0;
}

// 内部验证函数 - 返回成功状态
static int64_t hooked_sub_10B934(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 内部验证函数 - 返回成功状态
static int64_t hooked_sub_10C7BC(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 内部验证函数 - 返回成功状态
static int64_t hooked_sub_10B65C(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 内部验证函数 - 返回成功状态
static int64_t hooked_sub_55AC80(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 内部验证函数 - 返回成功状态
static int64_t hooked_sub_59E770(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 动态校验函数 - 防止未处理的验证逻辑
static int64_t hooked_sub_10E69C(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 路径验证函数 - 防止路径校验失败
static int64_t hooked_sub_10F07C(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 网络解析函数 - 防止网络响应验证失败
static int64_t hooked_sub_10C930(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 内存校验函数 - 防止内存完整性检查
static int64_t hooked_sub_10EE44(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// 信号生成函数 - 防止信号触发闪退
static int64_t hooked_sub_10E8B8(void *arg0, void *arg1) {
    validation_passed = true;
    return 0;
}

// stat函数 - 伪造更多越狱路径和动态元数据
static int hooked_stat(const char *path, struct stat *buf) {
    if (path && (strstr(path, "/var/jb") || strstr(path, "/Library/MobileSubstrate") ||
                 strstr(path, "/usr/libexec") || strstr(path, "/bin") ||
                 strstr(path, "/etc") || strstr(path, "/apt") ||
                 strstr(path, "/usr/bin") || strstr(path, "/usr/sbin"))) {
        if (buf) {
            buf->st_mode = S_IFDIR | 0755;
            buf->st_size = 4096;
            buf->st_mtime = time(NULL);
            buf->st_ino = arc4random();
            buf->st_nlink = 2;
            buf->st_uid = 0;
            buf->st_gid = 0;
        }
        return 0;
    }
    return orig_stat ? orig_stat(path, buf) : stat(path, buf);
}

// socket函数 - 确保网络连接成功
static int hooked_socket(int domain, int type, int protocol) {
    return orig_socket ? orig_socket(domain, type, protocol) : socket(AF_INET, SOCK_STREAM, 0);
}

// send函数 - 伪造数据发送成功
static ssize_t hooked_send(int sockfd, const void *buf, size_t len, int flags) {
    return len;
}

// recv函数 - 动态生成完整的服务器响应
static ssize_t hooked_recv(int sockfd, void *buf, size_t len, int flags) {
    NSDictionary *result = @{
        @"valid": @YES,
        @"expires_in": @(time(NULL) + 86400 * 30),
        @"license_key": [NSString stringWithFormat:@"%08x%08x", arc4random(), arc4random()],
        @"timestamp": @(time(NULL)),
        @"nonce": generate_nonce(),
        @"session_id": [[NSUUID UUID] UUIDString],
        @"metadata": @{@"version": @"1.0", @"device": @"iOS"},
        @"server_timestamp": @(time(NULL)),
        @"device_id": [[UIDevice currentDevice] identifierForVendor].UUIDString,
        @"license_version": @"2.1",
        @"challenge": generate_nonce(),
        @"extra_field": @"server_specific_2025",
        @"token": generate_nonce()
    };
    NSDictionary *fake_response = @{
        @"status": @"success",
        @"result": result,
        @"signature": generate_signature(result)
    };
    NSString *json_str = [[NSString alloc] initWithData:
        [NSJSONSerialization dataWithJSONObject:fake_response options:0 error:nil]
        encoding:NSUTF8StringEncoding];
    size_t copy_len = MIN(len, json_str.length);
    strncpy(buf, json_str.UTF8String, copy_len);
    validation_passed = true;
    return copy_len;
}

// connect函数 - 伪造连接成功
static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    return 0;
}

// getaddrinfo函数 - 伪造DNS解析成功
static int hooked_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    return 0;
}

// SSL握手函数 - 伪造握手成功
static OSStatus hooked_SSLHandshake(void *context) {
    validation_passed = true;
    return noErr;
}

// SSL ALPN协议函数 - 伪造协议协商
static OSStatus hooked_SSLCopyALPNProtocols(void *context, CFArrayRef *protocols) {
    const void *values[] = {CFSTR("http/1.1")};
    *protocols = CFArrayCreate(NULL, values, 1, &kCFTypeArrayCallBacks);
    return noErr;
}

// SSL密码套件函数 - 伪造密码套件协商
static OSStatus hooked_SSLGetNegotiatedCipher(void *context, SSLCipherSuite *cipher) {
    *cipher = TLS_AES_128_GCM_SHA256;
    return noErr;
}

// 证书信任评估函数 - 伪造证书验证通过
static OSStatus hooked_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    if (error) *error = NULL;
    validation_passed = true;
    return noErr;
}

// 证书公钥获取函数 - 伪造证书公钥
static SecKeyRef hooked_SecTrustCopyPublicKey(SecTrustRef trust) {
    return NULL;
}

// SHA256哈希函数 - 伪造哈希值
static void hooked_cc_sha256(const void *data, CC_LONG len, unsigned char *md) {
    uint8_t fake_hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256("validation_success_2025", 22, fake_hash);
    memcpy(md, fake_hash, CC_SHA256_DIGEST_LENGTH);
}

// 异步调度函数 - 控制任务执行
static void hooked_dispatch_async(dispatch_queue_t queue, void (^block)(void)) {
    validation_passed = true;
    dispatch_async(queue, block);
}

// 延迟调度函数 - 忽略延迟任务
static void hooked_dispatch_after(dispatch_time_t when, dispatch_queue_t queue, void (^block)(void)) {
    // 忽略延迟任务
}

// 定时器源创建函数 - 禁止创建定时器
static dispatch_source_t hooked_dispatch_source_create(dispatch_source_type_t type, uintptr_t handle, unsigned long mask, dispatch_queue_t queue) {
    return NULL;
}

// 队列创建函数 - 禁止创建队列
static dispatch_queue_t hooked_dispatch_queue_create(const char *label, dispatch_queue_attr_t attr) {
    return NULL;
}

// 定时器设置函数 - 忽略定时器设置
static void hooked_dispatch_source_set_timer(dispatch_source_t source, dispatch_time_t start, uint64_t interval, uint64_t leeway) {
    // 忽略定时器设置
}

// 线程创建函数 - 禁止创建线程
static int hooked_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg) {
    return 0;
}

// kill函数 - 防止进程被终止
static int hooked_kill(pid_t pid, int sig) {
    return 0;
}

// raise函数 - 防止信号触发
static int hooked_raise(int sig) {
    return 0;
}

// pthread_kill函数 - 防止线程被终止
static int hooked_pthread_kill(pthread_t thread, int sig) {
    return 0;
}

// syscall函数 - 拦截信号相关系统调用
static int hooked_syscall(int number, ...) {
    va_list args;
    va_start(args, number);
    if (number == SYS_kill) {
        va_end(args);
        return 0;
    }
    int ret = orig_syscall ? orig_syscall(number, args) : syscall(number, args);
    va_end(args);
    return ret;
}

// 内存保护函数 - 伪造内存状态
static kern_return_t hooked_vm_protect(vm_map_t target_task, vm_address_t address, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection) {
    return KERN_SUCCESS;
}

// 退出函数 - 防止退出
static void hooked_exit(int code) {
    // 忽略退出
}

// 中止函数 - 防止应用中止
static void hooked_abort(void) {
    // 忽略终止
}

// ObjC消息发送函数 - 拦截特定验证消息
static void *hooked_objc_msgSend(id self, SEL _cmd, ...) {
    if (self && _cmd) {
        const char *sel_name = sel_getName(_cmd);
        if (strstr(sel_name, "verify") || strstr(sel_name, "check") ||
            strstr(sel_name, "license") || strstr(sel_name, "auth") ||
            strstr(sel_name, "validate") || strstr(sel_name, "restrict") ||
            strstr(sel_name, "security") || strstr(sel_name, "protection")) {
            validation_passed = true;
            return (void *)@YES;
        }
    }
    va_list args;
    va_start(args, _cmd);
    void *ret = orig_objc_msgSend ? orig_objc_msgSend(self, _cmd, args) :
                  ((void *(*)(id, SEL, va_list))objc_msgSend)(self, _cmd, args);
    va_end(args);
    return ret;
}

// 任务端口函数 - 防止任务操作
static mach_port_t hooked_mach_task_self(void) {
    return MACH_PORT_NULL;
}

// 信号处理函数 - 覆盖更多信号类型
static void handle_signal(int sig, siginfo_t *info, void *context) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}

// 插件初始化函数 - 程序加载时自动执行
__attribute__((constructor))
void init(void) {
    // 设置信号处理器 - 覆盖更多信号
    struct sigaction sa;
    sa.sa_sigaction = handle_signal;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGKILL, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGALRM, &sa, NULL);

    // 获取各个段的内存地址
    uintptr_t text_start = 0, data_start = 0, jump_start = 0;
    size_t text_size = 0, data_size = 0, jump_size = 0;
    get_section("_______?aX______", &text_start, &text_size);
    get_section("____j_M__c___T__", &data_start, &data_size);
    get_section("_a_______d______", &jump_start, &jump_size);

    // 执行内存补丁，绕过验证机制
    if (data_start && data_size) {
        patch_validation_table(data_start, data_size);
        patch_integrity_checks();
    }
    if (text_start && text_size) {
        patch_exit_calls(text_start, text_size);
    }
    if (jump_start && jump_size) {
        patch_jump_tables();
    }

    // 缓存原始函数地址 - 扩展以支持新增函数
    cached_addrs.sub_5A8D1C = (void *)(text_start + 0x5A8D1C);
    cached_addrs.sub_10B934 = (void *)(text_start + 0x10B934);
    cached_addrs.sub_10C7BC = (void *)(text_start + 0x10C7BC);
    cached_addrs.sub_10B65C = (void *)(text_start + 0x10B65C);
    cached_addrs.sub_55AC80 = (void *)(text_start + 0x55AC80);
    cached_addrs.sub_59E770 = (void *)(text_start + 0x59E770);
    cached_addrs.sub_10E69C = (void *)(text_start + 0x10E69C);  
    cached_addrs.sub_10F07C = (void *)(text_start + 0x10F07C);  
    cached_addrs.sub_10C930 = (void *)(text_start + 0x10C930);  
    cached_addrs.sub_10EE44 = (void *)(text_start + 0x10EE44);  
    cached_addrs.sub_10E8B8 = (void *)(text_start + 0x10E8B8);  
    cached_addrs.stat = dlsym(RTLD_DEFAULT, "stat");
    cached_addrs.socket = dlsym(RTLD_DEFAULT, "socket");
    cached_addrs.send = dlsym(RTLD_DEFAULT, "send");
    cached_addrs.recv = dlsym(RTLD_DEFAULT, "recv");
    cached_addrs.connect = dlsym(RTLD_DEFAULT, "connect");
    cached_addrs.getaddrinfo = dlsym(RTLD_DEFAULT, "getaddrinfo");
    cached_addrs.vm_protect = dlsym(RTLD_DEFAULT, "vm_protect");
    cached_addrs.exit = dlsym(RTLD_DEFAULT, "exit");
    cached_addrs.abort = dlsym(RTLD_DEFAULT, "abort");
    cached_addrs.objc_msgSend = dlsym(RTLD_DEFAULT, "_objc_msgSend");
    cached_addrs.ssl_handshake = dlsym(RTLD_DEFAULT, "SSLHandshake");
    cached_addrs.ssl_copy_alpn = dlsym(RTLD_DEFAULT, "SSLCopyALPNProtocols");
    cached_addrs.ssl_get_cipher = dlsym(RTLD_DEFAULT, "SSLGetNegotiatedCipher");
    cached_addrs.sec_trust_evaluate = dlsym(RTLD_DEFAULT, "SecTrustEvaluateWithError");
    cached_addrs.sec_trust_copy_key = dlsym(RTLD_DEFAULT, "SecTrustCopyPublicKey");
    cached_addrs.cc_sha256 = dlsym(RTLD_DEFAULT, "CC_SHA256");
    cached_addrs.dispatch_async = dlsym(RTLD_DEFAULT, "dispatch_async");
    cached_addrs.dispatch_after = dlsym(RTLD_DEFAULT, "dispatch_after");
    cached_addrs.dispatch_source_create = dlsym(RTLD_DEFAULT, "dispatch_source_create");
    cached_addrs.dispatch_queue_create = dlsym(RTLD_DEFAULT, "dispatch_queue_create");
    cached_addrs.dispatch_source_set_timer = dlsym(RTLD_DEFAULT, "dispatch_source_set_timer");
    cached_addrs.pthread_create = dlsym(RTLD_DEFAULT, "pthread_create");
    cached_addrs.kill = dlsym(RTLD_DEFAULT, "kill");
    cached_addrs.raise = dlsym(RTLD_DEFAULT, "raise");
    cached_addrs.pthread_kill = dlsym(RTLD_DEFAULT, "pthread_kill");
    cached_addrs.syscall = dlsym(RTLD_DEFAULT, "syscall");
    cached_addrs.mach_task_self = dlsym(RTLD_DEFAULT, "mach_task_self");

    // Hook内部验证函数
    if (cached_addrs.sub_5A8D1C) {
        orig_sub_5A8D1C = cached_addrs.sub_5A8D1C;
        patch_c_function(cached_addrs.sub_5A8D1C, (void *)hooked_sub_5A8D1C);
    }
    if (cached_addrs.sub_10B934) {
        orig_sub_10B934 = cached_addrs.sub_10B934;
        patch_c_function(cached_addrs.sub_10B934, (void *)hooked_sub_10B934);
    }
    if (cached_addrs.sub_10C7BC) {
        orig_sub_10C7BC = cached_addrs.sub_10C7BC;
        patch_c_function(cached_addrs.sub_10C7BC, (void *)hooked_sub_10C7BC);
    }
    if (cached_addrs.sub_10B65C) {
        orig_sub_10B65C = cached_addrs.sub_10B65C;
        patch_c_function(cached_addrs.sub_10B65C, (void *)hooked_sub_10B65C);
    }
    if (cached_addrs.sub_55AC80) {
        orig_sub_55AC80 = cached_addrs.sub_55AC80;
        patch_c_function(cached_addrs.sub_55AC80, (void *)hooked_sub_55AC80);
    }
    if (cached_addrs.sub_59E770) {
        orig_sub_59E770 = cached_addrs.sub_59E770;
        patch_c_function(cached_addrs.sub_59E770, (void *)hooked_sub_59E770);
    }
    if (cached_addrs.sub_10E69C) {
        orig_sub_10E69C = cached_addrs.sub_10E69C;
        patch_c_function(cached_addrs.sub_10E69C, (void *)hooked_sub_10E69C);
    }
    if (cached_addrs.sub_10F07C) {
        orig_sub_10F07C = cached_addrs.sub_10F07C;
        patch_c_function(cached_addrs.sub_10F07C, (void *)hooked_sub_10F07C);
    }
    if (cached_addrs.sub_10C930) {
        orig_sub_10C930 = cached_addrs.sub_10C930;
        patch_c_function(cached_addrs.sub_10C930, (void *)hooked_sub_10C930);
    }
    if (cached_addrs.sub_10EE44) {
        orig_sub_10EE44 = cached_addrs.sub_10EE44;
        patch_c_function(cached_addrs.sub_10EE44, (void *)hooked_sub_10EE44);
    }
    if (cached_addrs.sub_10E8B8) {
        orig_sub_10E8B8 = cached_addrs.sub_10E8B8;
        patch_c_function(cached_addrs.sub_10E8B8, (void *)hooked_sub_10E8B8);
    }

    // Hook系统函数，绕过各种检测
    if (cached_addrs.stat) {
        orig_stat = cached_addrs.stat;
        patch_c_function(cached_addrs.stat, (void *)hooked_stat);
    }
    if (cached_addrs.socket) {
        orig_socket = cached_addrs.socket;
        patch_c_function(cached_addrs.socket, (void *)hooked_socket);
    }
    if (cached_addrs.send) {
        orig_send = cached_addrs.send;
        patch_c_function(cached_addrs.send, (void *)hooked_send);
    }
    if (cached_addrs.recv) {
        orig_recv = cached_addrs.recv;
        patch_c_function(cached_addrs.recv, (void *)hooked_recv);
    }
    if (cached_addrs.connect) {
        orig_connect = cached_addrs.connect;
        patch_c_function(cached_addrs.connect, (void *)hooked_connect);
    }
    if (cached_addrs.getaddrinfo) {
        orig_getaddrinfo = cached_addrs.getaddrinfo;
        patch_c_function(cached_addrs.getaddrinfo, (void *)hooked_getaddrinfo);
    }
    if (cached_addrs.vm_protect) {
        orig_vm_protect = cached_addrs.vm_protect;
        patch_c_function(cached_addrs.vm_protect, (void *)hooked_vm_protect);
    }
    if (cached_addrs.exit) {
        orig_exit = cached_addrs.exit;
        patch_c_function(cached_addrs.exit, (void *)hooked_exit);
    }
    if (cached_addrs.abort) {
        orig_abort = cached_addrs.abort;
        patch_c_function(cached_addrs.abort, (void *)hooked_abort);
    }
    if (cached_addrs.objc_msgSend) {
        orig_objc_msgSend = cached_addrs.objc_msgSend;
        patch_c_function(cached_addrs.objc_msgSend, (void *)hooked_objc_msgSend);
    }
    if (cached_addrs.ssl_handshake) {
        orig_SSLHandshake = cached_addrs.ssl_handshake;
        patch_c_function(cached_addrs.ssl_handshake, (void *)hooked_SSLHandshake);
    }
    if (cached_addrs.ssl_copy_alpn) {
        orig_SSLCopyALPNProtocols = cached_addrs.ssl_copy_alpn;
        patch_c_function(cached_addrs.ssl_copy_alpn, (void *)hooked_SSLCopyALPNProtocols);
    }
    if (cached_addrs.ssl_get_cipher) {
        orig_SSLGetNegotiatedCipher = cached_addrs.ssl_get_cipher;
        patch_c_function(cached_addrs.ssl_get_cipher, (void *)hooked_SSLGetNegotiatedCipher);
    }
    if (cached_addrs.sec_trust_evaluate) {
        orig_SecTrustEvaluateWithError = cached_addrs.sec_trust_evaluate;
        patch_c_function(cached_addrs.sec_trust_evaluate, (void *)hooked_SecTrustEvaluateWithError);
    }
    if (cached_addrs.sec_trust_copy_key) {
        orig_SecTrustCopyPublicKey = cached_addrs.sec_trust_copy_key;
        patch_c_function(cached_addrs.sec_trust_copy_key, (void *)hooked_SecTrustCopyPublicKey);
    }
    if (cached_addrs.cc_sha256) {
        orig_cc_sha256 = cached_addrs.cc_sha256;
        patch_c_function(cached_addrs.cc_sha256, (void *)hooked_cc_sha256);
    }
    if (cached_addrs.dispatch_async) {
        orig_dispatch_async = cached_addrs.dispatch_async;
        patch_c_function(cached_addrs.dispatch_async, (void *)hooked_dispatch_async);
    }
    if (cached_addrs.dispatch_after) {
        orig_dispatch_after = cached_addrs.dispatch_after;
        patch_c_function(cached_addrs.dispatch_after, (void *)hooked_dispatch_after);
    }
    if (cached_addrs.dispatch_source_create) {
        orig_dispatch_source_create = cached_addrs.dispatch_source_create;
        patch_c_function(cached_addrs.dispatch_source_create, (void *)hooked_dispatch_source_create);
    }
    if (cached_addrs.dispatch_queue_create) {
        orig_dispatch_queue_create = cached_addrs.dispatch_queue_create;
        patch_c_function(cached_addrs.dispatch_queue_create, (void *)hooked_dispatch_queue_create);
    }
    if (cached_addrs.dispatch_source_set_timer) {
        orig_dispatch_source_set_timer = cached_addrs.dispatch_source_set_timer;
        patch_c_function(cached_addrs.dispatch_source_set_timer, (void *)hooked_dispatch_source_set_timer);
    }
    if (cached_addrs.pthread_create) {
        orig_pthread_create = cached_addrs.pthread_create;
        patch_c_function(cached_addrs.pthread_create, (void *)hooked_pthread_create);
    }
    if (cached_addrs.kill) {
        orig_kill = cached_addrs.kill;
        patch_c_function(cached_addrs.kill, (void *)hooked_kill);
    }
    if (cached_addrs.raise) {
        orig_raise = cached_addrs.raise;
        patch_c_function(cached_addrs.raise, (void *)hooked_raise);
    }
    if (cached_addrs.pthread_kill) {
        orig_pthread_kill = cached_addrs.pthread_kill;
        patch_c_function(cached_addrs.pthread_kill, (void *)hooked_pthread_kill);
    }
    if (cached_addrs.syscall) {
        orig_syscall = cached_addrs.syscall;
        patch_c_function(cached_addrs.syscall, (void *)hooked_syscall);
    }
    if (cached_addrs.mach_task_self) {
        orig_mach_task_self = cached_addrs.mach_task_self;
        patch_c_function(cached_addrs.mach_task_self, (void *)hooked_mach_task_self);
    }

    // Hook Objective-C方法，拦截授权相关UI和网络请求
    hook_method(objc_getClass("UIAlertController"),
                @selector(alertControllerWithTitle:message:preferredStyle:),
                (IMP)hooked_showAlert,
                (IMP *)&orig_showAlert);
    hook_method(objc_getClass("UIViewController"),
                @selector(presentViewController:animated:completion:),
                (IMP)hooked_presentViewController,
                (IMP *)&orig_presentViewController);
    hook_method(objc_getClass("UIPresentationController"),
                @selector(initWithPresentedViewController:presentingViewController:),
                (IMP)hooked_initPresentation,
                (IMP *)&orig_initPresentation);
    hook_method(objc_getClass("JDSBNotificationViewController"),
                @selector(presentWithTitle:subtitle:style:completion:),
                (IMP)hooked_showNotification,
                (IMP *)&orig_showNotification);
    hook_method(objc_getClass("JDSBNotificationViewController"),
                @selector(dismissTimerFired:),
                (IMP)hooked_dismissTimerFired,
                (IMP *)&orig_dismissTimerFired);
    hook_method(objc_getClass("IESECPopupView"),
                @selector(show),
                (IMP)hooked_popupViewShow,
                (IMP *)&orig_popupViewShow);
    hook_method(objc_getClass("IESECPopupView"),
                @selector(present:animated:completion:),
                (IMP)hooked_popupViewPresent,
                (IMP *)&orig_popupViewPresent);
    hook_method(objc_getClass("IESECPopupView"),
                @selector(display:),
                (IMP)hooked_popupViewDisplay,
                (IMP *)&orig_popupViewDisplay);
    hook_method(objc_getClass("UIView"),
                @selector(addSubview:),
                (IMP)hooked_addSubview,
                (IMP *)&orig_addSubview);
    hook_method(objc_getClass("JDValidationManager"),
                @selector(validateData:context:),
                (IMP)hooked_validateData,
                (IMP *)&orig_validateData);
    hook_method(objc_getClass("JDValidationManager"),
                @selector(checkAuthStatus:),
                (IMP)hooked_checkAuthStatus,
                (IMP *)&orig_checkAuthStatus);
    hook_method(objc_getClass("AFHTTPSessionManager"),
                @selector(POST:parameters:progress:success:failure:),
                (IMP)hooked_post,
                (IMP *)&orig_post);
    hook_method(objc_getClass("AFHTTPSessionManager"),
                @selector(GET:parameters:progress:success:failure:),
                (IMP)hooked_get,
                (IMP *)&orig_get);
    hook_method(objc_getClass("AFSecurityPolicy"),
                @selector(evaluateServerTrust:forDomain:),
                (IMP)hooked_evaluateServerTrust,
                (IMP *)&orig_evaluateServerTrust);
    hook_method(objc_getClass("AFNetworkReachabilityManager"),
                @selector(isReachable),
                (IMP)hooked_isReachable,
                (IMP *)&orig_isReachable);
    hook_method(objc_getClass("AFURLSessionManager"),
                @selector(URLSession:didBecomeInvalidWithError:),
                (IMP)hooked_sessionDidBecomeInvalid,
                (IMP *)&orig_sessionDidBecomeInvalid);
    hook_method(objc_getClass("JDValidationManager"),
                @selector(validateSession:),
                (IMP)hooked_validateSession,
                (IMP *)&orig_validateSession);
    hook_method(objc_getClass("JDValidationManager"),
                @selector(checkLicense:),
                (IMP)hooked_checkLicense,
                (IMP *)&orig_checkLicense);
}