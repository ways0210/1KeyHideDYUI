#import "DYYYABTestHook.h"
#import <objc/runtime.h>

// 声明ABTestManager接口
@interface AWEABTestManager : NSObject
@property(retain, nonatomic) NSDictionary *abTestData;
@property(retain, nonatomic) NSMutableDictionary *consistentABTestDic;
@property(copy, nonatomic) NSDictionary *performanceReversalDic;
- (void)setAbTestData:(id)arg1;
- (void)_saveABTestData:(id)arg1;
- (id)abTestData;
+ (id)sharedManager;
@end

// 全局变量实现
static BOOL abTestBlockEnabled = NO;
static NSDictionary *gFixedABTestData = nil;
static dispatch_once_t onceToken;
static dispatch_queue_t abTestQueue = NULL;

// 从指定JSON文件加载ABTest数据
NSDictionary *loadFixedABTestData(void) {
    static dispatch_once_t queueToken;
    dispatch_once(&queueToken, ^{
        abTestQueue = dispatch_queue_create("com.dyyy.abtest", DISPATCH_QUEUE_SERIAL);
    });
    
    __block NSDictionary *result = nil;
    dispatch_sync(abTestQueue, ^{
        dispatch_once(&onceToken, ^{
            @autoreleasepool {
                // 获取Documents目录路径
                NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
                NSString *documentsDirectory = [paths firstObject];
                
                // 修改为DYYY子文件夹下的路径
                NSString *dyyyFolderPath = [documentsDirectory stringByAppendingPathComponent:@"DYYY"];
                NSString *jsonFilePath = [dyyyFolderPath stringByAppendingPathComponent:@"abtest_data_fixed.json"];
                
                // 确保DYYY目录存在
                NSFileManager *fileManager = [NSFileManager defaultManager];
                if (![fileManager fileExistsAtPath:dyyyFolderPath]) {
                    NSError *error = nil;
                    [fileManager createDirectoryAtPath:dyyyFolderPath withIntermediateDirectories:YES attributes:nil error:&error];
                    if (error) {
                        NSLog(@"[DYYY] 创建DYYY目录失败: %@", error.localizedDescription);
                    }
                }
                
                NSError *error = nil;
                NSData *jsonData = [NSData dataWithContentsOfFile:jsonFilePath options:NSDataReadingMappedIfSafe error:&error];
                
                if (jsonData) {
                    NSDictionary *loadedData = [NSJSONSerialization JSONObjectWithData:jsonData 
                                                                              options:NSJSONReadingMutableContainers 
                                                                                error:&error];
                    if (loadedData && !error) {
                        gFixedABTestData = [loadedData copy];
                    }
                }
                
                if (!gFixedABTestData) {
                    gFixedABTestData = @{};
                }
            }
        });
        result = gFixedABTestData;
    });
    
    return result;
}

// 替代空数据函数，返回固定数据
static inline NSDictionary *fixedABTestData(void) {
    if (!abTestBlockEnabled) {
        return nil;
    }
    return gFixedABTestData ?: loadFixedABTestData();
}

// 获取当前ABTest数据
NSDictionary *getCurrentABTestData(void) {
    if (abTestBlockEnabled && gFixedABTestData) {
        return gFixedABTestData;
    }
    
    AWEABTestManager *manager = [%c(AWEABTestManager) sharedManager];
    return manager ? [manager abTestData] : nil;
}

// Hook AWEABTestManager类
%hook AWEABTestManager

// 拦截获取 ABTest 数据的方法
- (id)abTestData {
    NSDictionary *data = fixedABTestData();
    return data ?: %orig;
}

// 拦截设置 ABTest 数据的方法
- (void)setAbTestData:(id)arg1 {
    if (!abTestBlockEnabled) {
        %orig;
    }
}

// 拦截内部检索方法
- (id)_retriveABTestData {
    NSDictionary *data = fixedABTestData();
    return data ?: %orig;
}

// 拦截增量数据更新
- (void)incrementalUpdateData:(id)arg1 unchangedKeyList:(id)arg2 {
    if (!abTestBlockEnabled) {
        %orig;
    }
}

// 拦截数据处理方法
- (void)handleABTestData:(id)arg1 {
    if (!abTestBlockEnabled) {
        %orig;
    }
}

// 拦截网络获取配置方法
- (void)fetchConfigurationWithRetry:(BOOL)arg1 completion:(id)arg2 {
    if (abTestBlockEnabled) {
        if (arg2 && [arg2 isKindOfClass:%c(NSBlock)]) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                ((void (^)(id))arg2)(nil);
            });
        }
        return;
    }
    %orig;
}

// 拦截另一个配置方法
- (void)fetchConfiguration:(id)arg1 {
    if (!abTestBlockEnabled) {
        %orig;
    }
}

// 拦截重写ABTest数据的方法
- (void)overrideABTestData:(id)arg1 needCleanCache:(BOOL)arg2 {
    if (!abTestBlockEnabled) {
        %orig;
    }
}

// 返回固定的ABTest案例
- (id)ABTestCaseWithPropertyName:(id)arg1 {
    if (abTestBlockEnabled) {
        NSDictionary *data = fixedABTestData();
        return [data objectForKey:arg1] ?: %orig;
    }
    return %orig;
}

// 返回固定的稳定值
- (id)stableValues {
    return abTestBlockEnabled ? fixedABTestData() : %orig;
}

%end

%ctor {
    %init;
    static dispatch_once_t initToken;
    dispatch_once(&initToken, ^{
        abTestBlockEnabled = [[NSUserDefaults standardUserDefaults] boolForKey:@"ABTestBlockEnabled"];
        if (abTestBlockEnabled) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
                loadFixedABTestData();
            });
        }
    });
}