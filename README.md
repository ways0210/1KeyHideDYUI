# 1KeyHideDYUI
一键隐藏抖音UI


以下是提供的UI组件名称的中文翻译及功能说明整理：

| 组件名称                            | 我的描述               | 官方说明                     |
|-------------------------------------|------------------------|------------------------------|
| AWEHPTopBarCTAContainer             | 顶栏操作按钮组         | 包含顶部导航栏的关键操作入口 |
| AWEHPDiscoverFeedEntranceView       | 发现页入口             | 进入发现页信息流的入口按钮   |
| AWELeftSideBarEntranceView          | 左侧边栏入口           | 打开左侧功能侧边栏的触发按钮 |
| DUXBadge                            | 左侧边栏红点           | 侧边栏功能未读状态提示       |
| AWEBaseElementView                  | 头像组                 | 展示用户头像及相关信息       |
| AWEElementStackView                 | 右侧互动组件组         | 包含点赞/评论/收藏/分享等操作 |
| AWEPlayInteractionDescriptionLabel  | 内容描述文案           | 视频/内容的说明性文字         |
| AWEUserNameLabel                    | 昵称标签               | 显示用户昵称                 |
| AWEStoryProgressSlideView           | 图集标签页指示         | 图文内容分页切换的进度指示条 |
| ACCEditTagStickerView               | 图集标签编辑器         | 添加/编辑图文内容的标签功能   |
| AWEFeedTemplateAnchorView           | 创作工具入口           | 跳转到剪映/拍同款的创作入口   |
| AWESearchFeedTagView                | 搜同款标签             | 显示同类内容搜索标签         |
| AWEPlayInteractionSearchAnchorView  | 相关搜索入口           | 触发内容关联搜索的入口       |
| AFDRecommendToFriendTagView         | 朋友推荐标签           | 标记为朋友推荐内容的标签     |
| AWEBaseElementView                  | 去汽水听入口           | 跳转至汽水音乐的播放入口     |
| AWELandscapeFeedEntryView           | 全屏播放按钮           | 触发视频全屏播放的控制按钮   |
| AWEFeedAnchorContainerView          | 地址信息容器           | 显示内容发布位置的信息       |
| AWEStoryProgressContainerView       | 图集标签容器           | 图文内容分页标签的容器       |
| AFDAIbumFolioView                   | 图集评分指示           | 显示图集内容的评分信息       |
| AWEAntiAddictedNoticeBarView        | 防沉迷提示条           | 显示防沉迷相关的系统提示     |

视频长按面板相关视图模型与控制器
类名	功能描述
AWELongPressPanelSpeedViewModel	处理视频播放速度的逻辑与数据展示（如倍速选项）。
AWELongPressPanelClearScreenViewModel	管理清屏功能的业务逻辑（如隐藏控制按钮）。
AWELongPressPanelWatchVideoLaterViewModel	实现 “稍后观看” 功能（如添加到待播列表）。
AWELongPressPanelCacheVideoModel	处理视频缓存逻辑（如本地存储、进度管理）。
AWELongPressPanelVideoPictureSearchViewModel	支持视频画面搜索功能（如截图识别、帧定位）。
AWELongPressPanelScreenCastViewModel	管理视频投屏逻辑（如设备连接、画面同步）。
AWELongPressPanelMultiDevicePlaySyncViewModel	实现多设备播放同步（如跨设备续播）。
AWELongPressPanelFamiliarRecommendViewModel	处理相似视频推荐逻辑（如算法推荐、个性化排序）。
AWELongPressPanelStoreViewModel	管理视频存储功能（如保存到本地、云存储）。
AWELongPressPanelDisLikeViewModel	处理用户 “不喜欢” 操作（如调整推荐算法）。
AWELongPressPanelReportViewModel	实现视频举报功能（如违规内容上报）。
AWELongPressPanelDanmakuViewModel	管理弹幕相关逻辑（如显示、发送、过滤）。
AWELongPressPanelTimingCloseViewModel	处理定时关闭功能（如倒计时锁屏）。
AWELongPressPaneliPhoneAutoPlayViewModel	控制 iPhone 自动播放行为（如横竖屏适配）。
AWELongPressPanelBGPlaySettingsViewModel	管理后台播放设置（如音频模式、耗电优化）。
AWELongPressPanelTableViewController	视图控制器，负责长按面板表格的布局与交互（整合上述功能选项）。

> 💡 **说明**：  
> 部分组件可能因版本更新而调整位置，建议通过调试工具动态查看  

