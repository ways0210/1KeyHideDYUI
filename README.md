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

> 💡 **说明**：  
> 1. 部分组件可能因版本更新而调整位置，建议通过调试工具动态查看  
> 2. 图标列使用 [Emoji](https://unicode.org/emoji/charts/emoji-list.html) 表示，实际开发需替换为资产目录资源  
> 3. 红色标注的 **AWEBaseElementView** 存在复用现象，需通过 `subviews` 进一步区分子组件
