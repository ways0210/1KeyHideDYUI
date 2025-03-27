ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:13.0
INSTALL_TARGET_PROCESSES = TikTok

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HideUIButton

HideUIButton_FILES = Tweak.x
HideUIButton_CFLAGS = -fobjc-arc
HideUIButton_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk

