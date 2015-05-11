LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := libpingle
LOCAL_SRC_FILES := appface.c tcpup_toyvpn.cpp tcpup_contrak.cpp tcpup_crypt.cpp tcpup_dnstrak.cpp tcpup_ip.cpp tcpup_up.cpp
LOCAL_LDFLAGS += -llog
#LOCAL_CFLAGS += -DUSE_DNS_MODE
#LOCAL_CXXFLAGS += -DUSE_DNS_MODE
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
include $(call all-makefiles-under,$(LOCAL_PATH))
