# A simple Makefile for building and installing our test application.

ADB=adb
APKTOOL=apktool
AUTOSIGN=autosign
DIST_DIR=dist
PROJECT_NAME=com.mwr.dz
APK_NAME=drozer-agent-2.3.2.apk
APK_NAME_SIGNED=drozer-agent-2.3.2-signed.apk

all: $(DIST_DIR)/$(APK_NAME) $(DIST_DIR)/$(APK_NAME_SIGNED)
	$(ADB) wait-for-device
	$(ADB) uninstall $(PROJECT_NAME)
	$(ADB) install $(DIST_DIR)/$(APK_NAME_SIGNED)

$(DIST_DIR)/$(APK_NAME):
	$(APKTOOL) build

$(DIST_DIR)/$(APK_NAME_SIGNED): $(DIST_DIR)/$(APK_NAME)
	$(AUTOSIGN) $(DIST_DIR)/$(APK_NAME) $(DIST_DIR)/$(APK_NAME_SIGNED)

clean:
	$(ADB) wait-for-device
	$(ADB) uninstall $(PROJECT_NAME)
	rm -rf $(DIST_DIR)/*
