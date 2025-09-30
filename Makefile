################################################################################
#
# Main Makefile
#
################################################################################
export ROOT_PATH := $(shell pwd)
export PATH := $(ROOT_PATH)/toolchain/linux/newlib/bin:${PATH}

export BUILD_PATH := $(ROOT_PATH)/project/realtek_amebapro2_v0_example/GCC-RELEASE
export IMAGE_DIR  := $(ROOT_PATH)/image

all: evn_check
	$(MAKE) -C $(BUILD_PATH)/build all
	$(MAKE) build_image

evn_check:
	mkdir -p $(IMAGE_DIR)
	@if [ -d $(BUILD_PATH)/build ]; then \
		echo "$(BUILD_PATH)/build exist."; \
	else \
		mkdir -p $(BUILD_PATH)/build; \
		cd $(BUILD_PATH)/build; \
		cmake $(BUILD_PATH) -DCMAKE_TOOLCHAIN_FILE=$(BUILD_PATH)/toolchain.cmake; \
	fi

rom_image:
	cmake --build $(BUILD_PATH)/build --target flash

build_image: rom_image
	@$(RM) -rf $(IMAGE_DIR)/*
	@cp -aRf $(BUILD_PATH)/build/*.bin $(IMAGE_DIR)

clean:
	@if [ -f $(BUILD_PATH)/build/Makefile ]; then \
		$(MAKE) -C $(BUILD_PATH)/build clean; \
	fi

distclean: clean
	@$(RM) -rf $(BUILD_PATH)/build $(IMAGE_DIR)

.PHONY : clean distclean
