################################################################################
#
# Main Makefile
#
################################################################################
export ROOT_PATH := $(shell pwd)
export PATH := $(ROOT_PATH)/toolchain/linux/newlib/bin:${PATH}

export BUILD_PATH := $(ROOT_PATH)/project/realtek_amebapro2_v0_example/GCC-RELEASE

all: evn_check
	$(MAKE) -C $(BUILD_PATH)/build all
	#cd $(BUILD_PATH)/build; cmake –build . –target flash

evn_check:
	@if [ -d $(BUILD_PATH)/build ]; then \
		echo "$(BUILD_PATH)/build exist."; \
	else \
		mkdir -p $(BUILD_PATH)/build; \
		cd $(BUILD_PATH)/build; \
		cmake $(BUILD_PATH) -DCMAKE_TOOLCHAIN_FILE=$(BUILD_PATH)/toolchain.cmake; \
	fi

clean:
	@if [ -f $(BUILD_PATH)/build/Makefile ]; then \
		$(MAKE) -C $(BUILD_PATH)/build clean; \
	fi

distclean: clean
	@$(RM) -rf $(BUILD_PATH)/build

.PHONY : clean distclean
