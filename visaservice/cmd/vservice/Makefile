ifneq ($(BUILD), release)
	ifndef PATCH
		PATCH=`date -u +%Y%m%d%H%M%S`-dev
	endif
endif


all:
	go build -ldflags "-X main.BuildVersion=$(PATCH)"


