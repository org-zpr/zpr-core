

all:
	cd zds && $(MAKE) all
	cd vsio && $(MAKE) all

clean:
	cd zds && $(MAKE) clean
	cd vsio && $(MAKE) clean



