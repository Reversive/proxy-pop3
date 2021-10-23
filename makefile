all: proxy

proxy:
	cd proxy; make all

clean:
	cd proxy; make clean

.PHONY: all clean proxy
