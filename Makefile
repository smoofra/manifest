

manifest: manifest.cc Makefile
	clang++ -std=gnu++17 -O2  -g -o manifest manifest.cc -lrocksdb -lcrypto -lmount -lpthread -lboost_coroutine -lboost_program_options

#	-lboost_filesystem
