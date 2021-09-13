OBJECTS += ./client.o \
./cmd.o \
./eclient.o \
./main.o \
./message.o \
./message_builder.o \
./message_parser.o \
./onion_routing.o \
./osocket.o \
./server.o \
./util.o 

CC_DEPS += ./deps/client.d \
./deps/cmd.d \
./deps/eclient.d \
./deps/main.d \
./deps/message.d \
./deps/message_builder.d \
./deps/message_parser.d \
./deps/onion_routing.d \
./deps/osocket.d \
./deps/server.d \
./deps/util.d 

./%.o: ./%.c
	@echo 'Building file: $<'
	$(CC) -c -Wall $< -o $@
	@echo 'Build finished: $<'
	@echo

./%.o: ./%.cc
	@echo 'Building file: $<'
	$(CC) -c -Wall $< -o $@
	@echo 'Build finished: $<'
	@echo

./%.o: ./%.cpp
	@echo 'Building file: $<'
	$(CC) -c -Wall $< -o $@
	@echo 'Build finished: $<'
	@echo

