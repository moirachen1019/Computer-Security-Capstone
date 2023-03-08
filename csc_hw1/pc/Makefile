CLIENT = tcp_client

all: $(CLIENT)

$(CLIENT): tcp_client.cpp
	g++ tcp_client.cpp -o $@

clean:
	rm -f $(CLIENT)