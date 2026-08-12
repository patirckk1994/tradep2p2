# Builds the blind-falcon-demo research prototype against this repo's own
# vendored, unmodified official FALCON reference implementation
# (../../third_party/falcon-impl-20211101/ - the same copy blindsig_falcon.cpp
# builds against). See ../README.md before running this for anything other
# than curiosity: this demo has NO zero-knowledge layer and reveals (rho, r,
# sig) in the clear - it only tests that the underlying algebra round-trips
# through a real FALCON trapdoor. The actual zero-knowledge proofs live in
# ../../blindsig-prover/.

FALCON_DIR := ../../third_party/falcon-impl-20211101
FALCON_SRCS := $(FALCON_DIR)/codec.c $(FALCON_DIR)/common.c \
               $(FALCON_DIR)/falcon.c $(FALCON_DIR)/fft.c \
               $(FALCON_DIR)/fpr.c $(FALCON_DIR)/keygen.c \
               $(FALCON_DIR)/rng.c $(FALCON_DIR)/shake.c \
               $(FALCON_DIR)/sign.c $(FALCON_DIR)/vrfy.c
FALCON_OBJS := $(FALCON_SRCS:.c=.o)

CC := cc
CXX := c++
CFLAGS := -O2 -I$(FALCON_DIR)
CXXFLAGS := -O2 -std=c++20 -I$(FALCON_DIR)
LDLIBS := -lssl -lcrypto -lm

blind-falcon-demo: blind_falcon_demo.o $(FALCON_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDLIBS)

blind_falcon_demo.o: blind_falcon_demo.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f blind-falcon-demo blind_falcon_demo.o $(FALCON_OBJS)

.PHONY: clean
