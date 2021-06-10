SHELL := bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

DESTDIR:=/
PREFIX:=/usr/local
CXX:=g++
OPTIMIZATION:=-O3 -flto
BASE_FLAGS=-D_FILE_OFFSET_BITS=64 -g -fno-omit-frame-pointer -std=c++17 -fPIC -Wall -Wextra -Werror -Wno-switch-bool -march=native -Wfatal-errors
CXXFLAGS=${BASE_FLAGS}

all: CXXFLAGS=${BASE_FLAGS} ${OPTIMIZATION}
all: perforated

install: all
	mkdir -p ${DESTDIR}/${PREFIX}/bin
	install -m 755 perforated ${DESTDIR}/bin

perforated: src/perforated.cc
	${CXX} ${CXXFLAGS} -o $@ $^

%.o: src/%.cc src/%.h
	${CXX} ${CXXFLAGS} -c $< -o $@ -MT $@ -MMD -MP -MF $*.d

clean:
	rm -f perforated
	rm -f massif.out.*
	rm -f *.gcno
	rm -f *.gcov
	rm -f *.gcda
	rm -f *.o
	rm -f *.d
	rm -f *.so
	rm -f *.a
.PHONY: clean

include $(wildcard *.d)
