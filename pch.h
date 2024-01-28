#pragma once
#include <iostream>
#include <string>
#include <thread>
#include <queue>
#include <mutex>
#include <cstdint>
#include <pcap.h>
#include <arpa/inet.h>
#include <cstdint>
#define DEBUG_VAR(var) if (debug_mode) std::cout << #var << ": " << var << std::endl;
#define HANDLE_ERROR_RETURN_NULLPTR(func_name, errbuf) \
    do { \
        fprintf(stderr, "Error in %s: %s\n", func_name, errbuf); \
        return nullptr; \
    } while (0)
#define HANDLE_ERROR_RETURN_0(func_name, errbuf) \
    do { \
        fprintf(stderr, "Error in %s: %s\n", func_name, errbuf); \
        return 0; \
    } while (0)
#define HANDLE_ERROR_RETURN(func_name, errbuf) \
    do { \
        fprintf(stderr, "Error in %s: %s\n", func_name, errbuf); \
        return; \
    } while (0)
#define HANDLE_ERROR_EXIT_0(func_name, errbuf) \
    do { \
        fprintf(stderr, "Error in %s: %s\n", func_name, errbuf); \
        exit(0); \
    } while (0)
#define HANDLE_ERROR_EXIT_1(func_name, errbuf) \
    do { \
        fprintf(stderr, "Error in %s: %s\n", func_name, errbuf); \
        exit(1); \
    } while (0)