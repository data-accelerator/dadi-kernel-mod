#pragma once

#define debug true

#define PRINT_INFO(fmt, ...)                                                   \
	pr_info("\033[33m|INFO |\033[0m%s:%d|%s: " fmt "\n", __FILE__,         \
		__LINE__, __FUNCTION__, ##__VA_ARGS__)

#define PRINT_ERROR(fmt, ...)                                                  \
	pr_err("\033[31m|ERROR|\033[0m%s:%d|%s: " fmt "\n", __FILE__,          \
	       __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define PRINT_DEBUG(fmt, ...)                                                  \
	if (debug)                                                             \
	pr_info("\033[33m|DEBUG |\033[0m%s:%d|%s: " fmt "\n", __FILE__,        \
		__LINE__, __FUNCTION__, ##__VA_ARGS__)
