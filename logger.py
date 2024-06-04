import time

def log_info(message):
    print('\033[92m[i] {}: {}\033[0m'.format(time.time(), message))

def log_warning(message):
    print('\033[93m[!] {}: {}\033[0m'.format(time.time(), message))

def log_error(message):
    print('\033[91m[x] {}: {}\033[0m'.format(time.time(), message))