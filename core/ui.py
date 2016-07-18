# This file contains functions/classes for aesthetics


class Colors():
    W = '\033[0m'  # white (normal)
    R = '\033[31m'  # red
    G = '\033[32m'  # green
    O = '\033[33m'  # orange
    B = '\033[34m'  # blue
    P = '\033[35m'  # purple
    C = '\033[36m'  # cyan
    GR = '\033[37m'  # gray


def banner(version):
    print(Colors.O + '''
    ****************************************************************
    \tMailoney - A Simple SMTP Honeypot - Version: {}
    ****************************************************************
    '''.format(version) + Colors.W)


def bullet(text):
    print('[' + Colors.G + '+' + Colors.W + ']' + text)


def warning(text):
    print('[' + Colors.O + '+' + Colors.W + ']' + text)


def error(text):
    print('[' + Colors.R + '+' + Colors.W + ']' + text)
