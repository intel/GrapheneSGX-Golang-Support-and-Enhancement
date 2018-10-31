#!/usr/bin/python

import sys

import regression


def main():
    loader = sys.argv[1]
    exec_file = sys.argv[2]
    runner = regression.Regression(loader, exec_file)
    runner.add_check(name=exec_file, check=lambda res: False)
    runner.run_checks()


if __name__ == '__main__':
    main()
