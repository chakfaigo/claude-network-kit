#!/bin/zsh
cd -- "${0:A:h}" || exit 1
./python/bin/python3.12 -I -B ./src/check_setup.py
result=$?
print '\n检查完成不等于验收完成。按回车关闭窗口。'
read -r
exit "$result"
