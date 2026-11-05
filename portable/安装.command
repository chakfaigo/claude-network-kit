#!/bin/zsh
cd -- "${0:A:h}" || exit 1
./python/bin/python3.12 -I -B ./src/controller.py install
result=$?
print '\n按回车关闭窗口。'
read -r
exit "$result"
