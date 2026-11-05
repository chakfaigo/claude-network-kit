#!/bin/zsh
"/Library/Application Support/ClaudeResidential/python/bin/python3.12" -I -B "/Library/Application Support/ClaudeResidential/controller.py" original
result=$?
print "按回车关闭窗口。"
read -r
exit "$result"
