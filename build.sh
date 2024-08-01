#!/bin/bash

# 进入psi_ca目录并运行copy_files.sh脚本
cd triangle_counting
./copy_files.sh

# 返回到2PC-Circuit-PSI/build目录
cd ../extern/2PC-Circuit-PSI/build

# 编译项目
make -j

mkdir -p ../../../bin
cp ./bin/gcf_psi ../../../bin/


