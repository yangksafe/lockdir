
简单的勒索软件，使用RSA密钥加密指定目录

这是我在观看了LockBit文件之后模仿制作的，仅用于教育目的



和LockBit类似，第一步生成密钥对

然后分别将密钥添加到加密解密器中，有三个文件

RSA.exe 用于生成RSA密钥对

lockdir.exe 用于加密，并在桌面生成一个hello.txt文件，你可以编辑里面的内容

opendir.exe 用于解密

替换lockdir.go中的公钥为你的公钥

替换opendir.go中的私钥为你的私钥

lockdir.exe 使用公钥加密指定文件夹中的所有内容 比如：lockdir 666

opendir.exe 使用私钥解密指定文件夹中的所有内容 比如：opendir 666

目前在windows和linux上进行了测试

