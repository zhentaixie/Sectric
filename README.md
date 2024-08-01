# Sectric
An implementation of Sectric protocol.

## Required packages:
- libboost-all-dev (version >=1.74)
- libgmp-dev
- libssl-dev
- libntl-dev
- pkg-config
- libglib2.0-dev
- openssl (modified as Kunlun[https://github.com/yuchen1024/Kunlun.git] said)
- openmp

## Compilation：
for the first time:
```bash
./setup.sh
```
else:
```bash
./build.sh
```

## Run
Run with the file test.py and some data files(eg. the neighbors of node in Facebook in ./data).

Enter the quering node number and enter the name of the data folder named with a specific format, such as facebook_4039_1_1045 (name_nodeCount_edgeCount[optional value,not important]_maxDegree).

```python
python3 test.py
Please enter the node number x：0
Please enter the filename:facebook_4039_1_1045
```
In the end, you will obtain some statistical information from the execution process and the results of the local triangle counting calculations like:
![image](https://github.com/user-attachments/assets/dabf5521-2ab8-46a5-a65a-479358cabd6f)
