Tested on Ubuntu 22.04 using WSL2 and VS Code


1.	On the Linux Machine clone the OpenFHE repository:
```
cd /user/home/
git clone https://github.com/openfheorg/openfhe-development.git
```
2.	Open the project in VS Code:
```
cd openfhe-development
code .
```
3.	Open a terminal in VS Code:
- Go to View in the menu bar
- Select Terminal

5.	In the VS Code terminal (Ubunutu machine), build the project as follows:
```
mkdir build
cd build
cmake ..
make
export LD_LIBRARY_PATH=${LD_LIBRARY_PATH}:/usr/local/lib/
```
6. Clone this project
```
cd /user/home/
git clone https://github.com/openfheorg/openfhe-development.git
```
8. Open the project in VS Code
7.	To run the program:
- Go to "Run->Run Without Debugging"
