# Graphene-SGX Golang Support Feature

Firstly, Please follow the instructions in Graphene README file to build Graphene-SGX
and then change directory to Graphene project.

### 1) build the preloaded libraries for symbol analysis
~~~
make -C LibOS/libs/symtab SGX=1
~~~

### 2) build the preloaded libraries for golang support
~~~
make -C LibOS/libs/golang SGX=1
~~~

### 3) download Gobyexample test code by script
~~~
cd LibOS/shim/test/go/
./setup_gobyexample
cd gobyexample.test/
~~~

### 4) Build example code and generate SGX signatures and tokens
### please note go == 1.11.5
### https://dl.google.com/go/go1.11.5.linux-amd64.tar.gz
~~~
export GOROOT=</path/to/go>
make SGX=1
make SGX_RUN=1
~~~

### 5) Run a compiled example "arrays" in Graphene-SGX
~~~
SGX=1 ./pal_loader arrays
~~~

Enjoy.
