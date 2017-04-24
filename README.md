# Welcome to virusCounter
You may have been been imagining how anti-virus software monitors the activities of all the processes in real time for long time, not getting the correct solution. Actually, the anti-virus loaded a **module**([Loadable Kernel Module](https://en.wikipedia.org/wiki/Loadable_kernel_module), LKM) into the kernel, intercepting the **system calls**. [System calls](https://en.wikipedia.org/wiki/System_call) are collections of API(Application Programming Interface) provided by kernel, including the most common I/O command **open**, **read**, **write** and others. Aha, you may now realized that how smart the anti-virus softwares are. The wrap a jacket on top of original system calls, performing virus checking codes.

The virtusCounter implemented an anti-virus LKM, monitoring characteristics code among difference I/O processes.

The sandBoxer enabled user to run unsafe software under limited privileges by modifying User ID of process through LKM, and also implement executable to check the modified process UID.

## Getting Started
### The Anti-Virus module

#### For linux

1. Compile the module and test program if you haven't yet:

  ```
  cd phase1
  sudo make
  ```

2. Open any file include the **VIRUS** character:

  ```
  nano test2.txt
  ```

3. Display the system log about virus detection history:

  ```
  grep 'mal' /var/log/syslog
  ```

4. Remove module and clean up files:

  ```
  sudo make clean
  ```

### The shift to user id module
#### For linux
1. Compile the module and user space program if you haven't yet:

  ```
  cd phase2
  sudo make
  ```

2. Run shift2uid program:

  ```
  ./shift2user -u [uid] -p [pid]
  ```

2. Run getloginuid program:

  ```
  ./getloginuid -p [pid]
  ```

3. Display the system log

  ```
  dmesg
  ```

4. Remove module and clean up files:

  ```
  sudo make clean
  ```

## Contributing

We encourage everyone to interact in virusCounter and its sub-projects' codebases, issue trackers, chat rooms, and mailing lists.

## The authors
[Yang liu](https://github.com/byliuyang) (Harry) from [Worcester Polytechnic Institute](http://www.wpi.edu/academics/cs/)

[Huyen Nguyen](https://github.com/HuyenNguyen2302) from [Worcester Polytechnic Institute](http://www.wpi.edu/academics/cs/)

## License
virusCounter are released under the [MIT License](http://opensource.org/licenses/MIT).
