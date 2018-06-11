# socket
udp flood/fake trace written in C (a rough version)

    gcc -o udpFlood udpFlood.c daemon.c
    gcc -pthread --openmp -o fakeTrace fakeTrace.c daemon.c
