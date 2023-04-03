To run:

For the server:
```
# lcore 0 and 1
sudo ./mp_server/build/mp_server-shared-debug -c 0x3 -a af:00.0 -- -p 0x1 -n 2
```

For Client #1
```
# lcore 2
sudo ./mp_client/build/mp_client-shared-debug -c 0x4 -a af:00.0 --proc-type=auto -- -n 0
```

```
# lcore 4
sudo ./mp_client/build/mp_client-shared-debug -c 0x10 -a af:00.0 --proc-type=auto -- -n 1
```