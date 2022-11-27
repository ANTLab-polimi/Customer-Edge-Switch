This README describe the structure of a p4 program and how it works.

I'm using this page to structure this readme and the documentation of the p4 comunity:
+ https://opennetworking.org/news-and-events/blog/getting-started-with-p4/
+ https://p4.org/p4-spec/docs/P4-16-v1.0.0-spec.html

First of all we need to create a file with the extension ".p4" which is the file where we will code our program.

Inside it, we will describe the structure of our architecture:

+ what libraries it includes
+ what type of header our program can handle, describing them
+ what functions our switch will apply to the packets (e.g., my_parser(), my_verify_checksum(), my_ingress() etc...)

After that, we need to compile it creating two different files:

+ the JSON file which is file the switch will compute
+ the ".p4i" file which contains all the API used to analyze the original written code in p4

(I'm consider the fact that we have already created all the interface and that all our (emulated or not) architecture is up and working...)

Now we have to run our program and to do it we can use the command:
```bash
$ sudo simple_switch_grpc --log-console --no-p4 --device-id 1 -i 1@eth1 -i 2@eth2 --thrift-port 9090 -- --grpc-server-addr localhost:50051 --cpu-port 255
```

To instantiate a software switch in localhost on port 50051, with controller port 255, connected to the interface eth1 and eth2 of our machine (vm release, mind that the interfaces can change their numbers, depending from the provisioning).

We have also the control plan in another python file which set some configurations which are outscope the p4 language.
