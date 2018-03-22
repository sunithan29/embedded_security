
# Secure Communication and Firewall Architecture for IoT Applications


* Decentralizing authentication and authorization in embedded devices

The architecture is implemented using Python and C languages. The implementations use AES-CBC-128 and RSA-1024 as symmetric and asymmetric encryption algorithms, respectively. They use XORed double encryption of data for hash generation. The application was implemented using FreeRTOS running on EK-TM4C129EXL IoT board. 

The C implementation focuses on resource constraints and portability.
It comprises server and client entities. It provides portability files, that can be used to port the client/server entity to any device and/or OS.

The python implementation targets non resource-constrained entities that have availability of Python 3.5 interpreter. It provides a secure communication architecture that includes Auth, server and client entities and a software stack that provides solutions for local Certificate Authority.

