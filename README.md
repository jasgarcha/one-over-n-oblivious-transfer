# one-over-n-oblivious-transfer

`OneOverNObliviousTransferSimulator` is a simulator of the 1-n Oblivious Transfer protocol (using a non-standard RSA implementation). The program demonstrates this security & privacy protocol in a client-server architecture.

## Usage:
Execute `Agent` (server) before `Inquirer` (client).

## Overview:
1) The `Agent` is initialized with a constant information object. 
2) The `Inquirer` is initialized with a random `k`, the index of the information item it desires. 
3) The `Agent` listens for the `Inquirer`. 
4) Once the `Inquirer` connects to the `Agent`, 1-n Oblivious Transfer begins. 
5) The protocol ends with the Inquirer receiving the `k`th information item from the `Agent`.

## Build
Compile `RSA.class` before `Agent` and `Inquirer`.