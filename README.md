# p4-median-estimation
This repository contains the P4 source code behind the implementation attempts of a fully in-switch median estimator. 
This work is part of the Master's Thesis: "Statistical methods for DDoS detection in the data plane". 

Programmable data planes provide a unique opportunity to compute and track such distribution-shape statistics directly on streaming traffic. Detecting deviations in these metrics may offer a lightweight, real-time method for identifying volumetric anomalies and pulse-wave attack signatures. However, the feasibility of computing these metrics within the constraints of P4 hardware remains understudied, and their effectiveness in real-world detection scenarios requires systematic analysis.
This thesis aimed to address these gaps by analyzing which distribution-shape statistics can feasibly be computed in the programmable data plane and whether such statistics can be leveraged to detect volumetric pulse-wave DDoS attacks efficiently and accurately.

Out of four potential descriptive statistics considered, a median estimate tracker was selected to be implemented into P4 for Tofino. The development/compilation environment for the seven different implementation attempts is as follows:

Machine running Linux 22.04.05 LTS
P4 SDE: Intel® P4 Studio Software Development Environment (SDE) - Open P4 Studio: https://github.com/p4lang/open-p4studio
Compiled for Tofino 1 Intel Switches
