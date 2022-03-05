FROM francescobattagin/ue-openairsim:netcat
RUN sudo apt-get install git
RUN git clone https://github.com/FrancescoBattagin/CES.git