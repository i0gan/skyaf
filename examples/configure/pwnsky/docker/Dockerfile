FROM ubuntu:16.04

RUN apt update && apt install -y lib32z1 xinetd

# clean
RUN rm -rf /var/lib/apt/lists/ && rm -rf /root/.cache && apt-get autoclean && rm -rf /tmp/* /var/lib/apt/* /var/cache/* /var/log/*

COPY . /conf

# copy bin,lib
RUN useradd -m ctf && echo "sky{token}"  > /home/ctf/sky_token && cp /conf/skyaf /
RUN cp -r /conf/ctf.xinetd /etc/xinetd.d/ctf &&\
    cp -r /conf/skyaf.xinetd /etc/xinetd.d/skyaf &&\
    cp -r /conf/file/pwn /home/ctf &&\
    cp -r /conf/file/lua.bin /home/ctf &&\
    cp -r /conf/file/lib /home/ctf &&\
    cp -r /conf/file/lib64 /home/ctf

# chown & chmod
RUN chown -R root:ctf /home/ctf && chmod 770 /home/ctf && chmod 770 /home/ctf/pwn && chmod 740 /home/ctf/sky_token && chmod -R 700 /conf

RUN mkdir /home/ctf/dev && mknod /home/ctf/dev/null c 1 3 && mknod /home/ctf/dev/zero c 1 5 && mknod /home/ctf/dev/random c 1 8 && mknod /home/ctf/dev/urandom c 1 9 && chmod 666 /home/ctf/dev/* 

EXPOSE 80
CMD ["/conf/service.sh"]
