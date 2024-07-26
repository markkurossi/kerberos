FROM ubuntu:24.04

RUN apt-get update
RUN apt-get update --fix-missing
RUN apt-get update

RUN apt install krb5-kdc -y
RUN apt install krb5-admin-server -y

RUN apt install less -y
RUN apt install inetutils-ping -y
RUN apt install dnsutils -y
RUN apt install vim -y
RUN apt install expect -y

COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY init.expect /root

RUN expect -f /root/init.expect
