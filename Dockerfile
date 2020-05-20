FROM python:3 AS https-knock

RUN pip install flask

RUN apt update && apt install -y  iptables ssh vim
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy

COPY templates /templates
COPY static /static
COPY http-knock.py /


CMD [ "python", "./http-knock.py" ]

