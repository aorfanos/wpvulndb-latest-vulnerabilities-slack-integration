FROM python:3.7-alpine 

ENV 

COPY . /opt/wpvulndb-api

WORKDIR /opt/wpvulndb-api

RUN \
pip install -r requirements.txt

CMD [ "python", "./wpvulndb-api.py" ]

