FROM python:3.7-alpine 

ENV WPVULNDB_API_TOKEN yourtokengoeshere
ENV SLACK_WEBHOOK_URL yourslackwebhookURL 

COPY . /opt/wpvulndb-api

WORKDIR /opt/wpvulndb-api

RUN \
pip install -r requirements.txt

CMD [ "python", "./wpvulndb-api.py" ]

