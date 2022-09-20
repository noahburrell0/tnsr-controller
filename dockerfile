# syntax=docker/dockerfile:1
FROM python:3.9.14-buster
RUN apt update && apt upgrade -y
RUN pip3 install requests
WORKDIR /app
COPY python/ .
RUN chmod -R +x /app
RUN ls -alR /app
CMD ["python3", "main.py"]
EXPOSE 80

