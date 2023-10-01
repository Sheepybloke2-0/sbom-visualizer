
FROM python:3.10.4-slim as base

RUN apt-get update

WORKDIR /workspace

COPY requirements.txt /workspace/requirements.txt

RUN pip install -r requirements.txt

COPY . /workspace/

ENTRYPOINT [ "spdx_visualizer" ]
