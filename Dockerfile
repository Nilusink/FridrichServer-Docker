# A dockerfile must always start by importing the base image.
# We use the keyword 'FROM' to do that.
# In our example, we want import the python image.
# So we write 'python' for the image name and 'latest' for the version.
FROM python:3.10.0

WORKDIR /usr/src/app/

# for superuser
RUN apt-get update \
 && apt-get install -y sudo

RUN adduser --disabled-password --gecos '' docker
RUN adduser docker sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER docker

# installing requirements
COPY ./ ./

RUN sudo apt-get update -y
RUN sudo apt-get upgrade -y
RUN sudo apt-get install python-dev -y
RUN sudo pip install --no-cache-dir -r requirements.txt

# execute command
CMD [ "sudo", "python", "./FridrichServer.py" ]
