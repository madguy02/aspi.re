FROM ubuntu:16.04
 
# Update OS
RUN sed -i 's/# \(.*multiverse$\)/\1/g' /etc/apt/sources.list
RUN apt-get update
RUN apt-get -y upgrade
 
# Install Python
RUN apt-get install -y python-dev python-pip
 
# Add requirements.txt
ADD requirements.txt /home/Videos/blog_app/requirements.txt
 
# Install uwsgi Python web server
RUN pip install uwsgi
#upgrade pip
RUN pip install --upgrade pip
RUN wget -O- https://bootstrap.pypa.io/get-pip.py | python
RUN pip install --upgrade setuptools
RUN pip install --upgrade virtualenv
# Install app requirements
RUN  pip install -r requirements.txt
 
# Create app directory
ADD . /home/Videos/blog_app
 
# Set the default directory for our environment
ENV HOME /home/Videos/blog_app
WORKDIR /home/Videos/blog_app
 
# Expose port 8000 for uwsgi
EXPOSE 8000
 
ENTRYPOINT ["uwsgi", "--http", "0.0.0.0:8000", "--module", "app:app", "--processes", "1", "--threads", "8"]
