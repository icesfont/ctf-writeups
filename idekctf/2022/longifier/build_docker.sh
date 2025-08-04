docker rm longifier;
docker build . --tag=longifier && docker run -p 3000:3000 -it --name=longifier longifier:latest
