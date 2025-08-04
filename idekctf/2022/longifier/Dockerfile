FROM node:alpine

RUN apk update && apk upgrade \
	&& apk add chromium

ENV PORT 3000

RUN mkdir /app
WORKDIR /app
COPY challenge .
RUN yarn

ENV CHROME_BIN=/usr/bin/chromium-browser

# Wipe /tmp every minute
RUN echo "* * * * * /bin/rm -rf /tmp/*" >> /var/spool/cron/crontabs/root

CMD crond && yarn start
