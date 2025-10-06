FROM node:20-bullseye

RUN apt-get update && apt-get install -y ca-certificates curl git xdg-utils && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY . .

ENV NODE_ENV=production
ENV PORT=8080

EXPOSE 8080
CMD ["npm","start"]
