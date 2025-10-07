FROM node:20-bullseye
RUN apt-get update && apt-get install -y ca-certificates curl git xdg-utils && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev && npx playwright install --with-deps
COPY . .
ENV NODE_ENV=production
EXPOSE 8080
CMD ["npm","start"]
