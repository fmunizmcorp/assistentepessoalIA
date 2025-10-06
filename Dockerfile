FROM node:20-bullseye
WORKDIR /app
COPY package.json ./
RUN npm i --omit=dev
COPY . .
ENV NODE_ENV=production
EXPOSE 8080
CMD ["npm","start"]
