FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json* ./
COPY packages/node-vault-ebpf packages/node-vault-ebpf
COPY examples/basic-httpbin examples/basic-httpbin
RUN npm install --workspace=node-vault-ebpf --workspace=basic-httpbin \
    && npm run build -w node-vault-ebpf
WORKDIR /app/examples/basic-httpbin
CMD ["node", "index.js"]
